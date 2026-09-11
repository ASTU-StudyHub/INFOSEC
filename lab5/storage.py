#!/usr/bin/env python3
"""Лабораторная работа №5. Хранилище менеджера учётных записей: подсистемы защиты.

Модуль без графического интерфейса (его даёт manager.py). Здесь реализованы:
  1) хранение паролей учётных записей в виде солёного хэша PBKDF2-HMAC-SHA256 и их
     проверка пересчётом хэша с той же солью;
  2) контроль целостности БД: при каждом изменении через программу хэш-сумма SHA-256
     файла БД записывается в отдельный файл; по запросу актуальная хэш-сумма сверяется
     с эталонной («БД в целостности» / «БД была изменена извне»);
  3) шифрование файлов БД, хэш-суммы и журнала симметричным шифром AES-256-CBC (aes.py)
     с отдельным ключом для каждого файла: ключ выводится из пароля файла функцией PBKDF2
     со случайной солью, подлинность шифртекста подтверждает HMAC-SHA256 (неверный пароль
     обнаруживается до расшифрования);
  4) журнал событий: дата и время каждой значимой операции в текстовом файле.

Шифрование не конфликтует с контролем целостности: хэш-сумма считается по открытому
содержимому БД, а шифрование обратимо байт в байт, поэтому после расшифрования проверка
сходится. Все операции регистрируются в журнале, поэтому пока журнал зашифрован,
доступно только его расшифрование.

Файлы (папка data рядом с программой): accounts.txt — БД, accounts.hash — эталонная
хэш-сумма, events.log — журнал. Только стандартная библиотека.
Запуск: python3 storage.py — автоматическая проверка всех подсистем без GUI.
"""

import base64
import datetime
import hashlib
import hmac
import os
import shutil
import sys
import tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import aes  # noqa: E402  (собственная реализация AES-CBC)

DATA_DIR = os.path.join(BASE, "data")
FILES = {"db": "accounts.txt", "hash": "accounts.hash", "log": "events.log"}
TITLES = {"db": "БД учётных записей", "hash": "хэш-сумма БД", "log": "журнал событий"}
ROLES = ("db", "hash", "log")

PASSWORD_ITERATIONS = 100_000     # PBKDF2 для паролей учётных записей
KDF_ITERATIONS = 200_000          # PBKDF2 для ключей шифрования файлов
MAGIC = "#ENCRYPTED AES-256-CBC, HMAC-SHA256, ключ: PBKDF2-HMAC-SHA256 из пароля файла"
DB_HEADER = "# логин:соль(hex):PBKDF2-HMAC-SHA256(пароль, соль, %d итераций)(hex)" % PASSWORD_ITERATIONS
LOGIN_MAX, PASSWORD_MAX = 32, 128


class ManagerError(Exception):
    """Ошибка, которую нужно показать пользователю (не сбой программы)."""


def first_upper(text):
    """Первая буква заглавная, остальное без изменений (capitalize() портит «БД»)."""
    return text[:1].upper() + text[1:]


# --- Пароли учётных записей ----------------------------------------------------------------
def hash_password(password, salt=None):
    """Солёный хэш пароля. Возвращает (соль hex, хэш hex)."""
    salt = os.urandom(16) if salt is None else salt
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return salt.hex(), digest.hex()


def check_password(password, salt_hex, hash_hex):
    """Пересчитывает хэш с сохранённой солью и сравнивает за постоянное время."""
    _, digest = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest, hash_hex)


def check_login(login):
    if not login or len(login) > LOGIN_MAX:
        raise ManagerError(f"логин должен содержать от 1 до {LOGIN_MAX} символов")
    if any(ch.isspace() or ch == ":" or ord(ch) < 32 for ch in login):
        raise ManagerError("логин не может содержать пробелы, двоеточие и управляющие символы")
    if login.startswith("#"):
        raise ManagerError("логин не может начинаться с символа «#» (так помечены строки-комментарии БД)")


def is_hex(text, length):
    """Строка ровно из length шестнадцатеричных цифр (соль, хэш, эталон)."""
    return len(text) == length and all(ch in "0123456789abcdef" for ch in text)


def check_new_password(password):
    if not password or len(password) > PASSWORD_MAX:
        raise ManagerError(f"пароль должен содержать от 1 до {PASSWORD_MAX} символов")


# --- Шифрование файлов ------------------------------------------------------------------------
def derive_keys(password, salt, role):
    """Из пароля файла — ключ шифрования (32 байта) и ключ HMAC (32 байта).
    Имя файла входит в соль, поэтому у файлов разные ключи даже при одинаковом пароле."""
    material = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt + FILES[role].encode("utf-8"),
                                   KDF_ITERATIONS, dklen=64)
    return material[:32], material[32:]


def encrypt_data(data, password, role):
    """Открытые байты → текст: строка-признак и base64(соль | IV | шифртекст | HMAC)."""
    salt, iv = os.urandom(16), os.urandom(16)
    key_enc, key_mac = derive_keys(password, salt, role)
    body = salt + iv + aes.encrypt_cbc(key_enc, iv, data)
    tag = hmac.new(key_mac, body, hashlib.sha256).digest()
    b64 = base64.b64encode(body + tag).decode("ascii")
    lines = [b64[i:i + 76] for i in range(0, len(b64), 76)]
    return MAGIC + "\n" + "\n".join(lines) + "\n"


def decrypt_data(text, password, role):
    """Обратное преобразование. ManagerError при неверном пароле или повреждении файла."""
    lines = text.split("\n")
    if not lines or lines[0] != MAGIC:
        raise ManagerError("файл не зашифрован этой программой")
    try:
        raw = base64.b64decode("".join(lines[1:]), validate=True)
    except (ValueError, TypeError):
        raise ManagerError("файл повреждён: не удалось прочитать base64")
    if len(raw) < 16 + 16 + 16 + 32:
        raise ManagerError("файл повреждён: слишком короткий")
    body, tag = raw[:-32], raw[-32:]
    salt, iv, cipher = body[:16], body[16:32], body[32:]
    key_enc, key_mac = derive_keys(password, salt, role)
    if not hmac.compare_digest(hmac.new(key_mac, body, hashlib.sha256).digest(), tag):
        raise ManagerError("неверный пароль или файл повреждён")
    try:
        return aes.decrypt_cbc(key_enc, iv, cipher)
    except ValueError as exc:
        raise ManagerError(f"файл повреждён: {exc}")


# --- Хранилище: файлы, учётные записи, целостность, журнал --------------------------------------
class Store:
    def __init__(self, data_dir=DATA_DIR):
        self.dir = data_dir
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as exc:
            raise ManagerError(f"не удалось создать папку данных {self.dir}: {exc.strerror or exc}")
        if self.read("db") is None and self.read("hash") is None and not self.is_encrypted("log"):
            self.create_db()                 # первый запуск; если эталон есть, а БД нет — это удаление извне

    def create_db(self):
        """Пустая БД и её эталонная хэш-сумма (первый запуск или явное решение пользователя)."""
        self.require_plain("hash", "log")
        self.write("db", (DB_HEADER + "\n").encode("utf-8"))
        self.write("hash", self.hash_line())
        self.log("создана пустая БД учётных записей, сохранена её хэш-сумма")

    def path(self, role):
        return os.path.join(self.dir, FILES[role])

    def read(self, role):
        """Байты файла или None, если файла нет."""
        try:
            with open(self.path(role), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ManagerError(f"не удалось прочитать файл {FILES[role]}: {exc.strerror or exc}")

    def write(self, role, data):
        """Запись через временный файл: на диске либо старое содержимое, либо новое целиком."""
        tmp = self.path(role) + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, self.path(role))
        except OSError as exc:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise ManagerError(f"не удалось записать файл {FILES[role]}: {exc.strerror or exc}")

    def is_encrypted(self, role):
        data = self.read(role)
        return data is not None and data.startswith(MAGIC.encode("utf-8") + b"\n")

    def require_plain(self, *roles):
        """Операция возможна, только если перечисленные файлы не зашифрованы."""
        for role in roles:
            if self.is_encrypted(role):
                raise ManagerError(f"файл {FILES[role]} ({TITLES[role]}) зашифрован — сначала расшифруйте его")

    # --- журнал событий
    def log(self, event):
        self.require_plain("log")
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.path("log"), "ab") as f:
                f.write(f"{stamp}  {event}\n".encode("utf-8"))
        except OSError as exc:
            raise ManagerError(f"не удалось записать журнал {FILES['log']}: {exc.strerror or exc}")

    def log_lines(self):
        data = self.read("log")
        if data is None:
            return []
        return data.decode("utf-8", "replace").splitlines()

    # --- учётные записи
    def load_accounts(self):
        """Список (логин, соль hex, хэш hex). ManagerError, если БД зашифрована или повреждена."""
        self.require_plain("db")
        data = self.read("db")
        if data is None:
            raise ManagerError(f"файл {FILES['db']} не найден")
        accounts = []
        for number, line in enumerate(data.decode("utf-8-sig", "replace").splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) != 3 or not parts[0] or not is_hex(parts[1], 32) or not is_hex(parts[2], 64):
                raise ManagerError(f"файл БД повреждён (строка {number})")
            accounts.append(tuple(parts))
        return accounts

    def save_accounts(self, accounts, event):
        """Запись БД, обновление эталонной хэш-суммы и запись в журнал — одно изменение."""
        self.require_plain("db", "hash", "log")
        old_db, old_hash = self.read("db"), self.read("hash")
        lines = [DB_HEADER] + [":".join(acc) for acc in accounts]
        self.write("db", ("\n".join(lines) + "\n").encode("utf-8"))
        try:
            self.write("hash", self.hash_line())
            self.log(f"{event}; хэш-сумма БД обновлена: {self.db_hash()[:16]}…")
        except ManagerError:
            try:                                   # откат: БД и эталон меняются только вместе
                if old_db is not None:
                    self.write("db", old_db)
                if old_hash is not None:
                    self.write("hash", old_hash)
            except ManagerError:
                pass
            raise

    def add_account(self, login, password):
        check_login(login)
        check_new_password(password)
        accounts = self.load_accounts()
        if any(acc[0] == login for acc in accounts):
            raise ManagerError(f"учётная запись «{login}» уже существует")
        accounts.append((login,) + hash_password(password))
        self.save_accounts(accounts, f"добавлена учётная запись «{login}»")

    def update_account(self, login, new_login, new_password):
        """Переименование и/или смена пароля; пустой new_password — пароль не меняется."""
        check_login(new_login)
        if new_password:
            check_new_password(new_password)
        accounts = self.load_accounts()
        index = next((i for i, acc in enumerate(accounts) if acc[0] == login), None)
        if index is None:
            raise ManagerError(f"учётная запись «{login}» не найдена")
        if new_login != login and any(acc[0] == new_login for acc in accounts):
            raise ManagerError(f"учётная запись «{new_login}» уже существует")
        changes = []
        if new_login != login:
            changes.append(f"логин «{login}» → «{new_login}»")
        if new_password:
            changes.append("пароль изменён")
        if not changes:
            raise ManagerError("изменений нет")
        salt, digest = hash_password(new_password) if new_password else accounts[index][1:]
        accounts[index] = (new_login, salt, digest)
        self.save_accounts(accounts, f"изменена учётная запись «{login}»: " + ", ".join(changes))

    def delete_account(self, login):
        accounts = self.load_accounts()
        rest = [acc for acc in accounts if acc[0] != login]
        if len(rest) == len(accounts):
            raise ManagerError(f"учётная запись «{login}» не найдена")
        self.save_accounts(rest, f"удалена учётная запись «{login}»")

    def verify_password(self, login, password):
        """Проверка пароля по хэшу; результат заносится в журнал (аудит входов)."""
        self.require_plain("log")
        for acc in self.load_accounts():
            if acc[0] == login:
                ok = check_password(password, acc[1], acc[2])
                self.log(f"проверка пароля «{login}»: {'верный' if ok else 'НЕВЕРНЫЙ'}")
                return ok
        raise ManagerError(f"учётная запись «{login}» не найдена")

    # --- целостность БД
    def db_hash(self):
        self.require_plain("db")
        data = self.read("db")
        if data is None:
            raise ManagerError(f"файл {FILES['db']} не найден: БД была удалена извне")
        return hashlib.sha256(data).hexdigest()

    def hash_line(self):
        return f"{self.db_hash()}  {FILES['db']}\n".encode("utf-8")

    def stored_hash(self):
        """Эталон из файла хэш-суммы; None, если файла нет; ManagerError, если он повреждён."""
        self.require_plain("hash")
        data = self.read("hash")
        if data is None:
            return None
        tokens = data.decode("utf-8-sig", "replace").split()
        if not tokens or not is_hex(tokens[0], 64):
            raise ManagerError(f"файл {FILES['hash']} повреждён: не содержит хэш-суммы SHA-256")
        return tokens[0]

    def save_hash(self):
        self.require_plain("db", "hash", "log")
        self.write("hash", self.hash_line())
        self.log(f"сохранена эталонная хэш-сумма БД: {self.db_hash()[:16]}…")

    def check_integrity(self):
        """Возвращает (совпало, эталон, актуальная). ManagerError, если эталона нет."""
        self.require_plain("db", "hash", "log")
        expected, actual = self.stored_hash(), self.db_hash()
        if expected is None:
            raise ManagerError("эталонная хэш-сумма не сохранена")
        ok = hmac.compare_digest(expected, actual)
        self.log("проверка целостности БД: " + ("БД в целостности" if ok
                 else f"БД БЫЛА ИЗМЕНЕНА ИЗВНЕ (эталон {expected[:16]}…, актуальная {actual[:16]}…)"))
        return ok, expected, actual

    # --- шифрование файлов
    def encrypt_file(self, role, password):
        if not password:
            raise ManagerError("пароль файла не может быть пустым")
        if self.is_encrypted(role):
            raise ManagerError(f"файл {FILES[role]} уже зашифрован")
        if role != "log":
            self.require_plain("log")
        data = self.read(role)
        if data is None:
            raise ManagerError(f"файл {FILES[role]} не найден")
        event = f"зашифрован файл: {TITLES[role]} ({FILES[role]})"
        if role == "log":
            self.log(event)                  # последняя запись перед шифрованием самого журнала
            data = self.read(role)
        try:
            self.write(role, encrypt_data(data, password, role).encode("utf-8"))
        except ManagerError as exc:
            if role == "log":
                self.log(f"ОТКАЗ в шифровании файла {FILES[role]}: {exc}")
            raise
        if role != "log":
            self.log(event)

    def decrypt_file(self, role, password):
        if not self.is_encrypted(role):
            raise ManagerError(f"файл {FILES[role]} не зашифрован")
        if role != "log":
            self.require_plain("log")
        text = self.read(role).decode("utf-8", "replace")
        try:
            plain = decrypt_data(text, password, role)
        except ManagerError as exc:
            if role != "log":
                self.log(f"ОТКАЗ в расшифровании файла {FILES[role]}: {exc}")
            raise
        self.write(role, plain)
        self.log(f"расшифрован файл: {TITLES[role]} ({FILES[role]})")


# --- Автоматическая проверка без GUI ---------------------------------------------------------------
def self_test(verbose=True):
    """Сценарий из задания: учётные записи → целостность → внешнее изменение → шифрование."""
    results = []

    def step(name, ok):
        results.append(ok)
        if verbose:
            print(f"  [{'ок' if ok else 'ОШИБКА'}] {name}")

    tmp = tempfile.mkdtemp(prefix="lab5_")
    try:
        st = Store(tmp)
        st.add_account("ivan", "qwerty123")
        st.add_account("maria", "Пароль!2026")
        db = st.read("db").decode("utf-8")
        step("пароли не хранятся открыто", "qwerty123" not in db and "Пароль!2026" not in db)
        step("два пользователя в БД", [a[0] for a in st.load_accounts()] == ["ivan", "maria"])
        step("верный пароль принимается", st.verify_password("ivan", "qwerty123"))
        step("неверный пароль отклоняется", not st.verify_password("ivan", "qwerty124"))
        st.update_account("ivan", "ivan", "newpass")
        step("смена пароля", st.verify_password("ivan", "newpass") and not st.verify_password("ivan", "qwerty123"))
        st.update_account("maria", "maria.p", "")
        step("переименование без смены пароля", st.verify_password("maria.p", "Пароль!2026"))
        try:
            st.add_account("ivan", "x")
            step("дубликат логина отклонён", False)
        except ManagerError:
            step("дубликат логина отклонён", True)
        salts = {a[1] for a in st.load_accounts()}
        step("у каждой записи своя соль", len(salts) == 2)

        ok, _, _ = st.check_integrity()
        step("целостность после изменений через программу", ok)
        with open(st.path("db"), "ab") as f:                       # изменение «извне», минуя программу
            f.write(("hacker:" + "00" * 16 + ":" + "00" * 32 + "\n").encode("ascii"))
        ok, _, _ = st.check_integrity()
        step("внешнее изменение обнаружено", not ok)
        st.delete_account("hacker")
        step("после изменения через программу эталон обновлён", st.check_integrity()[0])
        good_hash = st.read("hash")
        st.write("hash", "мусор вместо хэша\n".encode("utf-8"))          # порча файла эталона «извне»
        try:
            st.check_integrity()
            step("испорченный файл хэш-суммы → сообщение об ошибке", False)
        except ManagerError:
            step("испорченный файл хэш-суммы → сообщение об ошибке", True)
        st.write("hash", good_hash)
        good_db = st.read("db")
        st.write("db", good_db + b"eve:not-hex-salt:not-hex-hash\n")       # порча строки БД «извне»
        try:
            st.load_accounts()
            step("испорченная строка БД → сообщение об ошибке", False)
        except ManagerError:
            step("испорченная строка БД → сообщение об ошибке", True)
        st.write("db", good_db)
        try:
            st.add_account("#root", "x")
            step("логин с «#» отклонён", False)
        except ManagerError:
            step("логин с «#» отклонён", True)

        passwords = {"db": "key-db", "hash": "key-hash", "log": "key-log"}
        secrets = {"db": "ivan:", "hash": st.stored_hash(), "log": "проверка целостности"}   # что не должно читаться
        for role in ROLES:
            st.encrypt_file(role, passwords[role])
        step("все три файла зашифрованы", all(st.is_encrypted(r) for r in ROLES))
        for role in ROLES:
            text = st.read(role).decode("utf-8", "replace")
            step(f"{FILES[role]}: содержимое не читается", secrets[role] not in text)
        try:
            st.add_account("petr", "1")
            step("операции с зашифрованными файлами блокируются", False)
        except ManagerError:
            step("операции с зашифрованными файлами блокируются", True)
        try:
            st.decrypt_file("log", "wrong")
            step("неверный пароль файла отвергнут", False)
        except ManagerError:
            step("неверный пароль файла отвергнут", True)
        st.decrypt_file("log", passwords["log"])
        try:
            st.decrypt_file("db", "wrong")
            step("неверный пароль БД отвергнут", False)
        except ManagerError:
            step("неверный пароль БД отвергнут", True)
        st.decrypt_file("db", passwords["db"])
        st.decrypt_file("hash", passwords["hash"])
        step("после расшифрования БД в целостности", st.check_integrity()[0])
        step("учётные записи сохранились", [a[0] for a in st.load_accounts()] == ["ivan", "maria.p"])

        wanted = ["добавлена", "изменена", "удалена", "зашифрован файл", "расшифрован файл",
                  "сохранена эталонная", "проверка целостности", "ОТКАЗ"]
        st.save_hash()
        lines = st.log_lines()
        step("в журнале есть все виды событий", all(any(w in line for line in lines) for w in wanted))
        step("записи журнала с датой и временем", all(len(line) > 20 and line[4] == "-" and line[10] == " " for line in lines))
        if verbose:
            print("\nЖурнал событий:")
            for line in lines:
                print("  " + line)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    total, good = len(results), sum(results)
    if verbose:
        print(f"\nИтог: {good}/{total} проверок пройдено")
    return good == total


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")     # консоль Windows в cp866/cp1251 не знает «→» и «…»
    sys.exit(0 if self_test() else 1)
