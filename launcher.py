#!/usr/bin/env python3
"""Защита информации: единая точка входа для лабораторных работ 1–5.

Без аргументов — меню со списком работ курса. Выбранная работа запускается в отдельном
процессе (у каждой работы свой интерпретатор, у оконной работы 5 — свой Tk), после её
завершения меню показывается снова. С номером работы — сразу эта работа: остальные
аргументы передаются ей как её собственные, код возврата работы — код возврата лаунчера.

Программы работ не меняются: лаунчер импортирует их модули из папок lab1–lab5 и вызывает
функции main(). Из этого файла PyInstaller собирает исполняемые файлы INFOSEC-windows.exe,
INFOSEC-macos и INFOSEC-linux (.github/workflows/build.yml): модули работ в них уже внутри,
а данные работы 5 хранятся в домашней папке пользователя, в ~/.infosec/lab5.

Только стандартная библиотека. Запуск:
    python3 launcher.py                 меню работ
    python3 launcher.py lab3            сразу работа 3 (можно и просто 3)
    python3 launcher.py lab5 ПАПКА      работа 5 с папкой данных ПАПКА
    python3 launcher.py --selftest      проверка всех работ без окон (для CI)
    python3 launcher.py --help          справка
"""

import codecs
import collections
import os
import signal
import subprocess
import sys
import traceback

FROZEN = getattr(sys, "frozen", False)       # True в исполняемом файле PyInstaller
ROOT = os.path.dirname(os.path.abspath(__file__))
# Данные работы 5 в исполняемом файле. Папка data рядом с программой оказалась бы во
# временной папке распаковки, которая удаляется после выхода, — вместе с БД и журналом.
LAB5_DATA = os.path.join(os.path.expanduser("~"), ".infosec", "lab5")


# --- Работы курса --------------------------------------------------------------------------
# Модули работ импортируются внутри обёрток: загружается только запущенная работа, а
# PyInstaller находит импорт по тексту программы и включает модуль в исполняемый файл.
def run_lab1(argv):
    import dh
    dh.main()


def run_lab2(argv):
    import rsa
    rsa.main()


def run_lab3(argv):
    import myhash
    myhash.main()


def run_lab4(argv):
    import signature        # сам подключает rsa (ЛР2) и myhash (ЛР3)
    signature.main()


def run_lab5(argv):
    import manager          # окно tkinter; storage.py и aes.py подключает сам
    if FROZEN and not any(not arg.startswith("-") for arg in argv[1:]):
        argv = argv + [LAB5_DATA]           # папку (и ~/.infosec) создаёт Store из storage.py
    manager.main(argv)


Lab = collections.namedtuple("Lab", "title script run window")
LABS = {
    1: Lab("Протокол Диффи-Хеллмана", "dh.py", run_lab1, False),
    2: Lab("Алгоритм шифрования RSA", "rsa.py", run_lab2, False),
    3: Lab("Разработка алгоритма хэш-функции", "myhash.py", run_lab3, False),
    4: Lab("Реализация электронной цифровой подписи", "signature.py", run_lab4, False),
    5: Lab("Комплексное обеспечение безопасности менеджера учётных записей", "manager.py",
           run_lab5, True),
}


# --- Окружение -----------------------------------------------------------------------------
def add_lab_paths():
    """Запуск из исходников: папки lab1–lab5 — в начало sys.path, раньше site-packages,
    чтобы lab2/rsa.py не перекрыл одноимённый сторонний пакет. В исполняемом файле модули
    уже внутри, папок нет."""
    if FROZEN:
        return
    for number in sorted(LABS, reverse=True):
        path = os.path.join(ROOT, f"lab{number}")
        if path not in sys.path:
            sys.path.insert(0, path)


def setup_console():
    """Русский текст и знаки «→», «…» в любой консоли.

    В консоль Windows Python пишет в Юникоде, но при выводе в файл или канал (так вывод
    читает CI) кодировка — ANSI (cp1252), без кириллицы: такие потоки переводим на UTF-8,
    как и ASCII (локаль C). В прочих кодировках (например, KOI8-R) недостающие знаки
    заменяются на «?» вместо ошибки UnicodeEncodeError."""
    for stream in (sys.stdout, sys.stderr):
        if not hasattr(stream, "reconfigure"):
            continue
        try:
            encoding = codecs.lookup(stream.encoding or "ascii").name
        except LookupError:
            encoding = "ascii"
        try:
            if encoding != "utf-8" and (os.name == "nt" or encoding == "ascii"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


def program_name():
    """Как вызывается лаунчер — для справки и сообщений об ошибках."""
    return os.path.basename(sys.executable) if FROZEN else "python3 launcher.py"


# --- Запуск работы -------------------------------------------------------------------------
def lab_command(number, args=()):
    """Команда запуска работы в отдельном процессе: тот же исполняемый файл или тот же
    интерпретатор с этим файлом."""
    if FROZEN:
        return [sys.executable, f"lab{number}"] + list(args)
    return [sys.executable, os.path.abspath(__file__), f"lab{number}"] + list(args)


def run_lab(number, args):
    """Работа в текущем процессе: sys.argv работы = [её программа] + аргументы.
    Возвращает код возврата; sys.exit() внутри работы завершает и лаунчер с её кодом."""
    lab = LABS[number]
    add_lab_paths()
    sys.argv = [lab.script] + list(args)
    try:
        lab.run(sys.argv)
    except KeyboardInterrupt:       # Ctrl+C при открытом окне работы 5; работы 1–4 ловят сами
        print("\nВыход.")
        return 130
    return 0


def spawn_lab(number):
    """Работа из меню — отдельный процесс; лаунчер ждёт его завершения.

    Ввод и вывод лаунчера передаются работе явно: так работа получает и канал или файл,
    а не только консоль (в Windows subprocess без этого дескрипторы не наследует).
    Ctrl+C консоль посылает обоим процессам. Лаунчер его пропускает (обработчик-пустышка,
    а не SIG_IGN: игнорирование унаследовала бы работа), прерывание обрабатывает работа —
    в ЛР2 оно, например, останавливает факторизацию, а не завершает программу."""
    streams = {}
    for name, fd in (("stdin", 0), ("stdout", 1), ("stderr", 2)):
        try:
            os.fstat(fd)
            streams[name] = fd
        except OSError:             # поток закрыт — работа обойдётся без него
            pass
    sys.stdout.flush()              # меню — раньше вывода работы и при выводе в канал
    previous = signal.signal(signal.SIGINT, lambda signum, frame: None)
    try:
        return subprocess.call(lab_command(number), **streams)
    finally:
        signal.signal(signal.SIGINT, previous)


def parse_lab(arg):
    """«lab3», «LAB3» или «3» → 3; иначе None."""
    text = arg.lower()
    if text.startswith("lab"):
        text = text[3:]
    return int(text) if text in {str(number) for number in LABS} else None


# --- Меню и справка ------------------------------------------------------------------------
def read_choice(prompt):
    """Строка ввода меню. С терминала — input(). Из канала или файла — по одному байту:
    sys.stdin прочитал бы ввод вперёд целым блоком, и запущенная работа получила бы
    вместо своих строк конец файла."""
    if sys.stdin is None or sys.stdin.isatty():
        return input(prompt)
    print(prompt, end="", flush=True)
    line = b""
    while not line.endswith(b"\n"):
        byte = os.read(sys.stdin.fileno(), 1)
        if not byte:
            if not line:
                raise EOFError
            break
        line += byte
    return line.decode(sys.stdin.encoding or "utf-8", "replace")


def menu():
    lines = ["", "Защита информации — лабораторные работы (АГТУ, кафедра АСОИУ)"]
    for number, lab in LABS.items():
        lines.append(f"  {number} — {lab.title}" + (" (окно)" if lab.window else ""))
    lines.append("  0 — выход")
    text = "\n".join(lines)
    try:
        while True:
            print(text)
            choice = read_choice("Выбор: ").strip()
            if choice == "0":
                break
            number = parse_lab(choice)
            if number is None:
                print("  Нет такого пункта меню.")
                continue
            if LABS[number].window:
                print("  Работа откроется в отдельном окне, меню вернётся после его закрытия.")
            try:
                code = spawn_lab(number)
            except OSError as exc:
                print(f"  Не удалось запустить работу {number}: {exc}")
                continue
            if code:
                print(f"  Работа {number} завершилась с кодом {code}.")
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")
    return 0


def help_text():
    name = program_name()
    data = LAB5_DATA if FROZEN else os.path.join(ROOT, "lab5", "data")
    usage = [
        ("", "меню: номер работы — запуск, 0 — выход"),
        (" labN [аргументы]", "сразу работа N (1–5), аргументы передаются ей"),
        (" --selftest", "проверка всех работ без окон, код 0 — всё пройдено"),
        (" --help", "эта справка"),
    ]
    width = len(name) + max(len(args) for args, _ in usage) + 3
    lines = ["Защита информации — лабораторные работы 1–5 (АГТУ, кафедра АСОИУ).",
             "", "Запуск:"]
    lines += [f"  {name + args:{width}}{text}" for args, text in usage]
    lines += ["", "Работы:"]
    for number, lab in LABS.items():
        kind = "окно" if lab.window else "консоль"
        lines.append(f"  lab{number}  {lab.title} ({lab.script}, {kind})")
    lines += ["", f"Данные работы 5: {data}",
              f"Другая папка данных: {name} lab5 ПАПКА"]
    return "\n".join(lines)


# --- Самопроверка (--selftest, для CI) ---------------------------------------------------
HASH_VECTORS = [        # lab3/README.md, «Результаты»: хэш не должен зависеть от системы
    ("", "", "4a216c31"),
    ("abc", "", "7139aeec"),
    ("abc", "s1", "c75fe06f"),
    ("dmr75y", "", "cda8d68e"),             # найденная коллизия
    ("69ny4tv5t8k9", "", "cda8d68e"),
]


def check_lab1():
    import dh
    return dh.self_test() == len(dh.TABLE_1_1)


def check_lab2():
    import rsa
    return rsa.self_test()


def check_lab3():
    """У ЛР3 нет функции самопроверки: контрольные хэши из README (sin считает libm
    системы — значения должны совпасть на всех трёх) и структурные пары пункта 3 меню."""
    import myhash
    ok = True
    for message, salt, expected in HASH_VECTORS:
        got = myhash.to_hex(myhash.my_hash(message, salt))
        ok = ok and got == expected
        label = f"hash({message!r}" + (f", соль {salt!r})" if salt else ")")
        print(f"  {label:24} = {got}  {'совпал' if got == expected else 'НЕ СОВПАЛ'} с README")
    rows = myhash.structural_checks(myhash.my_hash)
    differ = sum(not row[6] for row in rows[:-1])
    control = rows[-1][6]                   # последняя пара — одинаковые входы
    print(f"  структурные пары с разными хэшами: {differ}/{len(rows) - 1}, "
          f"контрольная пара совпала: {'да' if control else 'нет'}")
    return ok and differ == len(rows) - 1 and control


def check_lab4():
    import signature
    return signature.self_test()


def check_aes():
    import aes
    return aes.self_test()


def check_storage():
    import storage
    return storage.self_test()


def check_lab5_window():
    """Модуль окна и Tcl/Tk без создания окна: дисплея в CI нет."""
    import manager                                  # noqa: F401  tkinter, ttk, messagebox
    import tkinter
    tcl = tkinter.Tcl()                             # интерпретатор Tcl без Tk
    print(f"  manager.py импортирован; Tcl {tcl.eval('info patchlevel')}, "
          f"Tk {tkinter.TkVersion}")
    print(f"  библиотека Tcl: {tcl.eval('info library')}")
    tk_dir = os.environ.get("TK_LIBRARY")           # задаёт PyInstaller в исполняемом файле
    if not tk_dir:
        return True
    found = os.path.isfile(os.path.join(tk_dir, "tk.tcl"))
    print(f"  библиотека Tk: {tk_dir} — tk.tcl {'есть' if found else 'НЕ НАЙДЕН'}")
    return found


def check_processes():
    """Работы 1–4 в отдельном процессе, как из меню: меню работы и выход по вводу «0»."""
    ok = True
    for number in (1, 2, 3, 4):
        result = subprocess.run(lab_command(number), input="0\n", capture_output=True,
                                encoding="utf-8", errors="replace", timeout=300)
        good = result.returncode == 0 and f"Лабораторная работа №{number}." in result.stdout
        ok = ok and good
        print(f"  lab{number}: код возврата {result.returncode}, меню работы "
              f"{'показано' if good else 'НЕ показано'}")
        if not good:
            print(result.stdout + result.stderr)
    return ok


SELF_TESTS = [
    ("ЛР1: самопроверка по таблице 1.1 (пункт 3 меню)", check_lab1),
    ("ЛР2: самопроверка RSA (пункт 5 меню)", check_lab2),
    ("ЛР3: контрольные хэши из README и структурные пары", check_lab3),
    ("ЛР4: автотест ЭЦП на 1000 сообщений (пункт 6 меню)", check_lab4),
    ("ЛР5: шифр AES, векторы FIPS-197 (aes.py)", check_aes),
    ("ЛР5: подсистемы хранилища (storage.py)", check_storage),
    ("ЛР5: модуль окна и Tcl/Tk без открытия окна", check_lab5_window),
    ("Запуск работ 1–4 в отдельном процессе", check_processes),
]


def self_test():
    add_lab_paths()
    results = []
    for title, check in SELF_TESTS:
        print(f"\n=== {title}")
        try:
            ok = bool(check())
        except Exception:                   # сбой проверки — тоже результат, идём дальше
            sys.stdout.flush()
            traceback.print_exc()
            ok = False
        results.append(ok)
        print(f"[{'ок' if ok else 'ОШИБКА'}] {title}")
    passed = sum(results)
    print(f"\nИтог: {passed}/{len(results)} проверок пройдено")
    return 0 if passed == len(results) else 1


# --- Точка входа ---------------------------------------------------------------------------
def main(argv):
    setup_console()
    if len(argv) < 2:
        return menu()
    first, rest = argv[1], argv[2:]
    if first in ("-h", "--help"):
        print(help_text())
        return 0
    if first == "--selftest":
        return self_test()
    number = parse_lab(first)
    if number is None:
        print(f"Неизвестный аргумент «{first}»: укажите работу lab1–lab5. "
              f"Справка: {program_name()} --help", file=sys.stderr)
        return 2
    return run_lab(number, rest)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
