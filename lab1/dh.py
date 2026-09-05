#!/usr/bin/env python3
"""Лабораторная работа №1. Протокол Диффи-Хеллмана.

Программа состоит из частей Алисы и Боба. Алиса (инициатор) генерирует
открытые параметры p и α и свой секретный показатель x, передаёт p, α и
A = α^x mod p Бобу по открытому каналу. Боб выбирает секретный y, отвечает
B = α^y mod p. Обе стороны вычисляют общий ключ K:
    K_A = B^x mod p,   K_B = A^y mod p,   K_A == K_B == α^(xy) mod p.

Режимы: случайная генерация параметров, ручной ввод с клавиатуры,
самопроверка по таблице 1.1 методички, перебор ключа третьим лицом
по журналу канала (почему учебное p < 10000 не даёт стойкости).

Только стандартная библиотека. Запуск: python3 dh.py
"""

import random
import time

# --- Ограничения задания ---------------------------------------------------
# «Ключ (< 10000)» трактуем как ограничение на модуль p; тогда все значения,
# идущие по каналу (p, α, A, B), и сам ключ K тоже меньше 10000.
P_MIN = 5          # при p = 2, 3 нет ни одного α в диапазоне [2, p-2]
P_MAX = 9999

# Таблица 1.1 методички — тест самопроверки: (p, α, x, y, K)
TABLE_1_1 = [
    (29, 2, 60, 82, 23),
    (53, 2, 20, 77, 42),
    (73, 5, 37, 47, 31),
    (31, 3, 31, 51, 15),
    (41, 6, 31, 98, 8),
    (19, 2, 20, 73, 4),
    (71, 7, 30, 89, 45),
    (109, 6, 7, 14, 84),
    (131, 2, 88, 15, 52),
    (97, 5, 58, 68, 6),
]


# --- Арифметика по модулю ---------------------------------------------------
def modpow(base, exp, mod):
    """Быстрое возведение в степень по модулю (бинарный метод).

    Остаток берётся после каждого умножения, поэтому промежуточные значения
    не превышают (mod-1)^2. Считать base**exp целиком не стоит: при p ~ 10^4
    и x ~ 10^4 это число из десятков тысяч цифр (в Java/C — переполнение,
    через double — потеря точности). Эквивалентно встроенному pow(base, exp, mod).
    """
    if mod == 1:
        return 0
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:                     # текущий бит показателя равен 1
            result = result * base % mod
        base = base * base % mod        # base^(2^i)
        exp >>= 1
    return result


def is_prime(n):
    """Проверка простоты пробным делением до sqrt(n). Для n < 10000 хватает."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def element_order(a, p):
    """Порядок элемента a в группе Z_p*: наименьшее k >= 1 с a^k ≡ 1 (mod p).

    Лобовой подсчёт: умножаем на a, пока не получим 1. O(p) шагов,
    для p < 10000 это доли миллисекунды. Определено только для простого p:
    при составном p множество {1..p-1} не является группой по умножению.
    """
    if not is_prime(p):
        raise ValueError("порядок элемента определён только для простого p")
    a %= p
    if a == 0:
        raise ValueError("a должно быть ненулевым по модулю p")
    k, value = 1, a
    while value != 1:
        value = value * a % p
        k += 1
    return k


def is_generator(a, p):
    """α — порождающий элемент Z_p*, если его порядок равен p-1,
    т.е. степени α^1..α^(p-1) пробегают все числа 1..p-1."""
    return 2 <= a <= p - 2 and element_order(a, p) == p - 1


def gen_prime(lo=P_MIN, hi=P_MAX):
    """Случайное простое из [lo, hi]."""
    while True:
        n = random.randint(lo, hi)
        if is_prime(n):
            return n


def gen_generator(p):
    """Случайный порождающий элемент Z_p*. Генераторов ровно φ(p-1) штук
    (в среднем около трети от p-1), поэтому нужно несколько попыток."""
    while True:
        a = random.randint(2, p - 2)
        if is_generator(a, p):
            return a


# --- Участники протокола и открытый канал ------------------------------------
class Channel:
    """Открытый (прослушиваемый) канал: всё, что через него проходит,
    печатается и записывается в журнал — это ровно то, что видит третье лицо."""

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.log = {}                   # метка -> значение, в порядке передачи

    def send(self, sender, receiver, label, value):
        self.log[label] = value
        if self.verbose:
            print(f"  {sender} -> {receiver}: {label} = {value}")
        return value


class Participant:
    """Общая часть Алисы и Боба: секретный показатель и две операции протокола."""

    def __init__(self, name):
        self.name = name
        self.secret = None              # x у Алисы, y у Боба; канал не покидает
        self.key = None                 # общий ключ K после завершения протокола

    def choose_secret(self, p, value=None):
        self.secret = value if value is not None else random.randint(1, p - 2)
        return self.secret

    def public_value(self, alpha, p):
        """α^secret mod p — единственное, что участник отправляет в канал."""
        return modpow(alpha, self.secret, p)

    def compute_key(self, other_public, p):
        """K = (α^other)^secret mod p."""
        self.key = modpow(other_public, self.secret, p)
        return self.key


class Alice(Participant):
    """Инициатор: генерирует p, α (если не заданы) и начинает обмен."""

    def __init__(self):
        super().__init__("Alice")

    def setup(self, p=None, alpha=None):
        p = p if p is not None else gen_prime()
        alpha = alpha if alpha is not None else gen_generator(p)
        return p, alpha


class Bob(Participant):
    def __init__(self):
        super().__init__("Bob")


def run_protocol(p=None, alpha=None, x=None, y=None, verbose=True):
    """Полный сеанс протокола. Возвращает (p, α, x, y, A, B, K_A, K_B, канал)."""
    alice, bob = Alice(), Bob()
    channel = Channel(verbose)

    p, alpha = alice.setup(p, alpha)
    channel.send("Alice", "Bob", "p", p)
    channel.send("Alice", "Bob", "alpha", alpha)

    x = alice.choose_secret(p, x)
    A = channel.send("Alice", "Bob", "A = alpha^x mod p", alice.public_value(alpha, p))

    y = bob.choose_secret(p, y)
    B = channel.send("Bob", "Alice", "B = alpha^y mod p", bob.public_value(alpha, p))

    k_a = alice.compute_key(B, p)      # Алиса: K = B^x mod p
    k_b = bob.compute_key(A, p)        # Боб:   K = A^y mod p
    return p, alpha, x, y, A, B, k_a, k_b, channel


def print_session(p, alpha, x, y, A, B, k_a, k_b):
    print(f"  секрет Алисы x = {x}, секрет Боба y = {y}  (по каналу не передаются)")
    print(f"  Алиса: K = B^x mod p = {B}^{x} mod {p} = {k_a}")
    print(f"  Боб:   K = A^y mod p = {A}^{y} mod {p} = {k_b}")
    if k_a == k_b:
        print(f"  Ключи совпали: общий сеансовый ключ K = {k_a}")
    else:
        print("  ОШИБКА: ключи различны")
    if A == 1 or B == 1:
        print("  Внимание: открытое значение равно 1 — секретный показатель кратен p-1, "
              "ключ вырожден (K = 1).")


# --- Самопроверка по таблице 1.1 ----------------------------------------------
def self_test(verbose=True):
    """Прогон всех 10 строк таблицы 1.1. Возвращает число пройденных строк."""
    passed = 0
    if verbose:
        print(f"  {'№':>2} {'p':>4} {'α':>2} {'x':>3} {'y':>3} {'A':>4} {'B':>4} {'K ожид.':>8} {'K получ.':>9}  результат")
    for i, (p, alpha, x, y, k_expected) in enumerate(TABLE_1_1, 1):
        _, _, _, _, A, B, k_a, k_b, _ = run_protocol(p, alpha, x, y, verbose=False)
        ok = k_a == k_b == k_expected
        passed += ok
        if verbose:
            print(f"  {i:>2} {p:>4} {alpha:>2} {x:>3} {y:>3} {A:>4} {B:>4} {k_expected:>8} {k_a:>9}  {'PASS' if ok else 'FAIL'}")
    if verbose:
        print(f"  Итог: {passed}/{len(TABLE_1_1)} строк совпали с таблицей 1.1")
    return passed


# --- Перебор дискретного логарифма (к контрольному вопросу 2) -----------------
def brute_force_dlog(p, alpha, target):
    """По перехваченным p, α, A = α^x mod p найти x перебором k = 1, 2, ...

    Возвращает наименьший k с α^k ≡ A (mod p): это x mod (p-1), а не сам x,
    но ключ по нему восстанавливается верно. Число итераций равно найденному k.
    Работает только потому, что p мало."""
    value = 1
    for k in range(1, p):
        value = value * alpha % p
        if value == target:
            return k
    return None


def attack_demo(channel):
    """Третье лицо знает только журнал канала: p, α, A, B — и ничего больше."""
    p, alpha = channel.log["p"], channel.log["alpha"]
    A, B = channel.log["A = alpha^x mod p"], channel.log["B = alpha^y mod p"]
    t0 = time.perf_counter()
    x_found = brute_force_dlog(p, alpha, A)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    k_found = modpow(B, x_found, p) if x_found is not None else None
    print(f"  Перехвачено из канала: p = {p}, alpha = {alpha}, A = {A}, B = {B}")
    print(f"  Перебор: x = {x_found} (по модулю p-1) найден за {x_found} итераций, {elapsed_ms:.3f} мс")
    print(f"  Восстановленный ключ K = B^x mod p = {k_found}")
    return x_found, elapsed_ms, k_found


# --- Ввод с клавиатуры -----------------------------------------------------------
def read_int(prompt, check=None, error="Недопустимое значение, повторите ввод."):
    """Читает целое число; при нечисловом вводе или нарушении check
    печатает сообщение и спрашивает снова."""
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print("  Нужно ввести целое число.")
            continue
        if check is None or check(value):
            return value
        print(" ", error)


def manual_mode():
    """Ручной ввод p, α, x, y с проверками. Возвращает канал сеанса."""
    print("Ручной ввод параметров.")
    p = read_int(f"  p (простое, {P_MIN} <= p <= {P_MAX}): ",
                 lambda v: P_MIN <= v <= P_MAX and is_prime(v),
                 f"p должно быть простым числом из [{P_MIN}, {P_MAX}].")
    alpha = read_int("  alpha (порождающий элемент, 2 <= alpha <= p-2): ",
                     lambda v: is_generator(v, p),
                     "alpha должно лежать в [2, p-2] и быть порождающим элементом Z_p* "
                     "(порядок alpha равен p-1).")
    # Верхняя граница для x, y не проверяется: α^x ≡ α^(x mod (p-1)) (mod p),
    # в таблице 1.1 шесть строк из десяти имеют x или y >= p-1.
    x = read_int("  x (секрет Алисы, x >= 1): ", lambda v: v >= 1, "x должно быть >= 1.")
    y = read_int("  y (секрет Боба, y >= 1): ", lambda v: v >= 1, "y должно быть >= 1.")
    print("Обмен по открытому каналу:")
    p, alpha, x, y, A, B, k_a, k_b, channel = run_protocol(p, alpha, x, y)
    print_session(p, alpha, x, y, A, B, k_a, k_b)
    return channel


def random_mode():
    """Случайная генерация всех параметров. Возвращает канал сеанса."""
    print("Случайная генерация параметров (Алиса — инициатор).")
    print("Обмен по открытому каналу:")
    p, alpha, x, y, A, B, k_a, k_b, channel = run_protocol()
    yes_no = lambda flag: "да" if flag else "нет"
    print(f"  свойства параметров: p простое — {yes_no(is_prime(p))}, p < 10000 — {yes_no(p < 10000)}, "
          f"alpha порождающий — {yes_no(is_generator(alpha, p))}")
    print_session(p, alpha, x, y, A, B, k_a, k_b)
    return channel


def main():
    last = None                          # канал последнего сеанса — для атаки
    menu = ("\nЛабораторная работа №1. Протокол Диффи-Хеллмана\n"
            "  1 — случайная генерация параметров\n"
            "  2 — ручной ввод параметров\n"
            "  3 — самопроверка по таблице 1.1\n"
            "  4 — перебор ключа третьим лицом (по журналу последнего сеанса)\n"
            "  0 — выход")
    try:
        while True:
            print(menu)
            choice = input("Выбор: ").strip()
            if choice == "1":
                last = random_mode()
            elif choice == "2":
                last = manual_mode()
            elif choice == "3":
                self_test()
            elif choice == "4":
                if last is None:
                    last = random_mode()
                attack_demo(last)
            elif choice == "0":
                break
            else:
                print("  Нет такого пункта меню.")
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")


if __name__ == "__main__":
    main()
