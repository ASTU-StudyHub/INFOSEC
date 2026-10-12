#!/usr/bin/env python3
"""Лабораторная работа №3. Разработка алгоритма хэш-функции.

Вариант 1 по таблице 3.1 методических указаний: основная функция sin(m).

Схема — итеративная (как у MD5/SHA), внутреннее состояние 64 бита = две 32-битные
половины (L, R), выход 32 бита (8 шестнадцатеричных цифр):

    (L, R) ← (IV_L, IV_R)
    для каждого символа с кодом c:      (L, R) ← (R, L xor F(R, c))      — раунд сети Фейстеля
    выход ← fmix(L xor R xor длина)     — свёртка 64 → 32 бита и перемешивание

Функция раунда F на основе sin (то, что по заданию лежит в основе алгоритма):
    t = (31·R + c) mod 2^32;  F = (round(sin(t)·2^30) mod 2^32) · P mod 2^32,
    P = 16777619 (простое из FNV-1a)

Почему именно так.
- Раунд Фейстеля обратим при известном символе: (L, R) = (R' xor F(L', c), L') — значит,
  шаг сжатия не «схлопывает» состояние: для одного и того же символа он переставляет
  2^64 состояний, а не отображает их случайно. Без этого две длинные строки одинаковой
  длины сходились к общему состоянию (у случайного отображения на 32 битах — уже через
  ~2^16 шагов), а вероятность коллизии на шаге была вдвое выше положенной.
- Односторонность даёт не sin (на отрезке монотонности он обратим через arcsin), а свёртка
  64-битного состояния в 32-битный выход: по хэшу состояние не восстановить, каждому
  выходу отвечает ~2^32 состояний. Прообраз ищется только перебором ~2^32 сообщений,
  второй прообраз — так же, коллизия — за ~2^16 попыток по парадоксу дней рождения
  (поиск пары с одинаковым хэшем из пункта 3 задания выполним; при 64-битном выходе
  перебор коллизию не нашёл бы).
- sin(t) квантуется до целого round(sin(t)·2^30): библиотеки libm (Apple, glibc) дают
  для больших аргументов значения, различающиеся в последнем бите double, и без
  квантования хэш одного сообщения на разных системах отличался бы. Умножение на P
  «размазывает» арксинусное распределение sin по всем 32 битам.
- Буквальный sin(m) от всего сообщения как одного числа не годится: double хранит 53 бита,
  и уже при 10 символах младшие символы перестают влиять на аргумент.
- Соль приписывается через разделитель: h("abc", соль "") ≠ h("bc", соль "a").
- Алфавит не проверяется (любой символ по коду): та же функция нужна в ЛР4 для ASCII.

Только стандартная библиотека. Запуск: python3 myhash.py
"""

import math
import random
import string
import time

MASK = 0xFFFFFFFF
IV_L = 0x811C9DC5            # смещение FNV-1a — ненулевое начальное состояние
IV_R = 0x9E3779B9            # 2^32 / золотое сечение — вторая половина состояния
P = 16777619                 # простое FNV-1a: нечётное, умножение обратимо по модулю 2^32
MUL = 31                     # нечётный (как в hashCode Java): t = 31·R + c обратимо по R
SIN_SCALE = 2 ** 30          # квантование sin до целого: последний бит libm почти не влияет
FMIX_1, FMIX_2 = 0x85EBCA6B, 0xC2B2AE35   # финализатор fmix32 из MurmurHash3 (сдвиги 16, 13, 16)
SEPARATOR = "\x1f"           # разделитель соли и сообщения (unit separator)
ALPHABET = string.ascii_lowercase + string.digits   # алфавит тестов по заданию: a-z, 0-9


# --- Ядро -----------------------------------------------------------------------------
def round_function(right, code):
    """Функция раунда F(R, c) на основе sin: половина состояния и код символа → 32 бита."""
    t = (MUL * right + code) & MASK          # аргумент sin: целое, зависит от R и символа
    quantized = int(round(math.sin(t) * SIN_SCALE)) & MASK
    return (quantized * P) & MASK


def compress(left, right, code):
    """Один раунд сети Фейстеля: (L, R) → (R, L xor F(R, c)). Биекция по (L, R):
    обратный ход — (L, R) = (R' xor F(L', c), L')."""
    return right, left ^ round_function(right, code)


def fmix(x):
    """Финализатор MurmurHash3 (fmix32): перемешивает 32 бита, обратим — служит только
    для лавины и равномерности, информацию не теряет (её теряет свёртка L xor R)."""
    x ^= x >> 16
    x = (x * FMIX_1) & MASK
    x ^= x >> 13
    x = (x * FMIX_2) & MASK
    x ^= x >> 16
    return x


def my_hash(message, salt=""):
    """Хэш сообщения (строка любой длины, включая пустую) с необязательной солью.
    Возвращает целое 0 ≤ h < 2^32; шестнадцатеричная запись — to_hex(h)."""
    data = salt + SEPARATOR + message if salt else message
    left, right = IV_L, IV_R
    for ch in data:
        left, right = compress(left, right, ord(ch))
    return fmix(left ^ right ^ len(data))


def to_hex(h):
    return format(h, "08x")


def naive_hash(message):
    """«Наивная» схема для сравнения в анализе: floor(|sin(сумма кодов)|·2^32) —
    коммутативна, неравномерна (арксинусное распределение)."""
    value = math.sin(sum(ord(ch) for ch in message))
    return int(abs(value) * 4294967296.0) & MASK


# --- Тесты по заданию ------------------------------------------------------------------
def hamming(a, b):
    return bin(a ^ b).count("1")


def random_message(rng, lo=1, hi=12):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(lo, hi)))


def sample_messages(count=100, seed=2026, lo=1, hi=12):
    """count различных случайных сообщений в фиксированном порядке (воспроизводимо по seed)."""
    rng = random.Random(seed)
    messages = []
    while len(messages) < count:
        m = random_message(rng, lo, hi)
        if m not in messages:
            messages.append(m)
    return messages


def avalanche_pair(message, position, new_char, hash_fn):
    """Сообщение против него же с заменой одного символа: оба хэша и расстояние Хэмминга."""
    changed = message[:position] + new_char + message[position + 1:]
    h1, h2 = hash_fn(message), hash_fn(changed)
    return changed, h1, h2, hamming(h1, h2)


def avalanche_stats(hash_fn, pairs=1000, seed=2026):
    """Среднее, минимум и максимум расстояния Хэмминга по случайным парам,
    отличающимся ровно одним символом (замена всегда отличается от исходного символа)."""
    rng = random.Random(seed)
    distances = []
    for _ in range(pairs):
        message = random_message(rng, 2, 12)
        position = rng.randrange(len(message))
        new_char = rng.choice(ALPHABET.replace(message[position], ""))
        distances.append(avalanche_pair(message, position, new_char, hash_fn)[3])
    return sum(distances) / len(distances), min(distances), max(distances)


def find_collision(seed=2026):
    """Поиск коллизии методом дней рождения: различные случайные сообщения до первого
    повтора хэша. Возвращает (сообщение 1, сообщение 2, хэш, число различных
    сообщений, секунды)."""
    rng = random.Random(seed)
    seen_hash, seen_msg = {}, set()
    t0 = time.perf_counter()
    while True:
        message = random_message(rng)
        if message in seen_msg:
            continue
        seen_msg.add(message)
        h = my_hash(message)
        if h in seen_hash:
            return seen_hash[h], message, h, len(seen_msg), time.perf_counter() - t0
        seen_hash[h] = message


def distribution(hash_fn, count=100, seed=2026, buckets=16):
    """Хэши count различных сообщений: отсортированный список (хэш, сообщение) и число
    хэшей в каждом из buckets равных диапазонов (при 16 диапазонах — первая hex-цифра)."""
    items = sorted((hash_fn(m), m) for m in sample_messages(count, seed))
    counts = [0] * buckets
    for h, _ in items:
        counts[h * buckets >> 32] += 1
    return items, counts


STRUCTURAL_PAIRS = [
    (("ab", ""), ("ba", "")),          # перестановка символов
    (("aa", ""), ("", "")),            # повтор символа против пустого входа
    (("abc", ""), ("bc", "a")),        # перенос символа из сообщения в соль
    (("0", ""), ("00", "")),           # ведущие нули
    (("a", ""), ("a", "")),            # контроль: одинаковые входы → одинаковый хэш
]


def structural_checks(hash_fn):
    """Пары входов, на которых ломаются наивные схемы. hash_fn(message, salt) → int."""
    rows = []
    for (m1, s1), (m2, s2) in STRUCTURAL_PAIRS:
        h1, h2 = hash_fn(m1, s1), hash_fn(m2, s2)
        rows.append((m1, s1, m2, s2, h1, h2, h1 == h2))
    return rows


# --- Меню ----------------------------------------------------------------------------------
def ask_salt():
    answer = input("  Добавить соль? (y/n): ").strip().lower()
    return input("  Соль: ") if answer in ("y", "д", "yes", "да") else ""


def mode_hash():
    message = input("  Сообщение (Enter — пустое): ")
    salt = ask_salt()
    h = my_hash(message, salt)
    print(f"  hash({message!r}{', соль ' + repr(salt) if salt else ''}) = {to_hex(h)}")


def mode_avalanche():
    message = input("  Сообщение (не короче 1 символа): ")
    while not message:
        message = input("  Сообщение не может быть пустым, повторите: ")
    while True:
        try:
            position = int(input(f"  Позиция заменяемого символа (0..{len(message) - 1}): "))
            if 0 <= position < len(message):
                break
        except ValueError:
            pass
        print("  Нужен номер позиции в пределах сообщения.")
    new_char = input("  Новый символ: ")[:1]
    while not new_char or new_char == message[position]:
        new_char = input("  Новый символ должен отличаться от исходного: ")[:1]
    changed, h1, h2, dist = avalanche_pair(message, position, new_char, my_hash)
    print(f"  {message!r:16} → {to_hex(h1)}  {h1:032b}")
    print(f"  {changed!r:16} → {to_hex(h2)}  {h2:032b}")
    marks = "".join("^" if (h1 ^ h2) >> (31 - i) & 1 else " " for i in range(32))
    print(f"  различаются биты:            {marks}")
    print(f"  расстояние Хэмминга: {dist} из 32 ({dist / 32:.0%}); "
          "ожидание для идеальной функции — 16")
    mean, lo, hi = avalanche_stats(my_hash)
    print(f"  Статистика по 1000 случайным парам: среднее {mean:.2f}, минимум {lo}, "
          f"максимум {hi} из 32 (биномиальное распределение B(32, 1/2): σ ≈ 2.8)")


def mode_collision():
    print("  Структурные проверки (пары, на которых ломаются наивные схемы):")
    for m1, s1, m2, s2, h1, h2, same in structural_checks(my_hash):
        left = f"hash({m1!r}{', соль ' + repr(s1) if s1 else ''})"
        right = f"hash({m2!r}{', соль ' + repr(s2) if s2 else ''})"
        verdict = "СОВПАЛИ" if same else "различны"
        print(f"    {left:26} = {to_hex(h1)}   {right:26} = {to_hex(h2)}   {verdict}")
    raw = input("  Seed генератора сообщений "
                "(Enter — три запуска с seed 2026, 1, 2): ").strip()
    seeds = [2026, 1, 2]
    if raw:
        try:
            seeds = [int(raw)]
        except ValueError:
            print("  Нужно целое число; выполняются три запуска с seed 2026, 1, 2.")
    expected = math.sqrt(math.pi / 2 * 2 ** 32)
    print("  Поиск коллизии методом дней рождения "
          "(различные сообщения из a-z0-9 длины 1..12);")
    print(f"  ожидание для 32 бит: sqrt(π/2 · 2^32) ≈ {expected:.0f} сообщений, "
          "разброс ±50 % (σ ≈ 0.52·E)")
    counts = []
    for seed in seeds:
        m1, m2, h, n, seconds = find_collision(seed)
        counts.append(n)
        print(f"    seed {seed:5d}: {m1!r} и {m2!r} → {to_hex(h)}; "
              f"различных сообщений {n}, время {seconds:.2f} с")
    if len(counts) > 1:
        mean = sum(counts) / len(counts)
        print(f"  Среднее по {len(counts)} запускам: {mean:.0f} (теория {expected:.0f})")


def mode_distribution():
    items, counts = distribution(my_hash)
    print("  Отсортированные хэши 100 различных случайных сообщений (seed 2026):")
    for row in range(0, len(items), 4):
        print("    " + "   ".join(f"{to_hex(h)} {m:<12}" for h, m in items[row:row + 4]))
    expected = len(items) / len(counts)
    sigma = math.sqrt(expected * (1 - 1 / len(counts)))
    print(f"  Распределение по 16 диапазонам (первая hex-цифра), "
          f"ожидание {expected:.2f} на диапазон, σ ≈ {sigma:.2f}:")
    for i, c in enumerate(counts):
        print(f"    {i:x}xxxxxxx  {c:3d}  {'#' * c}")
    cluster = math.floor(3 * expected) + 1    # наименьшее целое больше трёх ожиданий
    print(f"  Минимум {min(counts)}, максимум {max(counts)}; максимум из 16 диапазонов "
          f"при равномерном распределении обычно 10–12, скоплением считается {cluster} "
          "и более (свыше трёх ожиданий).")
    print("  Скоплений нет." if max(counts) < cluster else "  Внимание: есть скопление.")


def mode_compare():
    """Наивная схема (sin от суммы кодов) против итоговой на одних и тех же сообщениях."""
    print("  Наивная схема (floor(|sin(сумма кодов)|·2^32)) против итоговой, "
          "одинаковые сообщения и seed:")
    schemes = (("наивная", lambda m, s="": naive_hash(s + SEPARATOR + m if s else m)),
               ("итоговая", my_hash))
    for name, fn in schemes:
        mean, lo, hi = avalanche_stats(fn)
        _, counts = distribution(fn)
        pairs = structural_checks(fn)
        broken = sum(1 for row in pairs[:-1] if row[6])
        print(f"    {name:9}: лавина в среднем {mean:.1f} бит из 32 (мин {lo}, макс {hi}); "
              f"максимум в диапазоне {max(counts)} из 100; структурных коллизий {broken} из 4 "
              f"(ab/ba: {'совпали' if pairs[0][6] else 'различны'})")


def main():
    menu = ("\nЛабораторная работа №3. Хэш-функция на основе sin(m) (вариант 1), выход 32 бита\n"
            "  1 — вычислить хэш сообщения (с солью по желанию)\n"
            "  2 — эффект лавины: замена одного символа\n"
            "  3 — устойчивость к коллизиям и поиск пары с одинаковым хэшем\n"
            "  4 — равномерность распределения: 100 сообщений по 16 диапазонам\n"
            "  5 — сравнение с наивной схемой sin(сумма кодов)\n"
            "  0 — выход")
    actions = {"1": mode_hash, "2": mode_avalanche, "3": mode_collision,
               "4": mode_distribution, "5": mode_compare}
    try:
        while True:
            print(menu)
            choice = input("Выбор: ").strip()
            if choice == "0":
                break
            if choice in actions:
                actions[choice]()
            else:
                print("  Нет такого пункта меню.")
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")


if __name__ == "__main__":
    main()
