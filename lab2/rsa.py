#!/usr/bin/env python3
"""Лабораторная работа №2. Алгоритм шифрования RSA.

Ключи по методичке: p, q — простые; n = p·q; φ = (p−1)(q−1); d выбирается
случайно и взаимно просто с φ; e находится из условия e·d mod φ = 1.
Открытый ключ {e, n}, закрытый {d, n}.
Шифрование посимвольно: M = код символа, C = M^e mod n, M = C^d mod n.
Каждый блок должен быть меньше n. Порог n ≥ 256 взят с запасом: любой байт
0..255 меньше n; для 7-битного ASCII (0..127), который принимает программа,
хватило бы n ≥ 128.

Режимы: случайные ключи, ручной ввод ключей, шифрование, расшифрование,
самопроверка (пример методички + прогон всех кодов ASCII), вычисление
закрытого ключа по открытому (факторизация n — к контрольному вопросу 2).

Только стандартная библиотека. Запуск: python3 rsa.py
"""

import random
import time

P_MIN, P_MAX = 100, 9999     # диапазон случайных простых p, q
N_MIN = 256                  # n ≥ 256 — любой байт 0..255 меньше n (для ASCII 0..127 хватило бы 128)

# Пример методички: p = 3, q = 11, n = 33, d = 3, e = 7; "CAB" при A=1, B=2, C=3
EXAMPLE = {"p": 3, "q": 11, "d": 3, "e": 7, "M": [3, 1, 2], "C": [9, 1, 29]}


# --- Арифметика ---------------------------------------------------------------
def modpow(base, exp, mod):
    """Бинарное возведение в степень по модулю; остаток после каждого умножения.
    Считать base**exp целиком нельзя: при 4-значных p, q это число из миллионов
    цифр. Эквивалентно встроенному pow(base, exp, mod)."""
    if mod == 1:
        return 0
    result, base = 1, base % mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def is_prime(n):
    """Пробное деление до sqrt(n): для n < 10^6 мгновенно."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    k = 3
    while k * k <= n:
        if n % k == 0:
            return False
        k += 2
    return True


def gen_prime(lo=P_MIN, hi=P_MAX):
    while True:
        n = random.randint(lo, hi)
        if is_prime(n):
            return n


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def egcd(a, b):
    """Расширенный алгоритм Евклида: возвращает (g, x, y), где a·x + b·y = g = НОД(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a, m):
    """Обратный элемент a^(-1) mod m; существует только при НОД(a, m) = 1.
    Результат нормализуется в диапазон [1, m−1]. Эквивалентно pow(a, -1, m)."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"обратного элемента нет: НОД({a}, {m}) = {g}")
    return x % m


# --- Ключи ------------------------------------------------------------------------
def key_errors(p, q, d=None):
    """Список нарушений условий на p, q, d (пустой список — всё в порядке)."""
    errors = []
    if not is_prime(p):
        errors.append(f"p = {p} не простое")
    if not is_prime(q):
        errors.append(f"q = {q} не простое")
    if p == q:
        errors.append("p и q должны быть различны: при p = q формула φ = (p−1)(q−1) неверна")
    if p * q < N_MIN:
        errors.append(f"n = p·q = {p * q} < {N_MIN}: не любой код символа поместится в блок M < n")
    if d is not None and not errors:
        phi = (p - 1) * (q - 1)
        if not 1 < d < phi:
            errors.append(f"d должно лежать в (1, φ) = (1, {phi})")
        elif gcd(d, phi) != 1:
            errors.append(f"НОД(d, φ) = НОД({d}, {phi}) = {gcd(d, phi)} ≠ 1: обратного e нет")
    return errors


def make_keys(p, q, d=None, check=True):
    """Генерация пары ключей по методичке. Возвращает ((e, n), (d, n), φ).
    Если d не задано — выбирается случайно из (1, φ) до выполнения НОД(d, φ) = 1.
    check=False отключает проверку условий (нужно для примера методички с n = 33 < 256).
    Корректность M = C^d mod n для всех 0 ≤ M < n следует из e·d ≡ 1 (mod φ) и
    теоремы Эйлера (при НОД(M, n) = 1), а для M, кратных p или q, — из китайской
    теоремы об остатках; поэтому p ≠ q обязательно: при p = q значение φ иное."""
    if check:
        errors = key_errors(p, q, d)
        if errors:
            raise ValueError("; ".join(errors))
    n, phi = p * q, (p - 1) * (q - 1)
    if d is None:
        while True:
            d = random.randint(2, phi - 1)
            if gcd(d, phi) == 1:
                break
    e = modinv(d, phi)
    return (e, n), (d, n), phi


# --- Шифрование ---------------------------------------------------------------------
def encrypt_int(m, e, n):
    if not 0 <= m < n:
        raise ValueError(f"блок M = {m} должен лежать в [0, n−1] = [0, {n - 1}]")
    return modpow(m, e, n)


def decrypt_int(c, d, n):
    return modpow(c, d, n)


def encrypt_text(text, e, n):
    """Каждый символ — отдельный блок M = ord(символа). Возвращает список чисел."""
    return [encrypt_int(ord(ch), e, n) for ch in text]


def decrypt_text(numbers, d, n):
    """Обратное преобразование. При неверном ключе или чужом шифртексте блок M
    может не быть кодом символа — тогда ValueError с понятным сообщением."""
    chars = []
    for c in numbers:
        m = decrypt_int(c, d, n)
        if m > 0x10FFFF:
            raise ValueError(f"блок M = {m} не является кодом символа: неверный ключ или чужой шифртекст")
        chars.append(chr(m))
    return "".join(chars)


# --- Самопроверка и атака -------------------------------------------------------------
def self_test(verbose=True):
    """1) пример методички (p=3, q=11, d=3 → e=7; 3,1,2 → 9,1,29 → 3,1,2);
    2) прогон всех кодов 0..255 через ключ с n ≥ 256 (p=5, q=53, n=265)."""
    ex = EXAMPLE
    (e, n), (d, _), phi = make_keys(ex["p"], ex["q"], ex["d"], check=False)
    c = [encrypt_int(m, e, n) for m in ex["M"]]
    back = [decrypt_int(x, d, n) for x in c]
    ok1 = e == ex["e"] and c == ex["C"] and back == ex["M"]
    if verbose:
        print(f"  Пример методички: p={ex['p']}, q={ex['q']}, n={n}, φ={phi}, d={d} → e={e} (ожидалось {ex['e']})")
        print(f"    M = {ex['M']} → C = {c} (ожидалось {ex['C']}) → M' = {back}: {'PASS' if ok1 else 'FAIL'}")
    (e, n), (d, _), _ = make_keys(5, 53, 7)
    matched = sum(decrypt_int(encrypt_int(m, e, n), d, n) == m for m in range(256))
    ok2 = matched == 256
    if verbose:
        print(f"  Все коды 0..255 через ключ n={n} (p=5, q=53, d={d}, e={e}): совпало {matched}/256: {'PASS' if ok2 else 'FAIL'}")
        print(f"  Итог самопроверки: {'OK' if ok1 and ok2 else 'ОШИБКА'}")
    return ok1 and ok2


def factor(n):
    """Разложение n = p·q пробным делением до sqrt(n). Возвращает (p, q) или None."""
    if n % 2 == 0:
        return 2, n // 2
    k = 3
    while k * k <= n:
        if n % k == 0:
            return k, n // k
        k += 2
    return None


def recover_private_key(e, n):
    """Действия противника, знающего только открытый ключ {e, n}:
    факторизовать n → φ → d = e^(-1) mod φ. Возвращает (p, q, d, время в мс)."""
    t0 = time.perf_counter()
    p, q = factor(n)
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return p, q, d, (time.perf_counter() - t0) * 1000


# --- Ввод ---------------------------------------------------------------------------
def read_int(prompt, check=None, allow_empty=False):
    """Читает целое; check(value) возвращает None (OK) или текст ошибки.
    При allow_empty пустая строка возвращает None."""
    while True:
        raw = input(prompt).strip()
        if allow_empty and raw == "":
            return None
        try:
            value = int(raw)
        except ValueError:
            print("  Нужно ввести целое число.")
            continue
        error = check(value) if check else None
        if error is None:
            return value
        print(" ", error + ".")


def read_text(prompt):
    """Строка из символов ASCII (коды 0..127); иначе — сообщение и повтор."""
    while True:
        text = input(prompt)
        bad = [ch for ch in text if ord(ch) > 127]
        if not bad:
            return text
        print(f"  Символ «{bad[0]}» (код {ord(bad[0])}) вне кодировки ASCII, повторите ввод.")


class State:
    public = None        # (e, n)
    private = None       # (d, n)
    phi = None
    last_cipher = None   # последний шифртекст (список чисел)


def show_keys(st, p=None, q=None):
    (e, n), (d, _) = st.public, st.private
    if p is not None:
        print(f"  p = {p}, q = {q}, n = p·q = {n}, φ = (p−1)(q−1) = {st.phi}")
    print(f"  d = {d} (НОД(d, φ) = {gcd(d, st.phi)}), e = d⁻¹ mod φ = {e}, проверка: e·d mod φ = {e * d % st.phi}")
    print(f"  Открытый ключ {{e, n}} = {{{e}, {n}}}, закрытый ключ {{d, n}} = {{{d}, {n}}}")


def random_keys(st):
    print(f"Случайные ключи: p, q — простые из [{P_MIN}, {P_MAX}], d — случайное, взаимно простое с φ.")
    p = gen_prime()
    q = gen_prime()
    while q == p:
        q = gen_prime()
    st.public, st.private, st.phi = make_keys(p, q)
    show_keys(st, p, q)


def manual_keys(st):
    print("Ручной ввод ключей.")
    p = read_int("  p (простое): ", lambda v: None if is_prime(v) else f"p = {v} не простое")

    def check_q(v):
        if not is_prime(v):
            return f"q = {v} не простое"
        if v == p:
            return "q должно отличаться от p: при p = q формула φ = (p−1)(q−1) неверна"
        if p * v < N_MIN:
            return f"n = p·q = {p * v} < {N_MIN}: не любой код символа поместится в блок M < n"
        return None

    q = read_int("  q (простое, q ≠ p, p·q ≥ 256): ", check_q)
    phi = (p - 1) * (q - 1)
    print(f"  n = {p * q}, φ = {phi}")

    def check_d(v):
        if not 1 < v < phi:
            return f"d должно лежать в (1, φ) = (1, {phi})"
        if gcd(v, phi) != 1:
            return f"НОД(d, φ) = {gcd(v, phi)} ≠ 1: обратного e нет"
        return None

    d = read_int("  d (1 < d < φ, НОД(d, φ) = 1): ", check_d)
    st.public, st.private, st.phi = make_keys(p, q, d)
    show_keys(st, p, q)


def encrypt_mode(st):
    if st.public is None:
        print("  Сначала задайте ключи (пункт 1 или 2).")
        return
    e, n = st.public
    text = read_text("  Текст (ASCII): ")
    st.last_cipher = encrypt_text(text, e, n)
    print(f"  Коды символов M: {[ord(ch) for ch in text]}")
    print(f"  Шифртекст C = M^e mod n ({{e, n}} = {{{e}, {n}}}):")
    print("  " + " ".join(map(str, st.last_cipher)))


def decrypt_mode(st):
    has_key = st.private is not None
    d = read_int("  d (Enter — текущий закрытый ключ): " if has_key else "  d: ",
                 lambda v: None if v > 0 else "d должно быть положительным", allow_empty=has_key)
    n = read_int("  n (Enter — текущий): " if has_key else "  n: ",
                 lambda v: None if v > 1 else "n должно быть больше 1", allow_empty=has_key)
    if d is None:
        d, n = st.private
    elif n is None:
        n = st.private[1]
    prompt = "  Шифртекст, числа через пробел" + (" (Enter — последний результат): " if st.last_cipher else ": ")
    while True:
        raw = input(prompt).strip()
        if raw == "" and st.last_cipher:
            numbers = st.last_cipher
            break
        try:
            numbers = [int(x) for x in raw.split()]
        except ValueError:
            print("  Нужны целые числа через пробел.")
            continue
        if any(not 0 <= c < n for c in numbers):
            print(f"  Каждое число должно лежать в [0, n−1] = [0, {n - 1}].")
            continue
        break
    try:
        text = decrypt_text(numbers, d, n)
    except ValueError as err:
        print(f"  Не удалось расшифровать: {err}.")
        return
    print(f"  M = C^d mod n ({{d, n}} = {{{d}, {n}}}): {[ord(ch) for ch in text]}")
    print(f"  Расшифрованный текст: {text!r}")


def attack_mode(st):
    if st.public is None:
        print("  Сначала задайте ключи (пункт 1 или 2).")
        return
    e, n = st.public
    print(f"  Противник знает только открытый ключ {{e, n}} = {{{e}, {n}}}.")
    p, q, d, ms = recover_private_key(e, n)
    print(f"  Факторизация: n = {p} · {q}, φ = {(p - 1) * (q - 1)}, d = e⁻¹ mod φ = {d}  ({ms:.3f} мс)")
    print(f"  Совпадает с настоящим закрытым ключом: {'да' if d == st.private[0] else 'нет'}")


def main():
    st = State()
    menu = ("\nЛабораторная работа №2. Алгоритм шифрования RSA\n"
            "  1 — случайные ключи\n"
            "  2 — ввод ключей вручную (p, q, d)\n"
            "  3 — зашифровать текст открытым ключом {e, n}\n"
            "  4 — расшифровать закрытым ключом {d, n}\n"
            "  5 — самопроверка (пример методички, все коды ASCII)\n"
            "  6 — вычислить закрытый ключ по открытому (факторизация n)\n"
            "  0 — выход")
    actions = {"1": random_keys, "2": manual_keys, "3": encrypt_mode, "4": decrypt_mode,
               "5": lambda _: self_test(), "6": attack_mode}
    try:
        while True:
            print(menu)
            choice = input("Выбор: ").strip()
            if choice == "0":
                break
            if choice in actions:
                actions[choice](st)
            else:
                print("  Нет такого пункта меню.")
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")


if __name__ == "__main__":
    main()
