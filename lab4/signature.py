#!/usr/bin/env python3
"""Лабораторная работа №4. Реализация электронной цифровой подписи.

Подпись строится из программ предыдущих работ: RSA (lab2/rsa.py) и собственной
хэш-функции (lab3/myhash.py). Схема методички:
    формирование: h = H(M);  S = h^d mod n;  передаётся пара (M, S)
    проверка:     h' = H(M);  h'' = S^e mod n;  подпись верна, если h' = h''
Закрытый ключ {d, n} есть только у автора (аутентичность, неотказуемость), открытый
{e, n} — у всех (проверяемость). Любое изменение M меняет h' — подпись не сходится
(целостность).

Условие корректности, которое нужно учесть при выборе ключей: h < n, иначе S^e mod n = h mod n ≠ h
и подпись не сходится даже на нетронутом сообщении. Хэш 32-битный, поэтому
простые p, q берутся из [2^17, 2^18): n = p·q ≥ 2^34 > 2^32.

Режимы: ключи (случайно / вручную), ввод сообщения, подпись, проверка пары (M, S),
модификация сообщения с последующей проверкой, автотест, демонстрация условия h < n.

Только стандартная библиотека. Запуск: python3 signature.py [sin|cos|xor]
"""

import os
import random
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "..", "lab2"))     # rsa.py — лабораторная №2
sys.path.insert(0, os.path.join(BASE, "..", "lab3"))     # myhash.py — лабораторная №3
import rsa      # noqa: E402  (modpow, is_prime, gcd, gen_prime, key_errors, make_keys, read_int, read_text)
import myhash   # noqa: E402  (my_hash, to_hex, hamming, VARIANTS)

P_MIN, P_MAX = 2 ** 17, 2 ** 18 - 1     # простые для n > 2^32 (хэш 32-битный)
N_MIN = 2 ** 32                          # h < 2^32 ≤ n — условие корректности проверки
EXAMPLE_KEYS = (rsa.EXAMPLE["p"], rsa.EXAMPLE["q"], rsa.EXAMPLE["d"])   # пример ЛР2 (n = 33) — демонстрация h ≥ n
ASCII_PRINTABLE = [chr(c) for c in range(32, 127)]


# --- Подпись и проверка --------------------------------------------------------------
def sign(message, d, n, variant):
    """Формирование ЭЦП: h = H(M), S = h^d mod n. Возвращает (h, S)."""
    h = myhash.my_hash(message, variant=variant)
    if h >= n:
        raise ValueError(f"хэш h = {h} ≥ n = {n}: подпись не проверится, нужны p, q ≥ 2^17")
    return h, rsa.modpow(h, d, n)


def verify(message, signature, e, n, variant):
    """Проверка ЭЦП: h' = H(M), h'' = S^e mod n. Возвращает (h', h'', совпали ли)."""
    h1 = myhash.my_hash(message, variant=variant)
    h2 = rsa.modpow(signature, e, n)
    return h1, h2, h1 == h2


def modify(message, kind, position=None, char=None, rng=random):
    """Нарушение целостности: replace / insert / delete / swap. Возвращает (M', описание).
    Подпись при этом НЕ пересчитывается — это и есть модель злоумышленника в канале."""
    if not message and kind != "insert":
        kind = "insert"
    if position is None:
        position = rng.randrange(len(message) + 1) if kind == "insert" else (rng.randrange(len(message)) if message else 0)
    if kind == "replace":
        old = message[position]
        new = char if char is not None and char != old else rng.choice([c for c in ASCII_PRINTABLE if c != old])
        return message[:position] + new + message[position + 1:], f"замена символа {old!r} на {new!r} в позиции {position}"
    if kind == "insert":
        new = char if char is not None else rng.choice(ASCII_PRINTABLE)
        position = min(position, len(message))
        return message[:position] + new + message[position:], f"вставка символа {new!r} в позицию {position}"
    if kind == "delete":
        return message[:position] + message[position + 1:], f"удаление символа {message[position]!r} из позиции {position}"
    if kind == "swap":
        if len(message) < 2:
            return modify(message, "insert", rng=rng)
        position = min(position, len(message) - 2)
        if message[position] == message[position + 1]:
            return modify(message, "replace", position, rng=rng)
        swapped = message[:position] + message[position + 1] + message[position] + message[position + 2:]
        return swapped, f"перестановка символов {message[position]!r} и {message[position + 1]!r} (позиции {position}, {position + 1})"
    raise ValueError(f"неизвестный вид модификации: {kind}")


def make_keys(p=None, q=None, d=None):
    """Ключи RSA средствами ЛР2 с диапазоном простых под 32-битный хэш."""
    if p is None:
        p = rsa.gen_prime(P_MIN, P_MAX)
        q = rsa.gen_prime(P_MIN, P_MAX)
        while q == p:
            q = rsa.gen_prime(P_MIN, P_MAX)
    errors = rsa.key_errors(p, q, d)
    if p * q < N_MIN:
        errors.append(f"n = p·q = {p * q} < 2^32: 32-битный хэш не поместится в блок")
    if errors:
        raise ValueError("; ".join(errors))
    (e, n), (d, n), phi = rsa.make_keys(p, q, d)
    return p, q, phi, (e, n), (d, n)


def self_test(variant, count=1000, seed=2026, verbose=True):
    """count случайных сообщений: нетронутые должны проходить проверку, изменённые — нет."""
    rng = random.Random(seed)
    saved = random.getstate()
    random.seed(seed)                        # gen_prime и make_keys из ЛР2 используют глобальный random
    p, q, phi, (e, n), (d, _) = make_keys()
    random.setstate(saved)
    ok_intact = ok_detected = 0
    for _ in range(count):
        message = "".join(rng.choice(ASCII_PRINTABLE) for _ in range(rng.randint(0, 50)))
        h, s = sign(message, d, n, variant)
        ok_intact += verify(message, s, e, n, variant)[2]
        changed, _ = modify(message, rng.choice(["replace", "insert", "delete", "swap"]), rng=rng)
        ok_detected += not verify(changed, s, e, n, variant)[2]
    if verbose:
        print(f"  Ключи: p = {p}, q = {q}, n = {n} (> 2^32: {'да' if n > N_MIN else 'нет'}), e = {e}, d = {d}")
        print(f"  Сообщений: {count} (длина 0..50, все печатные ASCII)")
        print(f"  Нетронутые прошли проверку: {ok_intact}/{count}")
        print(f"  Изменённые отклонены:      {ok_detected}/{count}")
    return ok_intact == count and ok_detected == count


# --- Меню ----------------------------------------------------------------------------------
class State:
    keys = None          # (p, q, phi, (e, n), (d, n))
    message = None
    signature = None     # S для message
    modified = None      # изменённое сообщение (проверяется с тем же S)


def show_keys(st):
    p, q, phi, (e, n), (d, _) = st.keys
    print(f"  p = {p}, q = {q}, n = p·q = {n} ({'>' if n > N_MIN else '<'} 2^32 = {N_MIN}), φ = {phi}")
    print(f"  Открытый ключ {{e, n}} = {{{e}, {n}}}, закрытый {{d, n}} = {{{d}, {n}}}")


def mode_keys(st):
    choice = input("  Ключи: 1 — случайные (p, q из [2^17, 2^18)), 2 — ввести p, q, d вручную: ").strip()
    if choice == "2":
        p = rsa.read_int("  p (простое): ", lambda v: None if rsa.is_prime(v) else f"p = {v} не простое")
        q = rsa.read_int("  q (простое, q ≠ p, p·q > 2^32): ",
                         lambda v: (None if rsa.is_prime(v) and v != p and p * v > N_MIN else
                                    f"q = {v}: нужно простое, отличное от p, с p·q > 2^32 (иначе хэш ≥ n)"))
        phi = (p - 1) * (q - 1)
        d = rsa.read_int("  d (1 < d < φ, НОД(d, φ) = 1; Enter — случайное): ",
                         lambda v: None if 1 < v < phi and rsa.gcd(v, phi) == 1 else "d должно лежать в (1, φ) и быть взаимно простым с φ",
                         allow_empty=True)
        st.keys = make_keys(p, q, d)
    else:
        st.keys = make_keys()
    st.signature = st.modified = None
    show_keys(st)


def mode_message(st):
    choice = input("  Сообщение: 1 — ввести с клавиатуры, 2 — случайное из печатных ASCII: ").strip()
    if choice == "2":
        length = rsa.read_int("  Длина (1..200): ", lambda v: None if 1 <= v <= 200 else "нужна длина от 1 до 200")
        st.message = "".join(random.choice(ASCII_PRINTABLE) for _ in range(length))
    else:
        st.message = rsa.read_text("  Текст (ASCII, Enter — пустое): ")
    st.signature = st.modified = None
    print(f"  M = {st.message!r} ({len(st.message)} символов)")


def need(st, keys=True, message=False, signature=False):
    if keys and st.keys is None:
        print("  Сначала задайте ключи (пункт 1)."); return False
    if message and st.message is None:
        print("  Сначала введите сообщение (пункт 2)."); return False
    if signature and st.signature is None:
        print("  Сначала подпишите сообщение (пункт 3)."); return False
    return True


def mode_sign(st, variant):
    if not need(st, message=True):
        return
    _, _, _, (e, n), (d, _) = st.keys
    h, s = sign(st.message, d, n, variant)
    st.signature, st.modified = s, None
    print(f"  h = H(M) = {myhash.to_hex(h)} = {h} (h < n: {'да' if h < n else 'нет'})")
    print(f"  S = h^d mod n = {s}")
    print(f"  Передаётся пара (M, S): ({st.message!r}, {s})")


def mode_verify(st, variant):
    if not need(st):
        return
    _, _, _, (e, n), _ = st.keys
    if st.signature is not None:
        raw = input("  Проверить: Enter — текущую пару (M, S), m — изменённое сообщение с той же S, i — ввести M и S: ").strip().lower()
    else:
        raw = "i"
    if raw == "m":
        if st.modified is None:
            print("  Изменённого сообщения нет — сначала пункт 5."); return
        message, s = st.modified, st.signature
    elif raw == "i":
        message = rsa.read_text("  M (ASCII): ")
        s = rsa.read_int("  S: ", lambda v: None if 0 <= v < n else f"S должно лежать в [0, n−1] = [0, {n - 1}]")
    else:
        message, s = st.message, st.signature
    h1, h2, ok = verify(message, s, e, n, variant)
    print(f"  h'  = H(M)        = {myhash.to_hex(h1)}")
    if h2 >= 2 ** 32:
        print(f"  h'' = S^e mod n   = {h2} — не помещается в 32 бита: S не является подписью под этим ключом")
    else:
        print(f"  h'' = S^e mod n   = {myhash.to_hex(h2)}")
    if ok:
        print("  Подпись верна: хэш-суммы совпадают, сообщение подлинно и не изменено.")
    elif h2 < 2 ** 32:
        print(f"  ПОДПИСЬ НЕВЕРНА: хэш-суммы не совпадают (различаются {myhash.hamming(h1, h2)} бит из 32) — "
              "сообщение изменено или подписано другим ключом.")
    else:
        print("  ПОДПИСЬ НЕВЕРНА: хэш-суммы не совпадают — подпись чужая или искажена.")


def mode_modify(st, variant):
    if not need(st, message=True, signature=True):
        return
    kinds = {"1": "replace", "2": "insert", "3": "delete", "4": "swap"}
    choice = input("  Модификация: 1 — заменить символ, 2 — вставить, 3 — удалить, 4 — переставить соседние, Enter — случайная: ").strip()
    kind = kinds.get(choice) or random.choice(list(kinds.values()))
    position = char = None
    if choice in kinds and st.message:
        last = len(st.message) if kind == "insert" else len(st.message) - 1
        position = rsa.read_int(f"  Позиция (0..{last}, Enter — случайная): ",
                                lambda v: None if 0 <= v <= last else "позиция вне сообщения", allow_empty=True)
        if kind in ("replace", "insert"):
            typed = rsa.read_text("  Символ ASCII (Enter — случайный): ")
            char = typed[:1] or None
    st.modified, description = modify(st.message, kind, position, char)
    print(f"  Было:  {st.message!r}")
    print(f"  Стало: {st.modified!r}  — {description}; подпись S = {st.signature} не менялась")
    _, _, _, (e, n), _ = st.keys
    h1, h2, ok = verify(st.modified, st.signature, e, n, variant)
    print(f"  Проверка изменённого сообщения: h' = {myhash.to_hex(h1)}, h'' = {myhash.to_hex(h2)} → "
          f"{'подпись верна (?!)' if ok else f'НЕ СОВПАДАЮТ ({myhash.hamming(h1, h2)} бит из 32) — целостность нарушена'}")


def mode_demo_small_n(variant):
    """Почему нужен n > 2^32: ключи примера методички ЛР2 (n = 33) не проверяют даже нетронутое сообщение."""
    p, q, d = EXAMPLE_KEYS
    (e, n), (d, _), _ = rsa.make_keys(p, q, d, check=False)
    message = "Hello"
    h = myhash.my_hash(message, variant=variant)
    s = rsa.modpow(h, d, n)
    h2 = rsa.modpow(s, e, n)
    print(f"  Ключи примера ЛР2: p = {p}, q = {q}, n = {n}, e = {e}, d = {d}; сообщение {message!r}")
    print(f"  h = {h} (32 бита) ≥ n = {n}; S = h^d mod n = {s}; S^e mod n = {h2} = h mod n = {h % n}")
    print(f"  Проверка нетронутого сообщения: {'сошлась' if h2 == h else 'НЕ сошлась'} — при h ≥ n восстанавливается лишь h mod n.")
    print(f"  Поэтому p, q берутся из [2^17, 2^18): n ≥ 2^34 > 2^32 ≥ h.")


def main():
    variant = sys.argv[1].lower() if len(sys.argv) > 1 else "sin"
    variant = {"1": "sin", "2": "cos", "3": "xor"}.get(variant, variant)
    if variant not in myhash.VARIANTS:
        print(f"Неизвестный вариант хэш-функции «{sys.argv[1]}»: допустимы sin, cos, xor.")
        return
    st = State()
    menu = (f"\nЛабораторная работа №4. ЭЦП на RSA (ЛР2) и хэш-функции {variant}(m) (ЛР3)\n"
            "  1 — ключи RSA (случайные или вручную)\n"
            "  2 — сообщение (с клавиатуры или случайное)\n"
            "  3 — подписать сообщение\n"
            "  4 — проверить подпись\n"
            "  5 — изменить подписанное сообщение и проверить\n"
            "  6 — автотест на 1000 сообщений\n"
            "  7 — демонстрация условия h < n (ключи n = 33 из примера ЛР2)\n"
            "  0 — выход")
    actions = {"1": lambda: mode_keys(st), "2": lambda: mode_message(st), "3": lambda: mode_sign(st, variant),
               "4": lambda: mode_verify(st, variant), "5": lambda: mode_modify(st, variant),
               "6": lambda: self_test(variant), "7": lambda: mode_demo_small_n(variant)}
    try:
        while True:
            print(menu)
            choice = input("Выбор: ").strip()
            if choice == "0":
                break
            if choice in actions:
                try:
                    actions[choice]()
                except ValueError as err:
                    print(f"  Ошибка: {err}.")
            else:
                print("  Нет такого пункта меню.")
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")


if __name__ == "__main__":
    main()
