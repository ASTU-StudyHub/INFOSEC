#!/usr/bin/env python3
"""Лабораторная работа №4. Реализация электронной цифровой подписи.

Подпись строится из программ предыдущих работ: RSA (lab2/rsa.py) и собственной
хэш-функции (lab3/myhash.py). Схема из методических указаний:
    формирование: h = H(M);  S = h^d mod n;  передаётся пара (M, S)
    проверка:     h' = H(M);  h'' = S^e mod n;  подпись верна, если h' = h''
Закрытый ключ {d, n} есть только у автора (аутентичность, неотказуемость),
открытый {e, n} — у всех (проверяемость). Любое изменение M меняет h' — подпись
не сходится (целостность).

Условие корректности, которое нужно учесть при выборе ключей: h < n, иначе
S^e mod n = h mod n ≠ h и подпись не сходится даже на нетронутом сообщении.
Хэш 32-битный, поэтому простые p, q берутся из [2^17, 2^18): n = p·q ≥ 2^34 > 2^32.

Режимы: ключи (случайно / вручную), ввод сообщения, подпись, проверка пары (M, S),
модификация сообщения с последующей проверкой, автотест, демонстрация условия h < n.

Только стандартная библиотека. Запуск: python3 signature.py [sin|cos|xor]
(модули подключаются из соседних папок lab2 и lab3).
"""

import os
import random
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "..", "lab2"))     # rsa.py — лабораторная №2
sys.path.insert(0, os.path.join(BASE, "..", "lab3"))     # myhash.py — лабораторная №3
# rsa: modpow, gen_prime, prime_error, key_errors, make_keys, read_int, read_text, EXAMPLE
# myhash: my_hash, to_hex, hamming, VARIANTS
import rsa      # noqa: E402
import myhash   # noqa: E402

P_MIN, P_MAX = 2 ** 17, 2 ** 18 - 1     # простые для n > 2^32 (хэш 32-битный)
N_MIN = 2 ** 32                          # h < 2^32 ≤ n — условие корректности проверки
# ключи примера ЛР2 (n = 33) — демонстрация случая h ≥ n
EXAMPLE_KEYS = (rsa.EXAMPLE["p"], rsa.EXAMPLE["q"], rsa.EXAMPLE["d"])
ASCII_PRINTABLE = [chr(c) for c in range(32, 127)]


# --- Подпись и проверка --------------------------------------------------------------
def sign(message, d, n, variant):
    """Формирование ЭЦП: h = H(M), S = h^d mod n. Возвращает (h, S)."""
    h = myhash.my_hash(message, variant=variant)
    if h >= n:
        raise ValueError(f"хэш h = {h} ≥ n = {n}: подпись не проверится, "
                         "нужен модуль n = p·q > 2^32")
    return h, rsa.modpow(h, d, n)


def verify(message, signature, e, n, variant):
    """Проверка ЭЦП: h' = H(M), h'' = S^e mod n. Возвращает (h', h'', совпали ли)."""
    h1 = myhash.my_hash(message, variant=variant)
    h2 = rsa.modpow(signature, e, n)
    return h1, h2, h1 == h2


def swap_positions(message):
    """Позиции i, где M[i] ≠ M[i+1]: только там перестановка соседних меняет сообщение."""
    return [i for i in range(len(message) - 1) if message[i] != message[i + 1]]


def modify(message, kind, position=None, char=None, rng=random):
    """Нарушение целостности: replace / insert / delete / swap. Возвращает (M', описание).
    Подпись при этом НЕ пересчитывается — это и есть модель злоумышленника в канале.
    Вид, невозможный для данного сообщения (удаление из пустого, перестановка без
    соседних различных символов), заменяется вставкой; описание называет то, что
    сделано. Меню такие виды не принимает."""
    pairs = swap_positions(message)
    if kind in ("replace", "delete") and not message or kind == "swap" and not pairs:
        kind = "insert"
    if position is None:
        if kind == "swap":
            position = rng.choice(pairs)         # только пары различных символов
        else:
            position = rng.randrange(len(message) + 1 if kind == "insert" else len(message))
    if kind == "replace":
        old = message[position]
        if char is None or char == old:
            char = rng.choice([c for c in ASCII_PRINTABLE if c != old])
        return (message[:position] + char + message[position + 1:],
                f"замена символа {old!r} на {char!r} в позиции {position}")
    if kind == "insert":
        if char is None:
            char = rng.choice(ASCII_PRINTABLE)
        position = min(position, len(message))
        return (message[:position] + char + message[position:],
                f"вставка символа {char!r} в позицию {position}")
    if kind == "delete":
        return (message[:position] + message[position + 1:],
                f"удаление символа {message[position]!r} из позиции {position}")
    if kind == "swap":
        if position not in pairs:        # перестановка одинаковых символов ничего не меняет
            raise ValueError(f"в позиции {position} нет пары различных соседних символов")
        a, b = message[position], message[position + 1]
        return (message[:position] + b + a + message[position + 2:],
                f"перестановка символов {a!r} и {b!r} (позиции {position}, {position + 1})")
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
    random.seed(seed)                # gen_prime и make_keys из ЛР2 используют глобальный random
    p, q, phi, (e, n), (d, _) = make_keys()
    random.setstate(saved)
    ok_intact = ok_detected = 0
    for _ in range(count):
        message = "".join(rng.choice(ASCII_PRINTABLE) for _ in range(rng.randint(0, 50)))
        h, s = sign(message, d, n, variant)
        ok_intact += verify(message, s, e, n, variant)[2]
        kind = rng.choice(["replace", "insert", "delete", "swap"])
        changed, _ = modify(message, kind, rng=rng)
        ok_detected += not verify(changed, s, e, n, variant)[2]
    if verbose:
        print(f"  Ключи: p = {p}, q = {q}, n = {n} (> 2^32: {'да' if n > N_MIN else 'нет'}), "
              f"e = {e}, d = {d}")
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


def symbols(count):
    """Число символов с согласованным словом: 1 символ, 2 символа, 5 символов."""
    if count % 10 == 1 and count % 100 != 11:
        return f"{count} символ"
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return f"{count} символа"
    return f"{count} символов"


def ask_choice(prompt, options):
    """Вопрос подменю: повторяется, пока ответ не совпадёт с одним из вариантов."""
    while True:
        answer = input(prompt).strip().lower()
        if answer in options:
            return answer
        print("  Нет такого варианта, повторите ввод.")


def read_char(prompt, old=None):
    """Один символ ASCII или None (Enter — случайный). old — заменяемый символ."""
    while True:
        typed = rsa.read_text(prompt)
        if len(typed) > 1:
            print("  Нужен один символ, повторите ввод.")
        elif typed and typed == old:
            print("  Символ совпадает с заменяемым, повторите ввод.")
        else:
            return typed or None


def show_keys(st):
    p, q, phi, (e, n), (d, _) = st.keys
    print(f"  p = {p}, q = {q}, n = p·q = {n} ({'>' if n > N_MIN else '<'} 2^32 = {N_MIN}), "
          f"φ = {phi}")
    print(f"  Открытый ключ {{e, n}} = {{{e}, {n}}}, закрытый {{d, n}} = {{{d}, {n}}}")


def mode_keys(st):
    choice = ask_choice("  Ключи: 1 — случайные (p, q из [2^17, 2^18)), "
                        "2 — ввести p, q, d вручную: ", ("1", "2"))
    if choice == "1":
        st.keys = make_keys()
    else:
        # простота и предел 10^12 — проверка ЛР2 (prime_error): пробное деление
        # большого числа длилось бы минуты без вывода
        p = rsa.read_int("  p (простое, p ≤ 10^12): ", lambda v: rsa.prime_error("p", v))

        def check_q(v):
            error = rsa.prime_error("q", v)
            if error:
                return error
            if v == p:
                return "q должно отличаться от p: при p = q формула φ = (p−1)(q−1) неверна"
            if p * v <= N_MIN:
                return f"p·q = {p * v} ≤ 2^32: 32-битный хэш может оказаться ≥ n"
            return None

        q = rsa.read_int("  q (простое, q ≠ p, p·q > 2^32, q ≤ 10^12): ", check_q)
        print(f"  n = {p * q}, φ = {(p - 1) * (q - 1)}")

        def check_d(v):
            errors = rsa.key_errors(p, q, v)     # диапазон (1, φ) и НОД(d, φ) = 1 — ЛР2
            return errors[0] if errors else None

        d = rsa.read_int("  d (1 < d < φ, НОД(d, φ) = 1; Enter — случайное): ", check_d,
                         allow_empty=True)
        st.keys = make_keys(p, q, d)
    st.signature = st.modified = None
    show_keys(st)


def mode_message(st):
    choice = ask_choice("  Сообщение: 1 — ввести с клавиатуры, "
                        "2 — случайное из печатных ASCII: ", ("1", "2"))
    if choice == "2":
        length = rsa.read_int("  Длина (1..200): ",
                              lambda v: None if 1 <= v <= 200 else "нужна длина от 1 до 200")
        st.message = "".join(random.choice(ASCII_PRINTABLE) for _ in range(length))
    else:
        st.message = rsa.read_text("  Текст (ASCII, Enter — пустое): ")
    st.signature = st.modified = None
    print(f"  M = {st.message!r} ({symbols(len(st.message))})")


def need(st, keys=True, message=False, signature=False):
    """Выполнены ли нужные пункты меню; если нет — подсказка."""
    if keys and st.keys is None:
        print("  Сначала задайте ключи (пункт 1).")
        return False
    if message and st.message is None:
        print("  Сначала введите сообщение (пункт 2).")
        return False
    if signature and st.signature is None:
        print("  Сначала подпишите сообщение (пункт 3).")
        return False
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
        raw = ask_choice("  Проверить: Enter — текущую пару (M, S), m — изменённое сообщение "
                         "с той же S, i — ввести M и S: ", ("", "m", "i"))
    else:
        raw = "i"
    if raw == "m":
        if st.modified is None:
            print("  Изменённого сообщения нет — сначала пункт 5.")
            return
        message, s = st.modified, st.signature
    elif raw == "i":
        message = rsa.read_text("  M (ASCII): ")
        s = rsa.read_int("  S: ", lambda v: (None if 0 <= v < n else
                                             f"S должно лежать в [0, n−1] = [0, {n - 1}]"))
    else:
        message, s = st.message, st.signature
    h1, h2, ok = verify(message, s, e, n, variant)
    print(f"  h'  = H(M)        = {myhash.to_hex(h1)}")
    if h2 >= 2 ** 32:
        print(f"  h'' = S^e mod n   = {h2} — не помещается в 32 бита: "
              "S не является подписью под этим ключом")
    else:
        print(f"  h'' = S^e mod n   = {myhash.to_hex(h2)}")
    if ok:
        print("  Подпись верна: хэш-суммы совпадают, сообщение подлинно и не изменено.")
    elif h2 < 2 ** 32:
        print(f"  ПОДПИСЬ НЕВЕРНА: хэш-суммы не совпадают (различаются "
              f"{myhash.hamming(h1, h2)} бит из 32) — "
              "сообщение изменено или подписано другим ключом.")
    else:
        print("  ПОДПИСЬ НЕВЕРНА: хэш-суммы не совпадают — подпись чужая или искажена.")


def mode_modify(st, variant):
    if not need(st, message=True, signature=True):
        return
    kinds = {"1": "replace", "2": "insert", "3": "delete", "4": "swap"}
    shortest = {"replace": 1, "insert": 0, "delete": 1, "swap": 2}   # наименьшая длина M
    size = len(st.message)

    def impossible(k):
        """Почему вид k невозможен для текущего сообщения (None — возможен)."""
        if size < shortest[k]:
            return f"В сообщении {symbols(size)}: такая модификация невозможна"
        if k == "swap" and not swap_positions(st.message):
            return "В сообщении нет соседних различных символов: перестановка невозможна"
        return None

    while True:
        choice = ask_choice("  Модификация: 1 — заменить символ, 2 — вставить, 3 — удалить, "
                            "4 — переставить соседние, Enter — случайная: ",
                            ("1", "2", "3", "4", ""))
        reason = impossible(kinds[choice]) if choice else None
        if reason is None:
            break
        print(f"  {reason}, выберите другую.")
    if choice == "":
        kind = random.choice([k for k in kinds.values() if impossible(k) is None])
    else:
        kind = kinds[choice]
    position = char = None
    if choice and size:
        last = {"insert": size, "swap": size - 2}.get(kind, size - 1)

        def check_position(v):
            if not 0 <= v <= last:
                return f"позиция должна лежать в [0, {last}]"
            if kind == "swap" and st.message[v] == st.message[v + 1]:
                return (f"символы в позициях {v} и {v + 1} одинаковы, "
                        "перестановка ничего не изменит")
            return None

        position = rsa.read_int(f"  Позиция (0..{last}, Enter — случайная): ", check_position,
                                allow_empty=True)
    if choice and kind in ("replace", "insert"):
        old = st.message[position] if kind == "replace" and position is not None else None
        char = read_char("  Символ ASCII (Enter — случайный): ", old)
    st.modified, description = modify(st.message, kind, position, char)
    print(f"  Было:  {st.message!r}")
    print(f"  Стало: {st.modified!r}  — {description}; подпись S = {st.signature} не менялась")
    _, _, _, (e, n), _ = st.keys
    h1, h2, ok = verify(st.modified, st.signature, e, n, variant)
    if ok:
        verdict = "хэш-суммы совпали — коллизия хэш-функции"
    else:
        verdict = f"НЕ СОВПАДАЮТ ({myhash.hamming(h1, h2)} бит из 32) — целостность нарушена"
    print(f"  Проверка изменённого сообщения: h' = {myhash.to_hex(h1)}, "
          f"h'' = {myhash.to_hex(h2)} → {verdict}")


def mode_demo_small_n(variant):
    """Почему нужен n > 2^32: ключи примера из методических указаний к ЛР2 (n = 33)
    не проверяют даже нетронутое сообщение."""
    p, q, d = EXAMPLE_KEYS
    (e, n), (d, _), _ = rsa.make_keys(p, q, d, check=False)
    message = "Hello"
    h = myhash.my_hash(message, variant=variant)
    s = rsa.modpow(h, d, n)
    h2 = rsa.modpow(s, e, n)
    result = "сошлась" if h2 == h else "НЕ сошлась"
    print(f"  Ключи примера ЛР2: p = {p}, q = {q}, n = {n}, e = {e}, d = {d}; "
          f"сообщение {message!r}")
    print(f"  h = {h} (32 бита) ≥ n = {n}; S = h^d mod n = {s}; "
          f"S^e mod n = {h2} = h mod n = {h % n}")
    print(f"  Проверка нетронутого сообщения: {result} — "
          "при h ≥ n восстанавливается лишь h mod n.")
    print("  Поэтому p, q берутся из [2^17, 2^18): n ≥ 2^34 > 2^32 ≥ h.")


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
    actions = {"1": lambda: mode_keys(st), "2": lambda: mode_message(st),
               "3": lambda: mode_sign(st, variant), "4": lambda: mode_verify(st, variant),
               "5": lambda: mode_modify(st, variant), "6": lambda: self_test(variant),
               "7": lambda: mode_demo_small_n(variant)}
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
