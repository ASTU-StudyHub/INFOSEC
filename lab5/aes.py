#!/usr/bin/env python3
"""Лабораторная работа №5. Симметричный шифр AES (FIPS-197), режим CBC, дополнение PKCS#7.

Собственная реализация на стандартной библиотеке: S-блок вычисляется из арифметики поля
GF(2^8), поддерживаются ключи 128, 192 и 256 бит. Байты блока хранятся в порядке FIPS-197:
элемент состояния s[r][c] лежит в позиции r + 4c. Правильность проверяется на тестовых
векторах приложения C FIPS-197: python3 aes.py
"""

import os
import sys

BLOCK = 16          # размер блока в байтах


# --- Арифметика GF(2^8) и таблицы -----------------------------------------------------
def _xtime(a):
    """Умножение на x в GF(2^8) с многочленом x^8 + x^4 + x^3 + x + 1."""
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    """Произведение элементов GF(2^8)."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _make_sbox():
    """S-блок: обратный элемент в GF(2^8), затем аффинное преобразование (FIPS-197, 5.1.1)."""
    inverse = [0] * 256
    for a in range(1, 256):
        if inverse[a]:
            continue
        for b in range(1, 256):
            if gmul(a, b) == 1:
                inverse[a], inverse[b] = b, a
                break
    sbox = []
    for x in range(256):
        a = inverse[x]
        s = a
        for i in range(1, 5):
            s ^= ((a << i) | (a >> (8 - i))) & 0xFF      # циклические сдвиги на 1..4
        sbox.append(s ^ 0x63)
    return sbox


SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _s in enumerate(SBOX):
    INV_SBOX[_s] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
MUL = {c: [gmul(x, c) for x in range(256)] for c in (2, 3, 9, 11, 13, 14)}   # таблицы для MixColumns


# --- Раунд ----------------------------------------------------------------------------
def expand_key(key):
    """Расширение ключа (FIPS-197, 5.2). Возвращает список раундовых ключей по 16 байт."""
    nk = len(key) // 4
    if len(key) % 4 or nk not in (4, 6, 8):
        raise ValueError("ключ AES должен быть длиной 16, 24 или 32 байта")
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(words[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]            # RotWord + SubWord
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        words.append([words[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _add_round_key(state, key):
    return [a ^ b for a, b in zip(state, key)]


def _sub_bytes(state, box):
    return [box[b] for b in state]


def _shift_rows(state):
    """Строка r сдвигается влево на r позиций: s'[r][c] = s[r][(c + r) mod 4]."""
    return [state[(i + 4 * (i % 4)) % 16] for i in range(16)]


def _inv_shift_rows(state):
    return [state[(i - 4 * (i % 4)) % 16] for i in range(16)]


def _mix_columns(state, inverse=False):
    """Умножение каждого столбца на фиксированный многочлен над GF(2^8) (FIPS-197, 5.1.3 / 5.3.3)."""
    m2, m3, m9, m11, m13, m14 = (MUL[c] for c in (2, 3, 9, 11, 13, 14))
    out = []
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        if not inverse:
            out += [m2[a0] ^ m3[a1] ^ a2 ^ a3,
                    a0 ^ m2[a1] ^ m3[a2] ^ a3,
                    a0 ^ a1 ^ m2[a2] ^ m3[a3],
                    m3[a0] ^ a1 ^ a2 ^ m2[a3]]
        else:
            out += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3],
                    m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                    m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3],
                    m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
    return out


# --- Блок -----------------------------------------------------------------------------
def encrypt_block(round_keys, block):
    """Шифрование одного 16-байтового блока (FIPS-197, 5.1)."""
    state = _add_round_key(list(block), round_keys[0])
    for key in round_keys[1:-1]:
        state = _add_round_key(_mix_columns(_shift_rows(_sub_bytes(state, SBOX))), key)
    state = _add_round_key(_shift_rows(_sub_bytes(state, SBOX)), round_keys[-1])
    return bytes(state)


def decrypt_block(round_keys, block):
    """Расшифрование одного блока обратным шифром (FIPS-197, 5.3)."""
    state = _add_round_key(list(block), round_keys[-1])
    for key in reversed(round_keys[1:-1]):
        state = _mix_columns(_add_round_key(_sub_bytes(_inv_shift_rows(state), INV_SBOX), key), inverse=True)
    state = _add_round_key(_sub_bytes(_inv_shift_rows(state), INV_SBOX), round_keys[0])
    return bytes(state)


# --- Режим CBC с дополнением PKCS#7 ------------------------------------------------------
def pad(data):
    n = BLOCK - len(data) % BLOCK
    return bytes(data) + bytes([n]) * n


def unpad(data):
    if not data or len(data) % BLOCK:
        raise ValueError("длина данных не кратна размеру блока")
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("неверное дополнение PKCS#7")
    return data[:-n]


def encrypt_cbc(key, iv, data):
    """C_i = E(P_i xor C_{i-1}), C_0 = iv. Возвращает шифртекст (длина кратна 16)."""
    if len(iv) != BLOCK:
        raise ValueError("вектор инициализации должен быть 16 байт")
    round_keys = expand_key(key)
    prev, out = bytes(iv), []
    padded = pad(data)
    for i in range(0, len(padded), BLOCK):
        block = bytes(a ^ b for a, b in zip(padded[i:i + BLOCK], prev))
        prev = encrypt_block(round_keys, block)
        out.append(prev)
    return b"".join(out)


def decrypt_cbc(key, iv, data):
    """P_i = D(C_i) xor C_{i-1}. Снимает дополнение; ValueError при повреждённых данных."""
    if len(iv) != BLOCK:
        raise ValueError("вектор инициализации должен быть 16 байт")
    if not data or len(data) % BLOCK:
        raise ValueError("длина шифртекста не кратна размеру блока")
    round_keys = expand_key(key)
    prev, out = bytes(iv), []
    for i in range(0, len(data), BLOCK):
        block = data[i:i + BLOCK]
        out.append(bytes(a ^ b for a, b in zip(decrypt_block(round_keys, block), prev)))
        prev = block
    return unpad(b"".join(out))


# --- Самопроверка -----------------------------------------------------------------------
FIPS_VECTORS = [   # FIPS-197, приложение C: (ключ, открытый текст, шифртекст)
    ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
]


def self_test(verbose=True):
    """Тестовые векторы FIPS-197 (AES-128/192/256) и обратимость CBC на случайных данных."""
    ok = True
    assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0x53] == 0xED
    for key, plain, cipher in FIPS_VECTORS:
        rk = expand_key(bytes.fromhex(key))
        got = encrypt_block(rk, bytes.fromhex(plain)).hex()
        back = decrypt_block(rk, bytes.fromhex(cipher)).hex()
        good = got == cipher and back == plain
        ok &= good
        if verbose:
            print(f"AES-{len(key) * 4}: E(текст) = {got}  {'совпал' if good else 'НЕ СОВПАЛ'} с FIPS-197; D(шифртекст) = {back}")
    for length in (0, 1, 15, 16, 17, 100, 1000):
        key, iv, data = os.urandom(32), os.urandom(16), os.urandom(length)
        ct = encrypt_cbc(key, iv, data)
        good = decrypt_cbc(key, iv, ct) == data and len(ct) == (length // BLOCK + 1) * BLOCK
        ok &= good
        if verbose:
            print(f"CBC, {length:4d} байт: шифртекст {len(ct):4d} байт, расшифрование {'верно' if good else 'НЕВЕРНО'}")
    if verbose:
        print("Итог:", "все проверки пройдены" if ok else "ЕСТЬ ОШИБКИ")
    return ok


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    sys.exit(0 if self_test() else 1)
