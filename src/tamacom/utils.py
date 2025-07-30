# SPDX-FileCopyrightText: 2025-present cyanic
#
# SPDX-License-Identifier: GPL-3.0-or-later
from hashlib import sha256
from itertools import cycle


def crypt(secret: bytes, nonce: bytes, data: bytes) -> bytes:
    if secret is None:
        raise TypeError('secret is None.')
    if nonce is None:
        raise TypeError('nonce is None.')
    if data is None:
        raise TypeError('data is None.')

    keystream = bytearray(sha256(nonce + secret).digest())
    result = bytearray(data)
    for i in range(len(result)):
        key_index = i % len(keystream)
        result[i] ^= keystream[key_index]
        keystream[key_index] = (keystream[key_index] * 2 + 1) & 0xff

    return bytes(result)
