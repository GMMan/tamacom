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
    
    keystream = sha256(nonce + secret).digest()
    return bytes(i ^ j for i, j in (zip(data, cycle(keystream)) if len(data) > len(keystream) else zip(cycle(data), keystream)))
