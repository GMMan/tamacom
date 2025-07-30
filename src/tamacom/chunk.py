# SPDX-FileCopyrightText: 2025-present cyanic
#
# SPDX-License-Identifier: GPL-3.0-or-later
from typing import Any, Final, Union
import struct
import crc
from . import comm


HEADER_FORMAT: Final[str] = '<I3sBBBH'
HEADER_MAGIC: Final[bytes] = b'TCP'
HEADER_LENGTH: Final[int] = struct.calcsize(HEADER_FORMAT)


crc_calculator = crc.Calculator(crc.Crc16.IBM)  # type: ignore


def parse_chunk(chunk: bytes) -> dict[str, Any]:
    (session_id, magic, msg_type, chunk_index, chunk_index_comp, crc) = \
        struct.unpack(HEADER_FORMAT, chunk[:HEADER_LENGTH])

    if magic != HEADER_MAGIC:
        raise ValueError('Chunk has invalid magic string.')
    if chunk_index + chunk_index_comp != 0xff:
        raise ValueError('Invalid chunk index and complement.')

    payload = chunk[HEADER_LENGTH:]
    if not crc_calculator.verify(payload, crc):
        raise ValueError('Payload CRC check failed.')

    return {
        'session_id': session_id,
        'msg_type': msg_type,
        'chunk_index': chunk_index,
        'payload': payload,
    }


def create_chunk(session_id: Union[int, None], msg_type: int, chunk_index: int, payload: bytes) -> bytes:
    if session_id is None:
        session_id = 0
    if session_id < 0 or session_id > 0xffffffff:
        raise ValueError('Session ID is not an unsigned 32-bit integer.')
    if msg_type < 0 or msg_type > 0xff:
        raise ValueError('Message type is not an unsigned 8-bit integer.')
    if chunk_index < 0 or chunk_index > 0xff:
        raise ValueError('Chunk index is not an unsigned 8-bit integer.')
    if payload is None:
        raise TypeError('Payload cannot be None.')
    if len(payload) > comm.CHUNK_MAX_LENGTH:
        raise ValueError('Chunk is too large.')

    crc = crc_calculator.checksum(payload)
    return struct.pack(HEADER_FORMAT, session_id, HEADER_MAGIC, msg_type, chunk_index,
                        0xff - chunk_index, crc) + payload
