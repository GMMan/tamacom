# SPDX-FileCopyrightText: 2025-present cyanic
#
# SPDX-License-Identifier: GPL-3.0-or-later
from enum import Enum, auto


class TCPState(Enum):
    IDLE = auto()
    INITIATING = auto()
    LISTENING = auto()
    SENDING = auto()
    RECEIVING = auto()
    ECHO = auto()


class TCPEchoResult(Enum):
    REQUESTING = auto()
    RESPONDED = auto()
    TIMEOUT = auto()


class TCPResult(Enum):
    NONE = auto()
    SUCCESS = auto()
    FAILURE = auto()
    CANCELLED = auto()


class TCPCallbackType(Enum):
    CHUNK_RECEIVED = auto()
    CHUNK_PREPARE_TO_SEND = auto()
    CUSTOM_CMD = auto()
    SUCCESS = auto()
    FAILURE = auto()
