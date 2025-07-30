# SPDX-FileCopyrightText: 2025-present cyanic
#
# SPDX-License-Identifier: GPL-3.0-or-later
from enum import Enum, auto


class TCPState(Enum):
    """Represents communicator state."""
    IDLE = auto()
    """Communicator is idle."""
    INITIATING = auto()
    """Communicator is initiating a packet send."""
    LISTENING = auto()
    """Communicator is waiting to receive a packet."""
    SENDING = auto()
    """Communicator is sending packet data."""
    RECEIVING = auto()
    """Communicator is receiving packet data."""
    ECHO = auto()
    """Communicator is in echo check mode."""


class TCPEchoResult(Enum):
    """Represents the result of an echo check."""
    REQUESTING = auto()
    """Echo check in progress."""
    RESPONDED = auto()
    """Echo check succeeded."""
    TIMEOUT = auto()
    """Echo check timed out."""


class TCPResult(Enum):
    """Represents the operation result."""
    NONE = auto()
    """No operation has occurred."""
    SUCCESS = auto()
    """Operation was successful."""
    FAILURE = auto()
    """Operation failed, too many retries from failed transfers or timeouts."""
    CANCELLED = auto()
    """Operation was cancelled by either peer."""


class TCPCallbackType(Enum):
    """Represents event that triggered the callback."""
    CHUNK_RECEIVED = auto()
    """Data chunk was received."""
    CHUNK_PREPARE_TO_SEND = auto()
    """Data chunk will be sent and needs to be prepared."""
    CUSTOM_CMD = auto()
    """A custom or otherwise unparseable command was received."""
    SUCCESS = auto()
    """The operation has succeeded."""
    FAILURE = auto()
    """The operation has failed."""
