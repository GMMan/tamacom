# SPDX-FileCopyrightText: 2025-present cyanic
#
# SPDX-License-Identifier: GPL-3.0-or-later
from random import randbytes
from typing import Any, Final, List, Optional, Protocol, Tuple, Union
from serial import Serial
import struct
import time
from .enums import TCPState, TCPEchoResult, TCPResult, TCPCallbackType
from .chunk import HEADER_LENGTH, parse_chunk, create_chunk
from .utils import crypt


CHUNK_MAX_LENGTH: Final[int] = 0x1000
NONCE_LENGTH: Final[int] = 4
MAX_PAYLOAD_LENGTH: Final[int] = CHUNK_MAX_LENGTH * 256  # Chunk index can represent 256 values in chunk header

CMD_PKT: Final[bytes] = b'PKT'
CMD_ACK: Final[bytes] = b'ACK'
CMD_NAK: Final[bytes] = b'NAK'
CMD_ENQ: Final[bytes] = b'ENQ'
CMD_CAN: Final[bytes] = b'CAN'
CMD_ECHO: Final[bytes] = b'ECHO'
PARAM_ECHO_REQ: Final[bytes] =b'REQ'
PARAM_ECHO_REP: Final[bytes] = b'REP'
NEWLINE: Final[bytes] = b'\r\n'


class TCPCallback(Protocol):
    def __call__(self, sender: 'TCPComm', cb_type: TCPCallbackType, **kwargs: Any) -> bool:
        ...


class TCPComm:
    def __init__(self, port: str, secret: bytes, cmd_timeout: float=2, data_timeout: float=5, echo_timeout: float=3, retries: int=3, read_timeout: float=0.1):
        if port is None:
            raise TypeError('port is None.')
        if secret is None:
            raise TypeError('secret is None.')

        self._serport = Serial(port, baudrate=460800, timeout=cmd_timeout)
        self._secret = secret
        self._state = TCPState.IDLE
        self._result = TCPResult.NONE
        self._cmd_queue: List[bytes] = []
        self._msg_type = 0
        self._echo_reply_time = 0
        self._echo_response_only = False

        self.cmd_timeout = cmd_timeout
        self.data_timeout = data_timeout
        self.echo_timeout = echo_timeout
        self.read_timeout = read_timeout
        self.retries = retries
        self.session_id: Union[int, None] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._serport.close()

    @property
    def result(self) -> TCPResult:
        return self._result

    @property
    def echo_reply_time(self) -> float:
        return self._echo_reply_time

    def send_packet(self, msg_type: int=0, data: Optional[bytes]=None, data_length: Optional[int]=None,
                    callback: Optional[TCPCallback]=None) -> TCPResult:
        if self._state != TCPState.IDLE:
            raise RuntimeError('Communicator is not idle.')
        if data is None and data_length is None:
            raise TypeError('Either data or data_length needs to be specified')
        if data is None and callback is not None:
            raise TypeError('Callback needs to be specified when data is None.')
        if data is not None and data_length is not None and data_length != len(data):
            raise ValueError('Data length and data_length do not match.')

        self._data = data
        if data is not None:
            self._data_length = len(data)
        elif data_length is not None:
            self._data_length = data_length

        if self._data_length > MAX_PAYLOAD_LENGTH:
            raise ValueError('Payload is too large.')

        self._msg_type = msg_type
        self._callback = callback
        self._current_chunk = 0
        self._total_chunks = (self._data_length + CHUNK_MAX_LENGTH - 1) // CHUNK_MAX_LENGTH
        self._cmd_queue.clear()
        self._echo_response_only = False
        self._result = TCPResult.NONE
        self._state = TCPState.INITIATING
        self._run_state_machine()
        return self._result

    def send_session_id(self, session_id: int) -> TCPResult:
        if self._state != TCPState.IDLE:
            raise RuntimeError('Communicator is not idle.')
        if session_id is None:
            raise TypeError('session_id is None.')
        if session_id < 0 or session_id > 0xffffffff:
            raise ValueError('Session ID is not an unsigned 32-bit integer.')

        result = self.send_packet(0x10, randbytes(2))
        if result == TCPResult.SUCCESS:
            self.session_id = session_id
        return result

    def receive_packet(self, msg_type: int=0, callback: Optional[TCPCallback]=None) -> Tuple[TCPResult, bytes]:
        if self._state != TCPState.IDLE:
            raise RuntimeError('Communicator is not idle.')

        self._msg_type = msg_type
        self._callback = callback
        self._data = bytearray()
        self._current_chunk = 0
        self._total_chunks = 0
        self._cmd_queue.clear()
        self._echo_response_only = False
        self._result = TCPResult.NONE
        self._state = TCPState.LISTENING
        self._run_state_machine()
        return (self._result, bytes(self._data))

    def echo_check(self, response_only: bool=False) -> TCPEchoResult:
        if self._state != TCPState.IDLE:
            raise RuntimeError('Communicator is not idle.')

        result = TCPEchoResult.REQUESTING
        self._cmd_queue.clear()
        self._echo_reply_time = 0
        self._echo_response_only = response_only
        self._state = TCPState.ECHO

        for _ in range(self.retries):
            if not self._echo_response_only:
                self.send_echo_req()
            start_time = time.time()

            while time.time() - start_time < self.echo_timeout:
                if self._read_serial():
                    self._handle_commands()
                else:
                    time.sleep(self.read_timeout)

                if self._echo_reply_time >= start_time:
                    result = TCPEchoResult.RESPONDED
                    break

            if result == TCPEchoResult.RESPONDED:
                break

        if result != TCPEchoResult.RESPONDED:
            result = TCPEchoResult.TIMEOUT

        self._state = TCPState.IDLE
        return result

    def set_chunk_to_send(self, data: bytes) -> None:
        if data is None:
            raise TypeError('data is None.')

        self._next_send_chunk = data

    def touch_last_activity_time(self) -> None:
        self._last_activity_time = time.time()

    def send_echo_req(self) -> None:
        self._send_command(b'%b %b' % (CMD_ECHO, PARAM_ECHO_REQ))

    def send_custom_command(self, command: str, *args: str) -> None:
        if command is None:
            raise TypeError('command is None.')

        cmd_str = ('%s %s' % (command, ' '.join(map(str, args)))).encode()
        if len(cmd_str) > 16:
            raise ValueError('Command is too long to fit in target device buffer.')

        self._send_command(cmd_str)

    def _send_nak(self) -> None:
        self._send_command(CMD_NAK)

    def _send_ack(self) -> None:
        self._send_command(CMD_ACK)

    def _send_cancel(self) -> None:
        self._send_command(CMD_CAN)
        self._state = TCPState.IDLE
        self._result = TCPResult.CANCELLED

    def _send_command(self, cmd: bytes) -> None:
        # print((b'< ' + cmd).decode())
        self._serport.write(cmd + NEWLINE)

    # Returns whether to retry
    def _handle_retry(self, send_cancel: bool) -> bool:
        self._attempts += 1
        if self._attempts >= self.retries:
            if send_cancel:
                self._send_command(CMD_CAN)

            if self._callback:
                if self._callback(self, TCPCallbackType.FAILURE, state=self._state):
                    self._result = TCPResult.FAILURE
                else:
                    self._result = TCPResult.CANCELLED
            else:
                self._result = TCPResult.FAILURE

            self._state = TCPState.IDLE
            return False
        else:
            self.touch_last_activity_time()
            return True

    def _handle_retry_with_nak(self) -> None:
        if self._handle_retry(True):
            self._send_nak()

    def _get_curr_chunk_length(self) -> int:
        if self._current_chunk == self._total_chunks - 1:
            return self._data_length - self._current_chunk * CHUNK_MAX_LENGTH
        elif self._current_chunk >= self._total_chunks:
            return 0
        else:
            return CHUNK_MAX_LENGTH

    def _read_serial(self) -> bool:
        if not self._serport.in_waiting:
            return False

        if self._state == TCPState.RECEIVING:
            self._handle_packet_receive()
        else:
            self._serport.timeout = self.read_timeout

            while self._serport.in_waiting:
                line = self._serport.readline()
                if len(line) == 0:
                    break

                self._cmd_queue.append(line.strip())

        return True

    def _handle_packet_receive(self) -> None:
        self._serport.timeout = self.data_timeout
        chunk_length = self._get_curr_chunk_length()
        read_length = NONCE_LENGTH + HEADER_LENGTH + chunk_length

        chunk = self._serport.read(read_length)
        # print('> <data>')
        if len(chunk) != read_length:
            self._handle_retry_with_nak()
            return

        chunk = crypt(self._secret, chunk[:NONCE_LENGTH], chunk[NONCE_LENGTH:])
        try:
            chunk_data = parse_chunk(chunk)
        except ValueError:
            self._handle_retry_with_nak()
            return
        if self.session_id is not None and chunk_data['session_id'] != self.session_id:
            self._handle_retry_with_nak()
            return
        if chunk_data['chunk_index'] != self._current_chunk:
            self._send_command(b'%b %d' % (CMD_ENQ, self._current_chunk))
            return

        if (chunk_data['msg_type'] & 0x10) != 0:
            self.session_id = chunk_data['session_id']
        else:
            msg_type = chunk_data['msg_type'] & 0x0f
            if self._msg_type != 0 and msg_type != 0 and msg_type != self._msg_type:
                self._handle_retry_with_nak()
                return

        current_offset = self._current_chunk * CHUNK_MAX_LENGTH
        if self._callback and not self._callback(self, TCPCallbackType.CHUNK_RECEIVED, current_offset=current_offset,
                        end_offset=current_offset + chunk_length, total_length=self._data_length,
                        chunk=chunk_data['payload']):
            self._send_cancel()
            return

        self._data.extend(chunk_data['payload'])  # type: ignore
        self._current_chunk += 1
        self._attempts = 0

        self._send_ack()
        self.touch_last_activity_time()

        if self._current_chunk == self._total_chunks:
            if self._callback:
                self._callback(self, TCPCallbackType.SUCCESS, state=self._state)
            self._result = TCPResult.SUCCESS
            self._state = TCPState.IDLE

    def _handle_commands(self):
        while len(self._cmd_queue) > 0:
            cmd = self._cmd_queue.pop(0)
            # print((b'> ' + cmd).decode())
            cmd_split = cmd.split()
            if len(cmd_split) == 0:
                continue

            need_callback = False
            if cmd_split[0] == CMD_PKT and len(cmd_split) >= 2:
                if self._state == TCPState.LISTENING:
                    try:
                        self._data_length = int(cmd_split[1])
                        self._current_chunk = 0
                        self._total_chunks = (self._data_length + CHUNK_MAX_LENGTH - 1) // CHUNK_MAX_LENGTH
                        self._attempts = 0
                        self._send_ack()
                        self._state = TCPState.RECEIVING
                        self.touch_last_activity_time()
                    except ValueError:
                        need_callback = True  # Can't parse parameter, forward it to callback
                else:
                    need_callback = True  # Weird message for state, forward it to callback
            elif cmd_split[0] == CMD_ACK:
                if self._state == TCPState.SENDING:
                    self._current_chunk += 1
                    self._last_activity_time = None
                    if self._current_chunk >= self._total_chunks:
                        if self._callback:
                            self._callback(self, TCPCallbackType.SUCCESS, state=self._state)
                        self._result = TCPResult.SUCCESS
                        self._state = TCPState.IDLE
                elif self._state == TCPState.INITIATING:
                    self._last_activity_time = None
                    self._state = TCPState.SENDING
                    if self._current_chunk >= self._total_chunks:  # 0-byte packet
                        if self._callback:
                            self._callback(self, TCPCallbackType.SUCCESS, state=self._state)
                        self._result = TCPResult.SUCCESS
                        self._state = TCPState.IDLE
                else:
                    need_callback = True  # Weird message for state, forward it to callback
            elif cmd_split[0] == CMD_NAK:
                if self._state == TCPState.SENDING:
                    self._last_activity_time = None  # Trigger resend of current chunk
                else:
                    need_callback = True  # Weird message for state, forward it to callback
            elif cmd_split[0] == CMD_ENQ and len(cmd_split) >= 2:
                if self._state == TCPState.SENDING:
                    try:
                        self._current_chunk = int(cmd_split[1])
                        if self._current_chunk < self._total_chunks:
                            self._last_activity_time = None  # Trigger resend of selected chunk
                        else:
                            need_callback = True  # Invalid parameter, forward it to callback
                    except ValueError:
                        need_callback = True  # Can't parse parameter, forward it to callback
                else:
                    need_callback = True  # Weird message for state, forward it to callback
            elif cmd_split[0] == CMD_CAN:
                self._state = TCPState.IDLE
                self._result = TCPResult.CANCELLED
            elif cmd_split[0] == CMD_ECHO and len(cmd_split) >= 2:
                if cmd_split[1] == PARAM_ECHO_REQ:
                    self._send_command(b'%b %b' % (CMD_ECHO, PARAM_ECHO_REP))
                    if self._echo_response_only:
                        self._echo_reply_time = time.time()
                elif cmd_split[1] == PARAM_ECHO_REP:
                    self._echo_reply_time = time.time()
                else:
                    need_callback = True  # Invalid parameter, forward it to callback
            else:
                need_callback = True

            if need_callback and self._callback and not self._callback(self, TCPCallbackType.CUSTOM_CMD, cmd=cmd.decode().split()):
                self._send_cancel()

    def _handle_sending(self):
        if self._state == TCPState.INITIATING:
            self._send_command(b'%b %d' % (CMD_PKT, self._data_length))
            self.touch_last_activity_time()
        elif self._state == TCPState.SENDING:
            self._next_send_chunk = None

            start_offset = self._current_chunk * CHUNK_MAX_LENGTH
            end_offset = start_offset + self._get_curr_chunk_length()
            if self._callback and not self._callback(self, TCPCallbackType.CHUNK_RECEIVED, current_offset=start_offset,
                            end_offset=end_offset, total_length=self._data_length):
                self._send_cancel()
                return

            if self._next_send_chunk is None:
                if self._data is None:
                    self._send_cancel()
                    raise RuntimeError('No chunk data set to send')
                else:
                    self._next_send_chunk = self._data[start_offset:end_offset]
            else:
                if len(self._next_send_chunk) != end_offset - start_offset:
                    self._send_cancel()
                    raise RuntimeError('Chunk data with incorrect length supplied.')

            chunk_to_send = create_chunk(self.session_id, self._msg_type, self._current_chunk, self._next_send_chunk)
            nonce = randbytes(NONCE_LENGTH)
            chunk_to_send = nonce + crypt(self._secret, nonce, chunk_to_send)
            # print('< <data>')
            self._serport.write(chunk_to_send)
            self.touch_last_activity_time()

    def _run_state_machine(self):
        if self._state == TCPState.IDLE:
            raise RuntimeError('State machine is idle.')

        if self._state == TCPState.LISTENING:
            self.touch_last_activity_time()
        else:
            self._last_activity_time = None
        self._attempts = 0

        while self._state != TCPState.IDLE:
            if self._read_serial():
                self._handle_commands()
            else:
                time.sleep(self.read_timeout)

            if self._last_activity_time is not None:
                if time.time() - self._last_activity_time >= self.cmd_timeout:
                    if not self._handle_retry(False):
                        continue
                else:
                    continue

            if self._state != TCPState.IDLE:
                self._handle_sending()
