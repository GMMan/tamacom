# tamacom: Tamagotchi Paradise prongs communication library

-----

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation

```console
pip install git+https://github.com/GMMan/punitapichan-notes.git@main
```

## Usage

The main class is `TCPComm`. Create an instance with a context manager.

```py
from tamacom import TCPComm, TCPResult

with TCPComm('COM4', SECRET) as comm:
    buf = b'\x55' * 256

    while True:
        (result, _) = comm.receive_packet(0xf)
        if result == TCPResult.SUCCESS:
            break

    while True:
        result = comm.send_packet(0xf, buf)
        if result == TCPResult.SUCCESS:
            break
```

The main methods in `TCPComm` are `send_packet()` and `receive_packet()`. You
may also sometimes need to use `send_session_id()` and `echo_check()`. The
library supports sending prepared data or generating data on the fly through
callbacks.

For details on the protocol, see [this](https://gist.github.com/GMMan/4948c6acae55ae53002a5f270704af5f).

### Sending using callbacks

Supply your callback (see `TCPCallback`) to `send_packet()`, and also specify
the length of the packet (this must be known ahead of time). When a chunk is
required, you receive a callback with type `TCPCallbackType.CHUNK_PREPARE_TO_SEND`.
Generate the chunk, and set it to be sent by calling `sender.set_chunk_to_send()`.
Return `True` to continue, or `False` to cancel operation. Note that the chunk
you want to send must have a length of `end_offset - current_offset`.

### Handling custom commands

If the packet type you are dealing with have custom commands during the
exchange, you should also provide a callback. For any commands that are unknown
or have invalid parameters, they are sent to the callback for processing.
You receive a callback with type `TCPCallbackType.CUSTOM_CMD`, and the command
and its parameters as a list in the `cmd` parameter. You can call
`sender.send_custom_command()` to respond to the command. If the command is
valid, you should also call `sender.touch_last_activity_time()` to prevent
a potential timeout.

### Sending session ID

Session IDs are sent using regular packet transfers. This means you must not be
currently in a packet transfer session when starting to send a session ID.
The library will automatically handle updating its local session ID if you
receive a packet. You can also manually set the ID via the `session_id` field
to change the session ID that is being compared against. To set a new session
ID and send it to the peer, use the `send_session_id()` method.

### Echos

You can initiate an echo using the `echo_check()` method. Sometimes the peer
expects you to respond to echos. If you are not currently receiving chunks,
you can call `echo_check(True)` to only respond to echo requests and not send
your own. The result of the function will let you know if the echo succeeded
either way. If you are in a callback and want to initiate an echo request,
you can call `sender.send_echo_req()`. You can access the `echo_reply_time`
property to check to see if you received a reply.

## License

`tamacom` is distributed under the terms of the [GNU General Public License v3.0 or later](https://spdx.org/licenses/GPL-3.0-or-later.html) license.
