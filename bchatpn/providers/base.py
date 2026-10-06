"""Provider contract. A provider turns (device token, opaque encrypted data) into one push.

The result tells the dispatcher what to do next, which is the whole point of the type:

    OK             delivered to the push service
    RETRY          transient trouble (timeout, 5xx, 429, connection error): try again, back off
    INVALID_TOKEN  the service says this token is dead: remove the device
    FAIL           permanent, but NOT the token's fault (oversize payload, bad credentials, wrong
                   topic): do not retry, do not remove the device
"""

from __future__ import annotations

import enum
from typing import Protocol


class Result(enum.Enum):
    OK = "ok"
    RETRY = "retry"
    INVALID_TOKEN = "invalid_token"
    FAIL = "fail"


class Provider(Protocol):
    name: str
    device_types: frozenset[str]  # which registered device types this provider serves
    max_in_flight: int  # concurrent sends the dispatcher may start against this provider

    async def send(self, token: str, data: str) -> Result: ...

    async def aclose(self) -> None: ...
