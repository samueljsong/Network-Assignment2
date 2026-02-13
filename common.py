#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional

PROTOCOL_VERSION = 1


class ProtocolError(Exception):
    pass


class MessageIO:
    @staticmethod
    def recv_msg(conn: socket.socket) -> Dict[str, Any]:
        header = MessageIO._recv_exact(conn, 4)
        length = int.from_bytes(header, "big")
        if length <= 0 or length > 100_000_000:
            raise ProtocolError(f"Invalid message length: {length}")

        data = MessageIO._recv_exact(conn, length)
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception as e:
            raise ProtocolError(f"Invalid JSON payload: {e}") from e
        if not isinstance(obj, dict):
            raise ProtocolError("Message must be a JSON object.")
        return obj

    @staticmethod
    def send_msg(conn: socket.socket, obj: Dict[str, Any]) -> None:
        payload = json.dumps(obj).encode("utf-8")
        conn.sendall(len(payload).to_bytes(4, "big") + payload)

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ProtocolError("Connection closed unexpectedly.")
            buf += chunk
        return buf


@dataclass(frozen=True)
class Job:
    full_hash: str
    length: int
    charset: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "JOB",
            "v": PROTOCOL_VERSION,
            "hash": self.full_hash,
            "length": self.length,
            "charset": self.charset,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Job":
        if d.get("type") != "JOB":
            raise ProtocolError("Expected JOB message.")
        if d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Protocol version mismatch.")
        return Job(
            full_hash=str(d["hash"]),
            length=int(d["length"]),
            charset=str(d["charset"]),
        )


@dataclass(frozen=True)
class Result:
    found: bool
    password: Optional[str]
    compute_time: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "RESULT",
            "v": PROTOCOL_VERSION,
            "found": self.found,
            "password": self.password,
            "compute_time": self.compute_time,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Result":
        if d.get("type") != "RESULT":
            raise ProtocolError("Expected RESULT message.")
        if d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("Protocol version mismatch.")
        return Result(
            found=bool(d["found"]),
            password=d.get("password", None),
            compute_time=float(d["compute_time"]),
        )


def heartbeat_req_dict() -> Dict[str, Any]:
    return {"type": "HEARTBEAT_REQ", "v": PROTOCOL_VERSION}


def heartbeat_resp_dict(delta_tested: int, total_tested: int, threads_active: int) -> Dict[str, Any]:
    return {
        "type": "HEARTBEAT_RESP",
        "v": PROTOCOL_VERSION,
        "delta_tested": int(delta_tested),
        "total_tested": int(total_tested),
        "threads_active": int(threads_active),
    }


def supported_charset_79() -> str:
    return (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:',.<>/?"
    )