#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time
import selectors
from dataclasses import dataclass

from common import (
    MessageIO,
    Job,
    Result,
    supported_charset_79,
    ProtocolError,
    PROTOCOL_VERSION,
    heartbeat_req_dict,
)
from hashing import detect_algorithm_name


class ShadowParseError(Exception):
    pass


@dataclass(frozen=True)
class ShadowEntry:
    username: str
    full_hash: str
    algo_name: str


class ShadowParser:
    @staticmethod
    def parse_shadow_file(shadow_file: str, username: str) -> ShadowEntry:
        with open(shadow_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line or ":" not in line:
                    continue
                if not line.startswith(username + ":"):
                    continue
                parts = line.strip().split(":")
                if len(parts) < 2:
                    raise ShadowParseError("Malformed shadow line.")
                full_hash = parts[1]
                if not full_hash or full_hash in ("*", "!", "!!"):
                    raise ShadowParseError("User has no usable password hash in the shadow file.")
                algo = detect_algorithm_name(full_hash)
                return ShadowEntry(username=username, full_hash=full_hash, algo_name=algo)
        raise ShadowParseError("User not found in shadow file.")


@dataclass
class Timings:
    parse_time: float = 0.0
    dispatch_latency: float = 0.0
    worker_compute: float = 0.0
    return_latency: float = 0.0
    total_runtime: float = 0.0


class ControllerApp:
    def __init__(self, shadow_file: str, username: str, port: int, heartbeat_seconds: float) -> None:
        self.shadow_file = shadow_file
        self.username = username
        self.port = port
        self.heartbeat_seconds = heartbeat_seconds

    def run(self) -> int:
        t0 = time.perf_counter()
        timings = Timings()

        # Parse shadow
        t_parse0 = time.perf_counter()
        entry = ShadowParser.parse_shadow_file(self.shadow_file, self.username)
        t_parse1 = time.perf_counter()
        timings.parse_time = t_parse1 - t_parse0

        # Listen for worker
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", self.port))
        server.listen(1)

        print(f"Controller listening on port {self.port}...")
        conn, addr = server.accept()
        print(f"Worker connected from {addr}")

        try:
            # Registration
            reg = MessageIO.recv_msg(conn)
            if reg.get("type") != "REGISTER" or reg.get("v") != PROTOCOL_VERSION:
                raise ProtocolError("Invalid REGISTER message.")

            # Send job (FULL SPACE, fixed length 3)
            job = Job(
                full_hash=entry.full_hash,
                length=3,
                charset=supported_charset_79(),
            )

            t_send0 = time.perf_counter()
            MessageIO.send_msg(conn, job.to_dict())
            t_send1 = time.perf_counter()
            timings.dispatch_latency = t_send1 - t_send0

            # Heartbeat + receive loop
            conn.setblocking(False)
            sel = selectors.DefaultSelector()
            sel.register(conn, selectors.EVENT_READ)

            next_hb = time.perf_counter() + self.heartbeat_seconds
            last_hb_time = time.perf_counter()

            print(f"Heartbeat interval: {self.heartbeat_seconds}s")
            print("Waiting for result... (heartbeats will print progress)")

            result: Result | None = None

            while True:
                now = time.perf_counter()

                # send heartbeat if due
                if now >= next_hb:
                    try:
                        MessageIO.send_msg(conn, heartbeat_req_dict())
                    except Exception as e:
                        raise ProtocolError(f"Failed to send heartbeat: {e}") from e
                    next_hb = now + self.heartbeat_seconds

                # wait for incoming message (timeout so we can heartbeat on schedule)
                timeout = max(0.0, min(0.25, next_hb - now))
                events = sel.select(timeout)

                if not events:
                    continue

                # read a message
                try:
                    msg = MessageIO.recv_msg(conn)  # may raise if connection closed
                except BlockingIOError:
                    continue

                mtype = msg.get("type")

                if mtype == "HEARTBEAT_RESP":
                    delta = int(msg.get("delta_tested", 0))
                    total = int(msg.get("total_tested", 0))
                    threads_active = int(msg.get("threads_active", 0))

                    hb_now = time.perf_counter()
                    elapsed = max(1e-9, hb_now - last_hb_time)
                    rate = delta / elapsed
                    last_hb_time = hb_now

                    print(f"[HB] delta_tested={delta} total_tested={total} threads_active={threads_active} rate={rate:.1f}/s")
                    continue

                if mtype == "RESULT":
                    t_recv = time.perf_counter()
                    result = Result.from_dict(msg)

                    timings.worker_compute = result.compute_time
                    timings.return_latency = (t_recv - t_send1) - result.compute_time
                    timings.total_runtime = t_recv - t0

                    self._report(entry, result, timings)
                    return 0

                raise ProtocolError(f"Unexpected message type: {mtype}")

        finally:
            try:
                conn.close()
            except Exception:
                pass
            try:
                server.close()
            except Exception:
                pass

    @staticmethod
    def _report(entry: ShadowEntry, result: Result, timings: Timings) -> None:
        print("\n=== JOB INFO ===")
        print(f"Username:     {entry.username}")
        print(f"Algorithm:    {entry.algo_name}")

        print("\n=== RESULTS ===")
        print(f"Password found: {result.found}")
        if result.found:
            print(f"Password:       {result.password}")

        print("\n=== TIMING (seconds) ===")
        print(f"Parse time:        {timings.parse_time:.6f}")
        print(f"Send latency:      {timings.dispatch_latency:.6f}")
        print(f"Worker compute:    {timings.worker_compute:.6f}")
        print(f"Return latency:    {timings.return_latency:.6f}")
        print(f"Total runtime:     {timings.total_runtime:.6f}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True, help="Path to shadow file")
    parser.add_argument("-u", required=True, help="Username to crack")
    parser.add_argument("-p", type=int, required=True, help="Port to listen on")
    parser.add_argument("-b", type=float, required=True, help="Heartbeat interval (seconds)")
    args = parser.parse_args()

    app = ControllerApp(args.f, args.u, args.p, args.b)
    raise SystemExit(app.run())


if __name__ == "__main__":
    main()
