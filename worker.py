#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import threading
import time
from typing import Optional

from common import (
    MessageIO,
    Job,
    Result,
    PROTOCOL_VERSION,
    heartbeat_resp_dict,
)
from cracking import ThreadedBruteForcer
from hashing import build_verifier, detect_algorithm_name


class WorkerApp:
    def __init__(self, controller_host: str, port: int, threads: int) -> None:
        self.controller_host = controller_host
        self.port = port
        self.threads = threads

        self._send_lock = threading.Lock()
        self._done = threading.Event()

        self._bruteforcer: Optional[ThreadedBruteForcer] = None
        self._crack_result_password: Optional[str] = None
        self._crack_found: bool = False
        self._compute_time: float = 0.0

    def _safe_send(self, sock: socket.socket, obj: dict) -> None:
        with self._send_lock:
            MessageIO.send_msg(sock, obj)

    def _heartbeat_loop(self, sock: socket.socket) -> None:
        # Allow periodic timeout so we can exit when done
        sock.settimeout(1.0)
        while not self._done.is_set():
            try:
                msg = MessageIO.recv_msg(sock)
            except socket.timeout:
                continue
            except Exception:
                # if connection dies, end loop
                self._done.set()
                return

            mtype = msg.get("type")
            if mtype == "HEARTBEAT_REQ":
                if self._bruteforcer is None:
                    # Not started yet
                    delta = 0
                    total = 0
                    active = 0
                else:
                    delta = self._bruteforcer.get_delta_since_last_heartbeat()
                    total = self._bruteforcer.get_total_tested()
                    active = self._bruteforcer.get_threads_active()

                resp = heartbeat_resp_dict(delta_tested=delta, total_tested=total, threads_active=active)
                try:
                    self._safe_send(sock, resp)
                except Exception:
                    self._done.set()
                    return
                continue

            # Controller should not send anything else while job is running
            # Ignore unknown messages to avoid breaking correctness
            continue

    def run(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.controller_host, self.port))

        try:
            # Register
            self._safe_send(sock, {"type": "REGISTER", "v": PROTOCOL_VERSION})

            # Receive job
            job_msg = MessageIO.recv_msg(sock)
            job = Job.from_dict(job_msg)

            # Build verifier
            _ = detect_algorithm_name(job.full_hash)
            verifier = build_verifier(job.full_hash)

            # Start heartbeat responder thread
            hb_thread = threading.Thread(target=self._heartbeat_loop, args=(sock,), daemon=True)
            hb_thread.start()

            # Start cracking (fixed-length as per job.length)
            self._bruteforcer = ThreadedBruteForcer(
                verifier=verifier,
                charset=job.charset,
                length=job.length,
                threads=self.threads,
                chunk_size=2000,
            )

            t0 = time.perf_counter()
            crack_res = self._bruteforcer.run()
            t1 = time.perf_counter()

            self._compute_time = t1 - t0
            self._crack_found = crack_res.found
            self._crack_result_password = crack_res.password

            # Send final result
            result = Result(found=crack_res.found, password=crack_res.password, compute_time=self._compute_time)
            self._safe_send(sock, result.to_dict())

            self._done.set()
            return 0

        finally:
            self._done.set()
            try:
                sock.close()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", required=True, help="Controller host/IP")
    parser.add_argument("-p", type=int, required=True, help="Controller port")
    parser.add_argument("-t", type=int, required=True, help="Worker thread count")
    args = parser.parse_args()

    app = WorkerApp(args.c, args.p, args.t)
    raise SystemExit(app.run())


if __name__ == "__main__":
    main()
