#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List
import threading

from hashing import HashVerifier


@dataclass
class CrackResult:
    found: bool
    password: Optional[str]
    tried: int


class StaticFirstCharBruteForcer:
    """
    ONLY length=3 brute force over charset^3.

    Static partitioning:
      - Split FIRST character space into T disjoint slices.
      - Each thread enumerates:
            for c1 in slice:
                for c2 in charset:
                    for c3 in charset:
                        test(c1+c2+c3)

    Covers full space exactly once, no duplicates, no omissions.
    Tracks total_tested + delta since last heartbeat.
    """

    def __init__(self, verifier: HashVerifier, charset: str, threads: int, batch_commit: int = 200) -> None:
        if threads <= 0:
            raise ValueError("threads must be > 0")
        if not charset:
            raise ValueError("charset must be non-empty")

        self.verifier = verifier
        self.charset = charset
        self.threads = threads
        self.batch_commit = max(1, batch_commit)

        self._stop = threading.Event()

        self._found_lock = threading.Lock()
        self._found_password: Optional[str] = None

        self._count_lock = threading.Lock()
        self._total_tested = 0
        self._last_hb_total = 0

        self._threads_active = 0
        self._threads_active_lock = threading.Lock()

    def _add_tested(self, n: int) -> None:
        with self._count_lock:
            self._total_tested += n

    def get_total_tested(self) -> int:
        with self._count_lock:
            return self._total_tested

    def get_delta_since_last_heartbeat(self) -> int:
        with self._count_lock:
            delta = self._total_tested - self._last_hb_total
            self._last_hb_total = self._total_tested
            return delta

    def get_threads_active(self) -> int:
        with self._threads_active_lock:
            return self._threads_active

    def _set_found(self, password: str) -> None:
        with self._found_lock:
            if self._found_password is None:
                self._found_password = password
                self._stop.set()

    def _slice_for_thread(self, i: int) -> str:
        n = len(self.charset)
        start = (n * i) // self.threads
        end = (n * (i + 1)) // self.threads
        return self.charset[start:end]

    def _worker(self, first_chars: str) -> None:
        with self._threads_active_lock:
            self._threads_active += 1

        local = 0
        try:
            for c1 in first_chars:
                if self._stop.is_set():
                    return
                for c2 in self.charset:
                    if self._stop.is_set():
                        return
                    for c3 in self.charset:
                        if self._stop.is_set():
                            return

                        candidate = c1 + c2 + c3
                        local += 1

                        if self.verifier.verify(candidate):
                            if local:
                                self._add_tested(local)
                                local = 0
                            self._set_found(candidate)
                            return

                        if local >= self.batch_commit:
                            self._add_tested(local)
                            local = 0

            if local:
                self._add_tested(local)

        finally:
            with self._threads_active_lock:
                self._threads_active -= 1

    def run(self) -> CrackResult:
        threads: List[threading.Thread] = []
        for i in range(self.threads):
            first_chars = self._slice_for_thread(i)
            t = threading.Thread(target=self._worker, args=(first_chars,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        tried = self.get_total_tested()
        with self._found_lock:
            pw = self._found_password

        return CrackResult(found=(pw is not None), password=pw, tried=tried)
