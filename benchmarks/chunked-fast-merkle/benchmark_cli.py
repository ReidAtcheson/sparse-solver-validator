#!/usr/bin/env python3
"""Measure repeated executions of a prover or validator command."""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    if args.warmups < 0 or args.repetitions <= 0:
        parser.error("warmups must be nonnegative and repetitions positive")
    return args


def main() -> None:
    args = parse_args()
    timings = []
    for repetition in range(args.warmups + args.repetitions):
        start = time.perf_counter_ns()
        subprocess.run(
            args.command,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        elapsed = (time.perf_counter_ns() - start) * 1.0e-9
        if repetition >= args.warmups:
            timings.append(elapsed)

    print(
        json.dumps(
            {
                "command": args.command,
                "warmups": args.warmups,
                "repetitions": args.repetitions,
                "minimum_seconds": min(timings),
                "median_seconds": statistics.median(timings),
                "maximum_seconds": max(timings),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
