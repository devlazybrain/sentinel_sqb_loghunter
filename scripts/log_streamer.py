#!/usr/bin/env python3
"""Replay a log file line-by-line with a fixed delay between rows."""
import argparse
import sys
import time


def parse_duration(s: str) -> float:
    s = s.strip().lower()
    if s.endswith("ms"):
        return float(s[:-2]) / 1000
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60
    if s.endswith("h"):
        return float(s[:-1]) * 3600
    return float(s)


def count_lines(path: str) -> int:
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def stream(path: str, delay: float, loop: bool) -> None:
    # time.sleep has ~1ms minimum granularity on Linux. For sub-ms per-line
    # delays we accumulate "debt" and sleep in 5ms chunks so the total elapsed
    # time tracks the target instead of being inflated by sleep overhead.
    chunk = 0.005
    while True:
        debt = 0.0
        with open(path, "r") as f:
            for line in f:
                sys.stdout.write(line)
                debt += delay
                if debt >= chunk:
                    sys.stdout.flush()
                    time.sleep(debt)
                    debt = 0.0
            sys.stdout.flush()
            if debt > 0:
                time.sleep(debt)
        if not loop:
            return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="path to the log file to replay")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="seconds to wait between lines (default: 0.1)")
    parser.add_argument("--duration",
                        help="finish one pass in this much time (e.g. 3m, 90s, 0.5h). "
                             "Overrides --delay by auto-computing per-line delay.")
    parser.add_argument("--loop", action="store_true",
                        help="restart from the top on EOF")
    args = parser.parse_args()

    delay = args.delay
    if args.duration is not None:
        target = parse_duration(args.duration)
        print(f"Counting lines in {args.path}...", file=sys.stderr)
        n = count_lines(args.path)
        delay = target / n if n > 0 else 0
        print(f"{n} lines, replay over {target:.2f}s -> {delay*1000:.3f} ms/line",
              file=sys.stderr)

    try:
        stream(args.path, delay, args.loop)
    except (BrokenPipeError, KeyboardInterrupt):
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
