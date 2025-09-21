#!/usr/bin/env python3
import argparse
import os
import shlex
import signal
import subprocess
import sys
import time

# Cross‑platform-ish cargo test timeout wrapper.
# - On Unix: starts cargo in its own process group and sends SIGINT -> SIGTERM -> SIGKILL on timeout.
# - Exit code 124 means timeout.

def main():
    default_timeout = int(os.environ.get("TEST_TIMEOUT_SECONDS", "900"))
    parser = argparse.ArgumentParser(description="Run cargo test with a hard timeout")
    parser.add_argument("--timeout", "-t", type=int, default=default_timeout,
                        help="timeout in seconds (default from TEST_TIMEOUT_SECONDS or 900)")
    parser.add_argument("--grace", type=int, default=int(os.environ.get("TEST_TIMEOUT_GRACE", "20")),
                        help="grace period in seconds after SIGINT before SIGTERM/SIGKILL (default 20)")
    parser.add_argument("--cmd", default="cargo test --workspace --all-targets",
                        help="command to run (default: cargo test --workspace --all-targets)")
    parser.add_argument("extra", nargs=argparse.REMAINDER,
                        help="extra args appended to the command (prefix with -- to stop parsing)")
    args = parser.parse_args()

    # Build final command
    if args.extra and args.extra[0] == "--":
        extra = args.extra[1:]
    else:
        extra = args.extra
    cmd_str = args.cmd
    if extra:
        cmd_str += " " + " ".join(shlex.quote(x) for x in extra)
    cmd = shlex.split(cmd_str)

    print(f"[test-with-timeout] running: {cmd_str}")
    print(f"[test-with-timeout] timeout={args.timeout}s grace={args.grace}s")

    start = time.time()

    # Launch process in its own group so we can signal the whole tree
    preexec = os.setsid if hasattr(os, "setsid") else None
    creationflags = 0
    if os.name == "nt":
        # CREATE_NEW_PROCESS_GROUP = 0x00000200
        creationflags = 0x00000200
    p = subprocess.Popen(cmd, preexec_fn=preexec, creationflags=creationflags)

    try:
        rc = p.wait(timeout=args.timeout)
        return rc
    except subprocess.TimeoutExpired:
        elapsed = int(time.time() - start)
        print(f"[test-with-timeout] timeout after {elapsed}s, sending SIGINT…", file=sys.stderr)
        try:
            if os.name == "nt":
                p.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            else:
                os.killpg(p.pid, signal.SIGINT)
        except Exception:
            try:
                p.send_signal(signal.SIGINT)
            except Exception:
                pass

        try:
            p.wait(timeout=args.grace)
            return 124
        except subprocess.TimeoutExpired:
            print(f"[test-with-timeout] still running after {args.grace}s, sending SIGTERM…", file=sys.stderr)
            try:
                if os.name != "nt":
                    os.killpg(p.pid, signal.SIGTERM)
                else:
                    p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=5)
                return 124
            except subprocess.TimeoutExpired:
                print("[test-with-timeout] force killing…", file=sys.stderr)
                try:
                    if os.name != "nt":
                        os.killpg(p.pid, signal.SIGKILL)
                    else:
                        p.kill()
                except Exception:
                    pass
                p.wait(timeout=5)
                return 124

if __name__ == "__main__":
    sys.exit(main())
