"""Safely resume an authorized, suspended demonstration process."""

import argparse

import psutil

from src.response.demo_authorization import is_authorized_demo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    args = parser.parse_args()

    if not is_authorized_demo(args.pid):
        print("REFUSED: PID is not an authorized demonstration process.")
        return

    process = psutil.Process(args.pid)

    if process.status() != psutil.STATUS_STOPPED:
        print("Process is not suspended.")
        return

    process.resume()

    if process.status() != psutil.STATUS_STOPPED:
        print(f"RESUME VERIFIED: PID {args.pid} is running.")
    else:
        print("WARNING: Process remains suspended.")


if __name__ == "__main__":
    main()
