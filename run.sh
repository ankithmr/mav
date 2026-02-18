#!/usr/bin/env python3
"""Interactively run commands from a text file."""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterator, Optional, Tuple


def iter_commands(path: Path) -> Iterator[Tuple[int, str]]:
    """Yield (line_number, command) pairs for non-empty, non-comment lines."""
    with path.open("r", encoding="utf-8") as handle:
        for index, raw_line in enumerate(handle, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            yield index, stripped


def prompt_user(command: str) -> bool:
    """Show the command and ask the user whether to execute it."""
    while True:
        response = input(f"Execute this command? [y/N/q] ").strip().lower()
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no", ""}:
            return False
        if response in {"q", "quit"}:
            raise KeyboardInterrupt("User aborted")
        print("Please respond with 'y' (yes), 'n' (no), or 'q' (quit).")


def run_command(
    command: str,
    ssh_target: str,
    ssh_port: Optional[int],
    ssh_identity: Optional[Path],
    dry_run: bool,
) -> int:
    """Enter config mode ('con') remotely, then run the provided command via SSH."""
    ssh_parts = ["ssh"]
    if ssh_identity:
        ssh_parts.extend(["-i", str(ssh_identity)])
    if ssh_port:
        ssh_parts.extend(["-p", str(ssh_port)])
    ssh_parts.append("-tt")
    ssh_parts.append(ssh_target)
    payload = f"con\n{command}\nexit\n"
    if dry_run:
        quoted_cmd = " ".join(shlex.quote(part) for part in ssh_parts)
        print(f"[dry-run] {quoted_cmd}")
        print(f"[dry-run] payload:\n{payload.rstrip()}\n")
        return 0
    completed = subprocess.run(ssh_parts, input=payload, text=True)
    return completed.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Interactively execute commands from a file")
    parser.add_argument("commands_file", type=Path, help="Path to the text file containing commands")
    parser.add_argument("--ssh-target", required=True, help="Destination for SSH (e.g., user@host)")
    parser.add_argument("--ssh-port", type=int, default=None, help="SSH port (defaults to 22)")
    parser.add_argument(
        "--ssh-identity",
        type=Path,
        default=None,
        help="Path to SSH private key to use for authentication",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the SSH command and payload instead of executing",
    )
    parser.add_argument(
        "--start-from",
        type=int,
        default=None,
        help="Begin processing at the given command index (1-based)",
    )
    parser.add_argument(
        "--resume-file",
        type=Path,
        default=None,
        help="Persist the next command index for automatic resume",
    )
    args = parser.parse_args()

    start_index = args.start_from
    if start_index is None:
        if args.resume_file and args.resume_file.exists():
            try:
                start_index = int(args.resume_file.read_text(encoding="utf-8").strip() or "1")
            except ValueError:
                start_index = 1
        else:
            start_index = 1
    elif start_index < 1:
        start_index = 1

    def update_resume(index: int) -> None:
        if not args.resume_file:
            return
        args.resume_file.parent.mkdir(parents=True, exist_ok=True)
        args.resume_file.write_text(str(index), encoding="utf-8")

    try:
        for line_number, command in iter_commands(args.commands_file):
            if line_number < start_index:
                continue
            print(f"\n[{line_number}] {command}")
            if args.dry_run:
                run_command(command, args.ssh_target, args.ssh_port, args.ssh_identity, True)
                continue
            try:
                should_run = prompt_user(command)
            except KeyboardInterrupt:
                print("\nAborting at user request.")
                sys.exit(130)
            if not should_run:
                print("Skipped.")
                continue
            exit_code = run_command(command, args.ssh_target, args.ssh_port, args.ssh_identity, False)
            if exit_code == 0:
                update_resume(line_number + 1)
                print("Completed successfully.")
            else:
                print(f"Command exited with status {exit_code}." )
                retry = input("Retry command? [y/N] ").strip().lower()
                if retry in {"y", "yes"}:
                    exit_code = run_command(command, args.ssh_target, args.ssh_port, args.ssh_identity, False)
                    if exit_code == 0:
                        update_resume(line_number + 1)
                        print("Completed successfully on retry.")
                    else:
                        print(f"Retry also failed (status {exit_code}).")
    except FileNotFoundError:
        print(f"Command file not found: {args.commands_file}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
