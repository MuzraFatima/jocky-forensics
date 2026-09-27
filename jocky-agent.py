#!/usr/bin/env python3
"""
JOCKY Endpoint Forensic Agent — Master CLI Runner

Provides the command-line interface for enrolling an endpoint device,
running the collection daemon, checking health/status, and managing pairing.

Usage:
    # 1. Pair device with JOCKY cloud/local backend using single-use 8-character code:
    python jocky-agent.py pair --server http://127.0.0.1:8000 --code ABC12345 [--name "My-Workstation"]

    # 2. Start background polling daemon (listens for forensic jobs):
    python jocky-agent.py start [--interval 2.0] [--heartbeat 15.0]

    # 3. Check endpoint enrollment & connection status:
    python jocky-agent.py status

    # 4. Unpair device and clear local credentials:
    python jocky-agent.py unpair
"""

import argparse
import logging
import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from agent.client import EndpointAgentClient
from agent.config import AgentConfig
from agent.runner import AgentRunner


BANNER = r"""
       _  ____   ____ _  ____   __
      | |/ __ \ / ___| |/ /\ \ / /
   _  | | |  | | |   | ' /  \ V / 
  | |_| | |__| | |___| . \   | |  
   \___/ \____/ \____|_|\_\  |_|  ENDPOINT FORENSIC AGENT
"""


def setup_logging(verbose: bool = False):
    """Sets up formatted terminal logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_pair(args) -> int:
    """Handles the 'pair' subcommand."""
    config = AgentConfig.load(args.config)
    client = EndpointAgentClient(config=config)

    server = args.server.strip()
    code = args.code.strip()
    name = args.name.strip() if args.name else None

    print(f"[*] Enrolling endpoint with JOCKY server at: {server}")
    print(f"[*] Submitting pairing code: {code}")

    success = client.pair(server_url=server, pairing_code=code, custom_hostname=name)
    if success:
        print("\n[+] SUCCESS: Device enrolled successfully!")
        print(f"    - Device ID:   {client.config.device_id}")
        print(f"    - Hostname:    {client.config.hostname}")
        print(f"    - Platform:    {client.config.platform}")
        print(f"    - Config File: {client.config.config_path}")
        print("\n[*] You may now start the agent daemon with:")
        print("    python jocky-agent.py start\n")
        return 0
    else:
        print("\n[-] ERROR: Pairing failed. Verify your pairing code, server URL, and network connectivity.\n")
        return 1


def cmd_start(args) -> int:
    """Handles the 'start' subcommand."""
    config = AgentConfig.load(args.config)
    if not config.is_paired:
        print("[-] ERROR: Device is not paired with a JOCKY server.")
        print("    Run `python jocky-agent.py pair --server <url> --code <code>` first.\n")
        return 1

    client = EndpointAgentClient(config=config)

    print(BANNER)
    print(f"[*] Starting JOCKY Endpoint Agent v{config.agent_version}")
    print(f"[*] Connected Server: {config.server_url}")
    print(f"[*] Device ID:        {config.device_id}")
    print(f"[*] Hostname:         {config.hostname} ({config.platform})")
    print(f"[*] Polling Interval: {args.interval}s | Heartbeat Interval: {args.heartbeat}s")
    print("[*] Press Ctrl+C to stop the daemon.\n")

    if args.once:
        print("[*] Running single execution pass (--once)...")
        completed = client.run_once()
        print(f"[+] Execution completed. Jobs processed: {completed}")
        return 0

    try:
        client.run_daemon(
            poll_interval=args.interval,
            heartbeat_interval=args.heartbeat,
        )
        return 0
    except KeyboardInterrupt:
        print("\n[*] Agent daemon terminated gracefully by user.")
        return 0
    except Exception as e:
        print(f"\n[-] Fatal daemon error: {e}")
        return 1


def cmd_status(args) -> int:
    """Handles the 'status' subcommand."""
    config = AgentConfig.load(args.config)

    print("\n--- JOCKY Endpoint Agent Status ---")
    print(f"  Configuration File: {config.config_path}")
    print(f"  Enrolled / Paired:  {'YES' if config.is_paired else 'NO'}")

    if not config.is_paired:
        print("  Status:             UNPAIRED")
        print("\n[*] To pair this device, run:")
        print("    python jocky-agent.py pair --server <url> --code <code>\n")
        return 0

    print(f"  Server URL:         {config.server_url}")
    print(f"  Device ID:          {config.device_id}")
    print(f"  Hostname:           {config.hostname}")
    print(f"  Platform:           {config.platform} ({config.os_version})")
    print(f"  Paired At:          {config.paired_at or 'Unknown'}")

    # Test live heartbeat
    print("\n[*] Probing central server presence...")
    client = EndpointAgentClient(config=config)
    alive = client.send_heartbeat()
    if alive:
        print("  Backend Connection: ONLINE (Heartbeat acknowledged)")
    else:
        print("  Backend Connection: OFFLINE or REVOKED (Check server status or credentials)")
    print("")
    return 0 if alive else 1


def cmd_unpair(args) -> int:
    """Handles the 'unpair' subcommand."""
    config = AgentConfig.load(args.config)
    if not config.is_paired and not Path(config.config_path).is_file():
        print("[*] Device is not currently paired.")
        return 0

    success = config.clear()
    if success:
        print("[+] Local credentials removed successfully. Device is unpaired.")
        return 0
    else:
        print("[-] Failed to remove credential file. Check file permissions.")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Builds the top-level argument parser."""
    parser = argparse.ArgumentParser(
        description="JOCKY Forensic Endpoint Agent CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--config", type=str, default=None, help="Custom path to .jocky-agent.json config file")

    subparsers = parser.add_subparsers(dest="command", help="Agent command to execute")

    # 1. pair
    p_pair = subparsers.add_parser("pair", help="Pair this endpoint using an 8-character code")
    p_pair.add_argument("--server", required=True, help="Central JOCKY server URL (e.g. http://127.0.0.1:8000)")
    p_pair.add_argument("--code", required=True, help="Single-use 8-character pairing code from the dashboard")
    p_pair.add_argument("--name", default=None, help="Optional friendly display name for this endpoint")

    # 2. start
    p_start = subparsers.add_parser("start", help="Start the background polling agent daemon")
    p_start.add_argument("--interval", type=float, default=2.0, help="Job polling interval in seconds (default: 2.0)")
    p_start.add_argument("--heartbeat", type=float, default=15.0, help="Heartbeat interval in seconds (default: 15.0)")
    p_start.add_argument("--once", action="store_true", help="Run a single polling iteration and exit")

    # 3. status
    subparsers.add_parser("status", help="Display pairing configuration and test live connection")

    # 4. unpair
    subparsers.add_parser("unpair", help="Clear local pairing credentials and unenroll device")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "pair":
        return cmd_pair(args)
    elif args.command == "start":
        return cmd_start(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "unpair":
        return cmd_unpair(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
