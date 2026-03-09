import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send a test POST request to /api/report."
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:18080/api/report",
        help="Target report endpoint URL.",
    )
    parser.add_argument(
        "--agent-id",
        default="VM-3-1",
        help="Agent ID.",
    )
    parser.add_argument(
        "--region",
        default="97区",
        help="Region label.",
    )
    parser.add_argument(
        "--current-group",
        type=int,
        default=None,
        help="Current group. If omitted, server falls back to finished_group.",
    )
    parser.add_argument(
        "--finished-group",
        type=int,
        default=32,
        help="Finished group.",
    )
    parser.add_argument(
        "--next-group",
        type=int,
        default=83,
        help="Next group.",
    )
    parser.add_argument(
        "--role-index",
        type=int,
        default=3,
        help="Role index.",
    )
    parser.add_argument(
        "--event",
        default="group_complete_ready_next",
        help="Event name.",
    )
    parser.add_argument(
        "--auth-token",
        default="",
        help="Optional X-Auth-Token header value.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    payload = {
        "event": args.event,
        "agent_id": args.agent_id,
        "region": args.region,
        "current_group": args.current_group,
        "finished_group": args.finished_group,
        "next_group": args.next_group,
        "role_index": args.role_index,
        "ts": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if args.auth_token:
        headers["X-Auth-Token"] = args.auth_token

    request = urllib.request.Request(
        args.url,
        data=data,
        headers=headers,
        method="POST",
    )

    print("POST", args.url)
    print(json.dumps(payload, ensure_ascii=False, indent=2))

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8", "ignore")
            print("status:", response.status)
            print("response:", body)
            return 0
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "ignore")
        print("status:", exc.code)
        print("response:", body)
        return 1
    except Exception as exc:
        print("request failed:", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
