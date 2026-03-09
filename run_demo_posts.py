import argparse
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send a batch of demo POST requests to /api/report."
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:18080/api/report",
        help="Target report endpoint URL.",
    )
    parser.add_argument(
        "--auth-token",
        default="",
        help="Optional X-Auth-Token header value.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="Delay in seconds between requests.",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=1,
        help="How many times to send the full demo dataset.",
    )
    return parser


def build_demo_payloads() -> List[Dict[str, Any]]:
    return [
        {
            "event": "group_complete_ready_next",
            "agent_id": "G1-1",
            "region": "97区",
            "current_group": 82,
            "finished_group": 82,
            "next_group": 83,
            "role_index": 3,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "VM-3-1",
            "region": "97区",
            "current_group": 32,
            "finished_group": 32,
            "next_group": 33,
            "role_index": 2,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "G1-2",
            "region": "103区",
            "current_group": 81,
            "finished_group": 81,
            "next_group": 82,
            "role_index": 4,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "VM-3-2",
            "region": "103区",
            "current_group": 32,
            "finished_group": 32,
            "next_group": 33,
            "role_index": 5,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "VM-3-4",
            "region": "109区",
            "current_group": 32,
            "finished_group": 32,
            "next_group": 33,
            "role_index": 4,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "VM-3-5",
            "region": "109区",
            "current_group": 80,
            "finished_group": 80,
            "next_group": 81,
            "role_index": 5,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "G1-3",
            "region": "111区",
            "current_group": 81,
            "finished_group": 81,
            "next_group": 82,
            "role_index": 5,
        },
        {
            "event": "group_complete_ready_next",
            "agent_id": "VM-3-6",
            "region": "111区",
            "current_group": 32,
            "finished_group": 32,
            "next_group": 33,
            "role_index": 3,
        },
    ]


def post_json(url: str, payload: Dict[str, Any], auth_token: str) -> int:
    request_payload = dict(payload)
    request_payload["ts"] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data = json.dumps(request_payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["X-Auth-Token"] = auth_token

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode("utf-8", "ignore")
        print(f"[{response.status}] {request_payload['agent_id']} {request_payload['region']} -> {body}")
        return response.status


def main() -> int:
    args = build_parser().parse_args()
    dataset = build_demo_payloads()

    if args.rounds < 1:
        print("rounds must be >= 1")
        return 2

    print("target:", args.url)
    print("records per round:", len(dataset))
    print("rounds:", args.rounds)
    print("delay seconds:", args.delay)

    sent = 0
    try:
        for round_index in range(args.rounds):
            print(f"=== round {round_index + 1} ===")
            for payload in dataset:
                post_json(args.url, payload, args.auth_token)
                sent += 1
                if args.delay > 0:
                    time.sleep(args.delay)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "ignore")
        print("http error:", exc.code, body)
        return 1
    except Exception as exc:
        print("request failed:", exc)
        return 1

    print("done, total sent:", sent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
