import argparse
import json
import os
import sys
from getpass import getpass

import requests


DEFAULT_BASE_URL = os.getenv("LOOKER_BASE_URL", "http://localhost:8000")
DEFAULT_API_PATH = os.getenv("LOOKER_API_PATH", "/api/investigate")
DEFAULT_SELECTOR = os.getenv("LOOKER_SELECTOR", "Phone Number")
DEFAULT_RAPIDAPI_HOST = os.getenv("RAPIDAPI_HOST", "")
DEFAULT_RAPIDAPI_URL = os.getenv("RAPIDAPI_URL", "")


def normalize_base_url(value: str) -> str:
    return value.rstrip("/")


def build_payload(phone_number: str) -> dict:
    return {
        "selector": DEFAULT_SELECTOR,
        "value": phone_number.strip(),
    }


def build_rapidapi_headers(api_key: str, host: str) -> dict:
    headers = {}
    if api_key:
        headers["X-RapidAPI-Key"] = api_key
    if host:
        headers["X-RapidAPI-Host"] = host
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a phone number to the local Looker investigation API."
    )
    parser.add_argument(
        "phone_number",
        nargs="?",
        help="Phone number to investigate. If omitted, you will be prompted.",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--api-path",
        default=DEFAULT_API_PATH,
        help=f"API path (default: {DEFAULT_API_PATH})",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("LOOKER_API_KEY", ""),
        help="API key for the Looker service. You can also set LOOKER_API_KEY.",
    )
    parser.add_argument(
        "--output",
        choices=("json", "pretty"),
        default="pretty",
        help="Output format.",
    )
    parser.add_argument(
        "--rapidapi-url",
        default=DEFAULT_RAPIDAPI_URL,
        help="Full RapidAPI endpoint URL. If set, the script calls RapidAPI instead of your local service.",
    )
    parser.add_argument(
        "--rapidapi-host",
        default=DEFAULT_RAPIDAPI_HOST,
        help="RapidAPI host header, for example truecaller4.p.rapidapi.com.",
    )
    args = parser.parse_args()

    phone_number = args.phone_number or input("Phone number: ").strip()
    if not phone_number:
        print("Phone number is required.", file=sys.stderr)
        return 2

    api_key = args.api_key.strip()
    if not api_key:
        prompt = "RapidAPI key" if args.rapidapi_url else "API key"
        api_key = getpass(f"{prompt} (hidden, press Enter if none): ").strip()

    if args.rapidapi_url:
        url = args.rapidapi_url.strip()
        headers = build_rapidapi_headers(api_key, args.rapidapi_host.strip())
    else:
        url = f"{normalize_base_url(args.base_url)}{args.api_path}"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["x-api-key"] = api_key

    try:
        if args.rapidapi_url:
            response = requests.get(url, headers=headers, params={"phone": phone_number}, timeout=60)
        else:
            response = requests.post(url, headers=headers, json=build_payload(phone_number), timeout=60)
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed with HTTP {response.status_code}", file=sys.stderr)
        try:
            print(response.text, file=sys.stderr)
        except Exception:
            pass
        return 1
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    data = response.json()
    if args.output == "json":
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    print(f"Status: {data.get('status', 'unknown')}")
    print(f"Input: {data.get('input', phone_number)}")

    extracted = data.get("extracted_intelligence", data)
    print("\nResult:")
    print(json.dumps(extracted, indent=2, ensure_ascii=False))

    case = data.get("case", {})
    if case:
        print("\nCase:")
        print(json.dumps(case, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
