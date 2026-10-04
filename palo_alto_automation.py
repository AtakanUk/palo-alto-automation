"""Palo Alto Networks response actions for SOAR playbooks.

* Prisma Access: add/remove domains in a custom URL category through the Strata
  Cloud Manager configuration API (OAuth2 client credentials, TSG-scoped token).
* NGFW: maintain the IP list file that the firewalls pull as an External
  Dynamic List (EDL) from a web server.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Any

import requests

log = logging.getLogger("palo_alto_automation")

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
API_BASE = "https://api.sase.paloaltonetworks.com/sse/config/v1"
URL_LIST_KEYS = ("list", "items", "urls", "url_list", "sites", "members")


@dataclass
class PrismaSettings:
    client_id: str
    client_secret: str
    tsg_id: str
    category_id: str | None = None
    folder: str = "Prisma Access"
    edl_path: str = "ip_list.txt"

    @classmethod
    def from_env(cls) -> PrismaSettings:
        return cls(
            client_id=os.getenv("PRISMA_CLIENT_ID", "").strip(),
            client_secret=os.getenv("PRISMA_CLIENT_SECRET", "").strip(),
            tsg_id=os.getenv("PRISMA_TSG_ID", "").strip(),
            category_id=os.getenv("PRISMA_CATEGORY_ID", "").strip() or None,
            folder=os.getenv("PRISMA_FOLDER", "Prisma Access").strip(),
            edl_path=os.getenv("EDL_PATH", "ip_list.txt").strip(),
        )

    def validate(self) -> None:
        missing = [
            name
            for name, value in (
                ("PRISMA_CLIENT_ID", self.client_id),
                ("PRISMA_CLIENT_SECRET", self.client_secret),
                ("PRISMA_TSG_ID", self.tsg_id),
            )
            if not value
        ]
        if missing:
            raise SystemExit(f"Missing configuration: {', '.join(missing)}")


def split_items(raw: str) -> list[str]:
    return list(
        dict.fromkeys(
            item.strip().lower() for item in raw.replace(";", ",").split(",") if item.strip()
        )
    )


def find_url_list_key(category: dict[str, Any]) -> str:
    """Name of the URL list field (it differs between API versions)."""
    for key in URL_LIST_KEYS:
        if isinstance(category.get(key), list):
            return key
    for key, value in category.items():
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return key
    raise RuntimeError("URL category has no URL list field")


class PrismaAccessClient:
    def __init__(self, settings: PrismaSettings, session: requests.Session | None = None) -> None:
        settings.validate()
        self.settings = settings
        self.session = session or requests.Session()
        self._token: str | None = None

    def token(self) -> str:
        if self._token is None:
            response = self.session.post(
                AUTH_URL,
                data={
                    "grant_type": "client_credentials",
                    "scope": f"tsg_id:{self.settings.tsg_id}",
                },
                auth=(self.settings.client_id, self.settings.client_secret),
                timeout=30,
            )
            response.raise_for_status()
            self._token = response.json().get("access_token")
            if not self._token:
                raise RuntimeError("Token response has no access_token")
        return self._token

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
        if "json" in kwargs:
            headers["Content-Type"] = "application/json"
        response = self.session.request(
            method, f"{API_BASE}{path}", headers=headers, timeout=30, **kwargs
        )
        if not response.ok:
            log.error(
                "%s %s -> HTTP %s %s", method, path, response.status_code, response.text[:1000]
            )
        response.raise_for_status()
        return response.json() if response.content else {}

    def list_categories(self, page_size: int = 200) -> list[dict[str, Any]]:
        categories: list[dict[str, Any]] = []
        while True:
            page = self._request(
                "GET",
                "/url-categories",
                params={
                    "folder": self.settings.folder,
                    "limit": page_size,
                    "offset": len(categories),
                },
            )
            data = page.get("data", [])
            categories.extend(data)
            if len(data) < page_size or len(categories) >= page.get("total", len(categories)):
                return categories

    def get_category(self, category_id: str) -> dict[str, Any]:
        body = self._request("GET", f"/url-categories/{category_id}")
        return body["data"] if isinstance(body.get("data"), dict) else body

    def update_domains(self, category_id: str, raw_domains: str, action: str) -> dict[str, Any]:
        if action not in ("add", "remove"):
            raise ValueError("action must be 'add' or 'remove'")
        requested = split_items(raw_domains)
        if not requested:
            raise ValueError("No domain given")
        category = self.get_category(category_id)
        key = find_url_list_key(category)
        current = list(category.get(key) or [])

        if action == "add":
            changed = [item for item in requested if item not in current]
            category[key] = sorted(set(current) | set(changed))
            unchanged_label = "already_present"
        else:
            changed = [item for item in requested if item in current]
            category[key] = sorted(set(current) - set(changed))
            unchanged_label = "not_found"

        if changed:
            self._request("PUT", f"/url-categories/{category_id}", json=category)
        log.info(
            "%s %d domain(s) in category %s",
            "Added" if action == "add" else "Removed",
            len(changed),
            category.get("name", category_id),
        )
        return {
            "action": action,
            "changed": changed,
            unchanged_label: [item for item in requested if item not in changed],
            "total_after": len(category[key]),
        }


def _write_atomic(path: str, lines: list[str]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".edl-")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("".join(f"{line}\n" for line in lines))
    os.replace(tmp, path)


def update_edl(path: str, raw_ips: str, action: str) -> dict[str, Any]:
    """Add or remove IPs/networks in the EDL file; invalid entries are reported, never written."""
    valid, invalid = [], []
    for item in split_items(raw_ips):
        try:
            network = ipaddress.ip_network(item, strict=False)
            valid.append(
                str(network.network_address) if network.num_addresses == 1 else str(network)
            )
        except ValueError:
            invalid.append(item)

    try:
        with open(path, encoding="utf-8") as handle:
            current = [line.strip() for line in handle if line.strip()]
    except FileNotFoundError:
        current = []

    if action == "add":
        changed = [ip for ip in valid if ip not in current]
        updated = current + changed
    else:
        changed = [ip for ip in valid if ip in current]
        updated = [ip for ip in current if ip not in changed]
    if changed:
        _write_atomic(path, updated)
    return {"action": action, "changed": changed, "invalid": invalid, "total_after": len(updated)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prisma Access URL categories and firewall EDL management"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-categories")
    get = commands.add_parser("get-category")
    get.add_argument("--category-id")
    for name in ("add-domains", "remove-domains"):
        sub = commands.add_parser(name)
        sub.add_argument("--category-id")
        sub.add_argument("--domains", required=True, help="comma-separated domains or URL patterns")
    for name in ("edl-add", "edl-remove"):
        sub = commands.add_parser(name)
        sub.add_argument("--ips", required=True, help="comma-separated IPs or networks")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = PrismaSettings.from_env()

    if args.command in ("edl-add", "edl-remove"):
        result: Any = update_edl(
            settings.edl_path, args.ips, "add" if args.command == "edl-add" else "remove"
        )
    else:
        client = PrismaAccessClient(settings)
        category_id = getattr(args, "category_id", None) or settings.category_id
        if args.command == "list-categories":
            result = [
                {"id": c.get("id"), "name": c.get("name"), "type": c.get("type")}
                for c in client.list_categories()
            ]
        elif not category_id:
            raise SystemExit("A category ID is required (--category-id or PRISMA_CATEGORY_ID)")
        elif args.command == "get-category":
            result = client.get_category(category_id)
        else:
            result = client.update_domains(
                category_id, args.domains, "add" if args.command == "add-domains" else "remove"
            )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
