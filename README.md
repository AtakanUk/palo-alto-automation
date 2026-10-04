# Palo Alto Automation

[![CI](https://github.com/AtakanUk/palo-alto-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/AtakanUk/palo-alto-automation/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Response actions for Palo Alto Networks environments, built to be called from SOAR playbooks:

- **Prisma Access**: add or remove domains in a custom URL category through the Strata Cloud Manager configuration API, so remote users are blocked at the SASE edge.
- **NGFW**: maintain the IP list that the firewalls pull as an External Dynamic List (EDL) from an internal web server, so on-prem traffic to and from an attacker is blocked within the EDL refresh interval.

```bash
python palo_alto_automation.py add-domains --domains "bad.example, phishing.example"
python palo_alto_automation.py edl-add --ips "198.51.100.23, 203.0.113.0/24"
```

## Details

- OAuth2 client credentials with a TSG-scoped token, fetched once per run.
- URL categories are updated read-modify-write. The URL list field is detected by name (`list`, `items`, ...), because it differs between API versions, and nothing is written when no change is needed.
- Results show exactly what changed (`changed`, `already_present` / `not_found`, `total_after`), so the playbook can write an accurate note.
- EDL entries are validated as IPs or networks before they are written, and invalid input is reported. The file is replaced atomically, so a firewall fetching the list never sees a partial file.
- `list-categories` follows pagination.

For time-limited blocks, combine this with [firewall-unban-scheduler](../firewall-unban-scheduler), which removes the entries again when the block expires.

## Configuration

| Variable | Description |
| --- | --- |
| `PRISMA_CLIENT_ID`, `PRISMA_CLIENT_SECRET` | Service account (needs configuration write access) |
| `PRISMA_TSG_ID` | Tenant service group ID |
| `PRISMA_CATEGORY_ID` | Default URL category |
| `PRISMA_FOLDER` | Configuration folder for listing (default `Prisma Access`) |
| `EDL_PATH` | EDL file on the web server, e.g. `/var/www/html/edl/blocked_ips.txt` |

Configuration changes in Prisma Access take effect after a push. Pushing can be done by the existing change process or from the Strata Cloud Manager UI.

## Usage

```bash
pip install -r requirements.txt

python palo_alto_automation.py list-categories
python palo_alto_automation.py get-category --category-id <uuid>
python palo_alto_automation.py add-domains --domains bad.example
python palo_alto_automation.py remove-domains --domains bad.example
python palo_alto_automation.py edl-add --ips 198.51.100.23
python palo_alto_automation.py edl-remove --ips 198.51.100.23
```

## Tests

```bash
pip install pytest
pytest
```

## License

[MIT](LICENSE)
