# etherhiding-list

Pi-hole blocklist for blockchain JSON-RPC domains (sourced daily from [Chainlist](https://chainlist.org/rpcs.json)) to help mitigate [EtherHiding](https://cloud.google.com/blog/topics/threat-intelligence/unc5142-etherhiding-distribute-malware) and unauthorized blockchain C2 / RPC traffic. Made using Google Gemini.

## Usage in Pi-hole

Add the following raw list URL to your Pi-hole under **Adlists** (or **Lists** in Pi-hole v6), then update Gravity (`pihole -g`):

```text
https://raw.githubusercontent.com/ForensicITGuy/etherhiding-list/main/domains.txt
```

## How It Works

A GitHub Action ([`.github/workflows/update-domains.yml`](.github/workflows/update-domains.yml)) runs daily at `00:00 UTC` (and on manual `workflow_dispatch`):
1. Runs the unit test suite (`tests/test_update_domains.py`).
2. Executes `update_domains.py` to download `https://chainlist.org/rpcs.json`.
3. Extracts all RPC URLs (both string and object formats across HTTP/HTTPS/WS/WSS).
4. Normalizes, validates, deduplicates, and sorts the domain names (excluding raw IPs, `localhost`, and template placeholders).
5. Saves the resulting Pi-hole compatible plain domain list to `domains.txt` and commits any changes back to the repository.

## Local Development

Generate `domains.txt` locally:

```bash
python3 update_domains.py
```

Run the unit tests:

```bash
python3 -m unittest discover -s tests -v
```
