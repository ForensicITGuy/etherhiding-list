# etherhiding-list

Pi-hole blocklist for blockchain JSON-RPC domains (sourced daily from [Chainlist](https://chainlist.org/rpcs.json)) to help mitigate [EtherHiding](https://cloud.google.com/blog/topics/threat-intelligence/unc5142-etherhiding-distribute-malware) and unauthorized blockchain C2 / RPC traffic. Made using Google Gemini.

## Usage in Pi-hole / Sinkholes

Add either of the following raw list URLs to your Pi-hole under **Adlists** (or **Lists** in Pi-hole v6) or your DNS sinkhole, then update Gravity (`pihole -g`):

- **Plain domain list** (one domain per line):
  ```text
  https://raw.githubusercontent.com/ForensicITGuy/etherhiding-list/main/domains.txt
  ```
- **Hosts file format** (`0.0.0.0 <domain>`):
  ```text
  https://raw.githubusercontent.com/ForensicITGuy/etherhiding-list/main/hosts.txt
  ```

## How It Works

A GitHub Action ([`.github/workflows/update-domains.yml`](.github/workflows/update-domains.yml)) runs daily at `00:00 UTC` (and on manual `workflow_dispatch`):
1. Runs the unit test suite (`tests/test_update_domains.py`).
2. Executes `update_domains.py` to download `https://chainlist.org/rpcs.json`.
3. Extracts all RPC URLs (both string and object formats across HTTP/HTTPS/WS/WSS).
4. Normalizes, validates, deduplicates, and sorts the domain names (excluding raw IPs, `localhost`, and template placeholders).
5. Compares the extracted domains against the existing `domains.txt` and `hosts.txt`. If domains were added or removed, writes the updated lists with a new `# Last updated:` UTC timestamp and commits the changes; if the domain list is unchanged, leaves the files and their timestamps untouched.

## Local Development

Generate `domains.txt` and `hosts.txt` locally:

```bash
python3 update_domains.py
```

Run the unit tests:

```bash
python3 -m unittest discover -s tests -v
```
