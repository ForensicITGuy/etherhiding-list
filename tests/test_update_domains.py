import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from update_domains import (
    extract_domain,
    extract_domains_from_chainlist,
    format_blocklist,
    main,
)


class TestExtractDomain(unittest.TestCase):
    def test_standard_protocols(self):
        self.assertEqual(extract_domain("https://eth.llamarpc.com"), "eth.llamarpc.com")
        self.assertEqual(extract_domain("http://rpc.ankr.com/eth"), "rpc.ankr.com")
        self.assertEqual(
            extract_domain("wss://ethereum-rpc.publicnode.com"),
            "ethereum-rpc.publicnode.com",
        )
        self.assertEqual(
            extract_domain("ws://rpc.flashbots.net:8545/ws"), "rpc.flashbots.net"
        )

    def test_schemeless_and_ports_and_credentials(self):
        self.assertEqual(extract_domain("rpc.example.com/v1"), "rpc.example.com")
        self.assertEqual(
            extract_domain("https://user:pass@node.example.org:8545/rpc?key=1"),
            "node.example.org",
        )

    def test_normalization_case_and_trailing_dot(self):
        self.assertEqual(
            extract_domain("  HTTPS://MainNet.Infura.IO./v3/abc  "),
            "mainnet.infura.io",
        )

    def test_template_in_path_allowed_but_template_in_host_rejected(self):
        self.assertEqual(
            extract_domain("https://mainnet.infura.io/v3/${INFURA_API_KEY}"),
            "mainnet.infura.io",
        )
        self.assertIsNone(extract_domain("https://${SUBDOMAIN}.example.com/rpc"))
        self.assertIsNone(extract_domain("https://{tenant}.example.com/rpc"))

    def test_rejects_ips_and_localhost(self):
        self.assertIsNone(extract_domain("http://localhost:8545"))
        self.assertIsNone(extract_domain("http://0.0.0.0:8545"))
        self.assertIsNone(extract_domain("http://127.0.0.1:8545"))
        self.assertIsNone(extract_domain("https://192.168.1.100/rpc"))
        self.assertIsNone(extract_domain("http://[::1]:8545"))
        self.assertIsNone(extract_domain("https://[2001:db8::1]:8545/rpc"))

    def test_rejects_invalid_domains(self):
        self.assertIsNone(extract_domain(""))
        self.assertIsNone(extract_domain("   "))
        self.assertIsNone(extract_domain(None))  # type: ignore[arg-type]
        self.assertIsNone(extract_domain("https://-badlabel.example.com"))
        self.assertIsNone(extract_domain("https://badlabel-.example.com"))
        self.assertIsNone(extract_domain("https://singlelabelonly"))

    def test_supports_idn_and_punycode(self):
        self.assertEqual(
            extract_domain("https://rpc.münchen.de/eth"),
            "rpc.xn--mnchen-3ya.de",
        )
        self.assertEqual(
            extract_domain("https://node.example.xn--p1ai"),
            "node.example.xn--p1ai",
        )


class TestExtractDomainsFromChainlist(unittest.TestCase):
    def test_extracts_and_deduplicates_mixed_entries(self):
        sample_data = [
            {
                "name": "Ethereum Mainnet",
                "chainId": 1,
                "rpc": [
                    "https://eth.llamarpc.com",
                    {"url": "https://ETH.LLAMARPC.COM/v1", "tracking": "none"},
                    {"url": "wss://mainnet.infura.io/ws/v3/${INFURA_API_KEY}"},
                    {"url": "http://127.0.0.1:8545"},
                    {},
                    123,
                ],
            },
            {
                "name": "BNB Smart Chain",
                "chainId": 56,
                "rpc": [
                    "https://bsc-dataseed.binance.org/",
                    {"url": "https://rpc.ankr.com/bsc"},
                ],
            },
            {"name": "Chain Without RPCs"},
            "invalid-chain-entry",
        ]

        result = extract_domains_from_chainlist(sample_data)
        self.assertEqual(
            result,
            [
                "bsc-dataseed.binance.org",
                "eth.llamarpc.com",
                "mainnet.infura.io",
                "rpc.ankr.com",
            ],
        )

    def test_raises_on_non_list_input(self):
        with self.assertRaises(ValueError):
            extract_domains_from_chainlist({"not": "a list"})  # type: ignore[arg-type]


class TestFormatAndMain(unittest.TestCase):
    def test_format_blocklist(self):
        output = format_blocklist(
            ["a.example.com", "b.example.com"],
            source_url="https://chainlist.org/rpcs.json",
        )
        expected = (
            "# Pi-hole Blocklist: Blockchain JSON-RPC Endpoints (Chainlist)\n"
            "# Source: https://chainlist.org/rpcs.json\n"
            "# Total domains: 2\n"
            "\n"
            "a.example.com\n"
            "b.example.com\n"
        )
        self.assertEqual(output, expected)

    @patch("update_domains.fetch_chainlist_data")
    def test_main_writes_output_file(self, mock_fetch):
        mock_fetch.return_value = [
            {"rpc": ["https://rpc.ankr.com/eth", {"url": "https://eth.llamarpc.com"}]}
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "domains.txt"
            exit_code = main(["--output", str(out_file)])
            self.assertEqual(exit_code, 0)
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("eth.llamarpc.com\nrpc.ankr.com\n", content)

    @patch("update_domains.fetch_chainlist_data")
    def test_main_raises_when_no_domains_extracted(self, mock_fetch):
        mock_fetch.return_value = [{"rpc": ["http://127.0.0.1:8545"]}]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "domains.txt"
            with self.assertRaises(RuntimeError):
                main(["--output", str(out_file)])


if __name__ == "__main__":
    unittest.main()
