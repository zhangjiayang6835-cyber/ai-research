import unittest

from fixes.ssrf_dns_rebinding_fix import (
    InvalidTargetURL,
    SSRFBlocked,
    is_public_ip,
    prepare_safe_request_target,
    validate_redirect_chain,
)


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


class SSRFDNSRebindingFixTests(unittest.TestCase):
    def test_prepares_ip_pinned_request_with_original_host_header(self) -> None:
        target = prepare_safe_request_target(
            "https://api.example.com/v1/memory?limit=10",
            resolver=lambda host, port: (PUBLIC_V4,),
        )

        self.assertEqual(target.connect_url, "https://93.184.216.34:443/v1/memory?limit=10")
        self.assertEqual(target.host_header, "api.example.com")
        self.assertEqual(target.server_hostname, "api.example.com")
        self.assertEqual(target.vetted_ip, PUBLIC_V4)
        self.assertEqual(target.port, 443)

    def test_custom_port_is_preserved_in_connect_url_and_host_header(self) -> None:
        target = prepare_safe_request_target(
            "http://api.example.com:8080/status",
            resolver=lambda _host, _port: (PUBLIC_V4,),
        )

        self.assertEqual(target.connect_url, "http://93.184.216.34:8080/status")
        self.assertEqual(target.host_header, "api.example.com:8080")
        self.assertEqual(target.port, 8080)

    def test_rejects_direct_private_loopback_and_metadata_addresses(self) -> None:
        for url in (
            "http://127.0.0.1/admin",
            "http://10.0.0.4/admin",
            "http://172.16.0.10/admin",
            "http://192.168.1.20/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/admin",
        ):
            with self.subTest(url=url):
                with self.assertRaises(SSRFBlocked):
                    prepare_safe_request_target(url)

    def test_rejects_hostname_that_resolves_to_private_address(self) -> None:
        with self.assertRaises(SSRFBlocked):
            prepare_safe_request_target(
                "https://attacker.example/fetch",
                resolver=lambda _host, _port: ("127.0.0.1",),
            )

    def test_rejects_mixed_public_private_resolution_set(self) -> None:
        with self.assertRaises(SSRFBlocked):
            prepare_safe_request_target(
                "https://rebind.example/fetch",
                resolver=lambda _host, _port: (PUBLIC_V4, "169.254.169.254"),
            )

    def test_resolver_is_called_once_and_client_receives_ip_target(self) -> None:
        calls = []

        def rebinding_resolver(host: str, port: int | None):
            calls.append((host, port))
            return (PUBLIC_V4,)

        target = prepare_safe_request_target(
            "https://rebind.example/data",
            resolver=rebinding_resolver,
        )

        self.assertEqual(calls, [("rebind.example", 443)])
        self.assertNotIn("rebind.example", target.connect_url)
        self.assertEqual(target.host_header, "rebind.example")

    def test_redirect_chain_revalidates_every_hop(self) -> None:
        def resolver(host: str, _port: int | None):
            if host == "safe.example":
                return (PUBLIC_V4,)
            if host == "internal.example":
                return ("10.0.0.5",)
            raise AssertionError(host)

        with self.assertRaises(SSRFBlocked):
            validate_redirect_chain(
                [
                    "https://safe.example/start",
                    "https://internal.example/admin",
                ],
                resolver=resolver,
            )

    def test_supports_public_ipv6_connect_url_brackets(self) -> None:
        target = prepare_safe_request_target(
            "https://ipv6.example/path",
            resolver=lambda _host, _port: (PUBLIC_V6,),
        )

        self.assertEqual(
            target.connect_url,
            "https://[2606:2800:220:1:248:1893:25c8:1946]:443/path",
        )
        self.assertEqual(target.vetted_ip, PUBLIC_V6)

    def test_rejects_invalid_url_shapes(self) -> None:
        for url in (
            "file:///etc/passwd",
            "gopher://example.com/_payload",
            "https://user:pass@example.com/private",
            "https:///missing-host",
            "http://example.com:99999/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(InvalidTargetURL):
                    prepare_safe_request_target(url, resolver=lambda _h, _p: (PUBLIC_V4,))

    def test_public_ip_classifier_blocks_reserved_and_private_ranges(self) -> None:
        self.assertTrue(is_public_ip(PUBLIC_V4))
        for address in ("0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.1.1", "224.0.0.1"):
            with self.subTest(address=address):
                self.assertFalse(is_public_ip(address))


if __name__ == "__main__":
    unittest.main()
