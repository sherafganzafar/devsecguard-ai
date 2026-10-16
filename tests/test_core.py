"""Offline tests: no network and no API key needed.

Fake secrets are assembled at runtime so no live-looking credential is stored in the repo.
Run with:  python -m unittest discover -s tests -v
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent  # noqa: E402
import core  # noqa: E402

STRIPE = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GITHUB = "ghp_" + "a" * 36
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"


class FakeClient:
    """Minimal stand-in for the OpenAI client."""

    def __init__(self, reply="", model_ids=(), fail=False):
        self._reply, self._ids, self._fail = reply, model_ids, fail
        self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id=i) for i in self._ids]))
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
        self.last_messages = None

    def _create(self, **kwargs):
        if self._fail:
            raise ConnectionError("boom")
        self.last_messages = kwargs["messages"]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self._reply))])


class SecretScanTests(unittest.TestCase):
    def test_detects_known_secret_formats_as_critical(self):
        for secret, name in ((STRIPE, "Stripe"), (AWS, "AWS"), (GITHUB, "GitHub"), (PRIVATE_KEY, "Private key")):
            with self.subTest(name=name):
                findings = core.scan_secrets(f"x = 1\nkey = '{secret}'\n")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "critical")
                self.assertEqual(findings[0].line, 2)
                self.assertIn(name.split()[0], findings[0].title)

    def test_snippet_never_contains_full_secret(self):
        finding = core.scan_secrets(f'STRIPE = "{STRIPE}"')[0]
        self.assertNotIn(STRIPE, finding.snippet)
        self.assertIn("********", finding.snippet)

    def test_generic_hardcoded_password_is_high(self):
        findings = core.scan_secrets('db_password = "Tr0ub4dor&3xyz"')
        self.assertEqual([f.severity for f in findings], ["high"])

    def test_generic_rule_handles_prefixed_names_and_json_style(self):
        for line in ('STRIPE_API_KEY = "Zx9Qw8Er7Ty6"', '"password": "hunter2hunter2"', "DB_PASSWORD='Tr0ub4dor&3xyz'"):
            with self.subTest(line=line):
                self.assertEqual([f.severity for f in core.scan_secrets(line)], ["high"])

    def test_generic_rule_ignores_unrelated_names(self):
        clean = 'tokenizer = "bert-base-uncased"\nmax_tokens = "1024abcdef"\nname = "some-long-value"\n'
        self.assertEqual(core.scan_secrets(clean), [])

    def test_placeholders_and_env_reads_are_ignored(self):
        clean = (
            'api_key = "your_api_key_here"\n'
            'token = "<paste token>"\n'
            'password = os.environ["DB_PASSWORD"]\n'
            'secret = os.getenv("SECRET", "fallback-value")\n'
            'password = f"{db_password}"\n'
            'api_key = "%s"\n'
        )
        self.assertEqual(core.scan_secrets(clean), [])

    def test_one_secret_produces_one_finding(self):
        findings = core.scan_secrets(f'api_key = "{STRIPE}"')
        self.assertEqual(len(findings), 1)
        self.assertIn("Stripe", findings[0].title)

    def test_redact_for_llm_removes_secret_and_keeps_line_numbers(self):
        text = f"a = 1\nkey = '{STRIPE}'\nb = 2"
        redacted = core.redact_for_llm(text)
        self.assertNotIn(STRIPE, redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)
        self.assertEqual(len(redacted.splitlines()), 3)


class LLMParsingTests(unittest.TestCase):
    def test_extract_json_handles_fences_think_blocks_and_prose(self):
        body = '{"findings":[{"severity":"high","title":"SQLi","line":3}]}'
        for reply in (body, f"```json\n{body}\n```", f"<think>hmm</think>\n{body}", f"Here you go: {body} Done."):
            with self.subTest(reply=reply[:20]):
                self.assertEqual(core.extract_json(reply)["findings"][0]["title"], "SQLi")

    def test_extract_json_rejects_garbage(self):
        with self.assertRaises(core.LLMError):
            core.extract_json("no json here")

    def test_normalize_clamps_bad_values(self):
        findings = core.normalize_findings(
            {"findings": [{"severity": "SEVERE", "title": "x", "line": "7"}, {"severity": "High", "line": 4}, "junk"]}
        )
        self.assertEqual([f.severity for f in findings], ["low", "high"])
        self.assertEqual([f.line for f in findings], [None, 4])
        self.assertTrue(all(f.source == "llm" for f in findings))

    def test_pick_model_prefers_super_then_nano_and_skips_non_chat(self):
        ids = ["meta/llama", "nvidia/nemotron-embed-1b", "nvidia/nemotron-3-nano-30b", "nvidia/nemotron-3-super-120b"]
        self.assertEqual(core.pick_model(FakeClient(model_ids=ids)), "nvidia/nemotron-3-super-120b")
        self.assertEqual(core.pick_model(FakeClient(model_ids=ids[:3])), "nvidia/nemotron-3-nano-30b")

    def test_pick_model_env_override_and_missing(self):
        os.environ["NEBIUS_MODEL"] = "custom/model"
        try:
            self.assertEqual(core.pick_model(FakeClient()), "custom/model")
        finally:
            del os.environ["NEBIUS_MODEL"]
        with self.assertRaises(core.LLMError):
            core.pick_model(FakeClient(model_ids=["meta/llama"]))


class ScanTextTests(unittest.TestCase):
    REPLY = '{"findings":[{"severity":"high","title":"SQL injection","line":3,"explanation":"e","fix":"f"}]}'

    def test_llm_findings_are_merged_and_sorted(self):
        client = FakeClient(reply=self.REPLY)
        text = f'x = 1\ny = 2\nq = "SELECT" % a\nk = "{STRIPE}"\n'
        result = core.scan_text(text, "f.py", client=client, model="m")
        self.assertTrue(result.llm_used)
        self.assertEqual([f.severity for f in result.findings], ["critical", "high"])

    def test_secret_is_never_sent_to_the_model(self):
        client = FakeClient(reply='{"findings":[]}')
        core.scan_text(f'k = "{STRIPE}"', "f.py", client=client, model="m")
        sent = " ".join(m["content"] for m in client.last_messages)
        self.assertNotIn(STRIPE, sent)

    def test_llm_failure_keeps_regex_results(self):
        result = core.scan_text(f'k = "{STRIPE}"', "f.py", client=FakeClient(fail=True), model="m")
        self.assertFalse(result.llm_used)
        self.assertIn("ConnectionError", result.llm_error)
        self.assertEqual(len(result.findings), 1)

    def test_bad_json_from_model_is_reported_not_fatal(self):
        result = core.scan_text("x = 1", "f.py", client=FakeClient(reply="sorry"), model="m")
        self.assertIn("not valid JSON", result.llm_error)

    def test_blocking_thresholds(self):
        high = [core.FileResult("a", [core.Finding("high", "t")])]
        self.assertTrue(core.is_blocked(high, "high"))
        self.assertFalse(core.is_blocked(high, "critical"))
        self.assertTrue(core.is_blocked([core.FileResult("a", [core.Finding("medium", "t")])], "medium"))
        self.assertFalse(core.is_blocked([core.FileResult("a", [])], "low"))


class FileCollectionTests(unittest.TestCase):
    def test_skips_vendor_dirs_and_respects_exclude(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in ("app.py", "venv/lib.py", "node_modules/x.js", "docs/skip.py", "notes.txt", "sub/ok.js"):
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as handle:
                    handle.write("x = 1\n")
            names = [os.path.relpath(p, root).replace(os.sep, "/") for p in core.collect_files(root, ["docs"])]
            self.assertEqual(names, ["app.py", "sub/ok.js"])


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = agent.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def _write(self, directory, name, text):
        path = os.path.join(directory, name)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def test_blocks_push_with_secret_and_passes_clean_code(self):
        with tempfile.TemporaryDirectory() as d:
            bad = self._write(d, "bad.py", f'KEY = "{STRIPE}"\n')
            good = self._write(d, "good.py", "def add(a, b):\n    return a + b\n")
            code, out, _ = self.run_cli("--file", bad, "--no-llm")
            self.assertEqual(code, 1)
            self.assertIn("RESULT: BLOCKED", out)
            self.assertNotIn(STRIPE, out)
            code, out, _ = self.run_cli("--file", good, "--no-llm")
            self.assertEqual(code, 0)
            self.assertIn("RESULT: PASSED", out)

    def test_repo_mode_writes_json_report(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "bad.py", f'KEY = "{AWS}"\n')
            report = os.path.join(d, "report.json")
            code, _, _ = self.run_cli("--repo", d, "--no-llm", "--json-out", report)
            self.assertEqual(code, 1)
            with open(report) as handle:
                self.assertIn('"blocked": true', handle.read())

    def test_missing_key_falls_back_to_regex_and_require_llm_fails(self):
        saved = os.environ.pop("NEBIUS_API_KEY", None)
        try:
            with tempfile.TemporaryDirectory() as d:
                good = self._write(d, "good.py", "x = 1\n")
                code, _, err = self.run_cli("--file", good)
                self.assertEqual(code, 0)
                self.assertIn("regex-only", err)
                code, _, _ = self.run_cli("--file", good, "--require-llm")
                self.assertEqual(code, 2)
        finally:
            if saved is not None:
                os.environ["NEBIUS_API_KEY"] = saved

    def test_missing_file_is_a_config_error(self):
        code, _, err = self.run_cli("--file", "/no/such/file.py", "--no-llm")
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_demo_is_blocked_offline(self):
        code, out, _ = self.run_cli("--demo", "--no-llm")
        self.assertEqual(code, 1)
        self.assertIn("Stripe live secret key", out)


if __name__ == "__main__":
    unittest.main()
