# DevSecGuard AI 🛡️

**A real-time DevSecOps guardrail that scans every push for leaked secrets and vulnerabilities, and blocks the push when the risk is too high.**

Built for the **Nebius x NVIDIA Global AI Hackathon** · Track: **Coding and Agentic Engineering**

| | |
|---|---|
| **Models** | NVIDIA Nemotron (open source), served on **Nebius Token Factory** |
| **Live demo** | _add your Streamlit / Hugging Face Space URL here_ |
| **Demo video** | _add your YouTube URL here_ |
| **License** | [MIT](LICENSE) |

---

## The problem

Developers ship fast. API keys, passwords and injectable queries slip into version control, and classic static-analysis tools either drown teams in false positives or miss logic flaws that need context to understand. By the time a leaked key is noticed, it is already in the git history.

## What DevSecGuard AI does

Every file goes through two layers:

1. **Regex layer (instant, offline).** Detects hardcoded credentials such as AWS, Stripe, GitHub, Slack, Google, NVIDIA and OpenAI-style keys, private key blocks, and generic `password = "..."` assignments. It ignores placeholders, environment-variable reads and format-string interpolation.
2. **Nemotron layer (contextual reasoning).** NVIDIA Nemotron, running on Nebius Token Factory, reviews the code for SQL injection, command injection, `eval`/`exec`, unsafe deserialization, path traversal, weak validation and more, and returns structured JSON with a severity, an explanation and a suggested fix.

Findings are classified and enforced by a policy:

| Severity | Typical finding | Default action |
|---|---|---|
| CRITICAL | Live API keys, private keys, tokens | Block push |
| HIGH | SQL injection, command injection, RCE, auth bypass, hardcoded password | Block push |
| MEDIUM | Weak input validation, missing rate limiting | Warn (block with `--strict`) |
| LOW | Hardening and hygiene | Report |

**Secrets never leave your machine.** Anything the regex layer detects is replaced with `[REDACTED_SECRET]` before the code is sent to the model (this behaviour is covered by a unit test). If the model is unreachable, the regex layer still runs and still blocks.

## How NVIDIA Nemotron and Nebius Token Factory are used

- **Model:** an NVIDIA Nemotron model (auto-selected from your account, preferring Super, then Nano, then Ultra, or pinned with `NEBIUS_MODEL`) performs the semantic security review.
- **Infrastructure:** all inference goes through **Nebius Token Factory** (`https://api.tokenfactory.nebius.com/v1/`). Its OpenAI-compatible API lets a plain CI runner use a large open model with no GPU and no model hosting.
- **Strict JSON contract:** the prompt forces a single JSON object so results can drive an automated pass/fail decision. Reasoning traces (`<think>` blocks) and markdown fences are stripped before parsing.

## Architecture

```
 git push / pull request
          │
          ▼
 GitHub Actions  ──►  agent.py --repo .
                           │
            ┌──────────────┴───────────────┐
            ▼                              ▼
   Regex secret layer              Redact secrets, then send to
   (local, instant)                Nemotron on Nebius Token Factory
            │                              │
            └──────────────┬───────────────┘
                           ▼
              Merge + classify (critical/high/medium/low)
                           ▼
        exit 0 = pass   |   exit 1 = block the push
        console report · JSON report · GitHub job summary
```

## Quick start

```bash
git clone https://github.com/sherafganzafar/devsecguard-ai.git
cd devsecguard-ai
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # then put your key in .env (get one at tokenfactory.nebius.com)

python agent.py --list-models     # see which Nemotron models your key can use
python agent.py --demo            # scan a built-in vulnerable sample
```

### Command line

```bash
python agent.py --file app.py                    # one file
python agent.py --repo . --exclude tests         # a whole repository
python agent.py --repo . --fail-on critical      # only block on critical findings
python agent.py --repo . --strict                # block on medium and above
python agent.py --repo . --no-llm                # offline, regex layer only
python agent.py --repo . --json-out report.json  # machine-readable report
```

Exit codes: `0` passed · `1` push should be blocked · `2` usage or configuration error.

### Web demo

```bash
streamlit run app.py
```

Paste code, press **Scan code**, and see the report. To deploy it free, use Streamlit Community Cloud or a Hugging Face Space and add `NEBIUS_API_KEY` in the host's secrets settings (never in the repo). The demo limits input size and scans per session to protect your credits.

## GitHub Actions

`.github/workflows/security_scan.yml` runs the unit tests and then the scan on every push and pull request. Add your key once under **Settings → Secrets and variables → Actions → `NEBIUS_API_KEY`**. When a finding meets the threshold the job fails, which blocks the merge when branch protection requires the check. Each run publishes a summary table and a JSON report artifact. Pull requests from forks have no access to secrets, so they run with the regex layer only.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite runs offline with a fake model client. It covers the secret rules and placeholder handling, redaction before model calls, JSON parsing of model replies, model selection, merge and blocking logic, file collection and the command-line exit codes.

## Project layout

```
agent.py                      command line scanner and CI entry point
core.py                       scanning engine (regex layer, Nemotron layer, policy, reports)
app.py                        Streamlit web demo
tests/test_core.py            offline unit tests
.github/workflows/            CI workflow
requirements.txt, .env.example, LICENSE
```

## Limitations

- The model can miss issues or flag false positives, so treat its findings as an assistant to code review, not a replacement for it.
- Only the first 12,000 characters of each file are sent to the model, and `--repo` mode sends at most 20 files (`--max-llm-files`). The regex layer always covers every scanned file.
- Secrets already committed in older git history need to be rotated; this tool guards new pushes.

## Author

**Sherafgan Zafar** · [github.com/sherafganzafar](https://github.com/sherafganzafar)
