# DevSecGuard AI 🛡️🤖

**DevSecGuard AI** is an advanced, AI-powered DevSecOps assistant and automated guardrail engine designed to secure code repositories in real-time. Powered by cutting-edge language models (Groq and Llama models), it automatically scans codebases for hardcoded credentials, API keys, and severe vulnerabilities, classifying risk levels and enforcing security compliance on every code push.

---

## 🚀 Key Features

* **AI-Powered Code Analysis:** Leverages LLMs to intelligently inspect source code files (`agent.py`) for security flaws and logical vulnerabilities.
* **Automated Secret Scanning & Prevention:** Detects sensitive credentials (like Stripe API keys and tokens) locally and within CI/CD pipelines to prevent accidental leakage.
* **Continuous Security Compliance (CI/CD):** Integrated seamlessly with GitHub Actions via automated security scan workflows (`security_scan.yml`).
* **Risk Severity Classification:** Automatically categorizes detected security risks and severity levels to prioritize remediation.
* **CLI & Script Support:** Includes modular core engines for local scanning (`agent.py`) and model utility management (`list_nvidia_models.py`).

---

## 📂 Project Architecture & File Structure

```text
devsecguard-ai/
├── .github/workflows/security_scan.yml   # Automated GitHub Actions workflow
├── agent.py                              # Core AI security scanning engine
├── list_nvidia_models.py                 # Model utility script
├── .gitignore                            # Git exclusion rules
└── README.md                             # Project documentation

```

---

## 🛠️ Tech Stack

* **Programming Language:** Python
* **AI & LLMs:** Groq API / Llama Models
* **DevSecOps & CI/CD:** GitHub Actions, Git Secret Scanning
* **Environment:** Linux / WSL (Ubuntu)

---

## ⚙️ Setup and Installation

To run or test the core engine locally in a development environment:

1. **Clone the Repository:**
```bash
git clone https://github.com/sherafganzafar/devsecguard-ai.git
cd devsecguard-ai

```


2. **Set up a Virtual Environment:**
```bash
python3 -m venv venv
source venv/bin/activate

```


3. **Run the Security Agent:**
```bash
python agent.py

```



---

## 🔒 Security & Compliance

DevSecGuard AI strictly adheres to modern DevSecOps standards:

* **Zero Hardcoded Secrets:** All sensitive API keys and tokens are purged from active code branches and managed via secure environment variables.
* **Automated Push Protection:** Integrated GitHub secret scanning safeguards repositories against accidental credential exposure.

---

## 👤 Author

* **Sherafgan Zafar**
* GitHub: [@sherafganzafar](https://www.google.com/search?q=https://github.com/sherafganzafar)

