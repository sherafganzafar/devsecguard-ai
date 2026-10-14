import os
import sys
import argparse
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def get_working_model():
    try:
        models = client.models.list()
        for m in models.data:
            mid = m.id.lower()
            if "llama" in mid and "guard" not in mid and "/" not in mid:
                return m.id
        for m in models.data:
            if "/" not in m.id and "whisper" not in m.id:
                return m.id
        return models.data[0].id
    except Exception:
        return "llama-3.3-70b-versatile"

def analyze_vulnerability(code_snippet):
    model_name = get_working_model()
    print(f"⚙️ Using Active Model: {model_name}\n")
    
    prompt = f"""
    You are DevSecGuard AI, an expert CI/CD DevSecOps AI Agent.
    Analyze the following code for security vulnerabilities, hardcoded credentials, or risky patterns:
    
    Code:
    ```python
    {code_snippet}
    ```
    
    Provide:
    1. Vulnerability Severity (Low, Medium, High, Critical)
    2. Explanation of the risk
    3. Suggested Fix / Patch
    """

    completion = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=800,
    )

    return completion.choices[0].message.content

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DevSecGuard AI Security Scanner")
    parser.add_argument("--file", type=str, help="Path to the python file to scan", default="")
    args = parser.parse_args()

    if args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                code_to_scan = f.read()
            print(f"🔍 Scanning file: {args.file}...\n")
        else:
            print(f"❌ Error: File '{args.file}' not found.")
            sys.exit(1)
    else:
  # Default sample code agar file na di jaye
    code_to_scan = """
    import requests
    def fetch_data():
        api_key = "your_stripe_key_here"
        response = requests.get(f"https://api.example.com/data?key={api_key}")
        return response.json()
    """
    print(f"🔍 Scanning Default Sample Code...\n")

    report = analyze_vulnerability(code_to_scan)
    print("📋 Security Report:\n")
    print(report)
