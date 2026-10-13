import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=os.environ.get("NVIDIA_API_KEY")
)

print("🔑 Fetching valid models for your NVIDIA API key...\n")
models = client.models.list()
for model in models.data:
    print(f" - {model.id}")
