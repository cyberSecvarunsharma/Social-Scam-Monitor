import requests
import json


class LLMScamAnalyzer:

    def __init__(self):
        self.url = "http://localhost:11434/api/generate"
        self.model = "llama3.2:3b"

    def analyze(self, text):

        prompt = f"""
You are a cyber fraud analyst.

Analyze the text and return ONLY valid JSON.

Text:
{text}

Format:

{{
    "risk_level":"LOW",
    "confidence":0,
    "reason":"..."
}}
"""

        try:

            response = requests.post(
                self.url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )

            result = response.json()["response"]

            return json.loads(result)

        except Exception as e:

            return {
                "risk_level": "LOW",
                "confidence": 0,
                "reason": str(e)
            }
