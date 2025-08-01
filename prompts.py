import os 
from dotenv import load_dotenv
from openai import OpenAI
class Prompts(): 

    @staticmethod
    def llm_call(prompt: str) -> str:
        """Makes a call to the DeepSeek API."""
        load_dotenv()
        api_key = os.getenv("DEEPSEEK_API_KEY")
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            stream=False
        )
        return response.choices[0].message.content

