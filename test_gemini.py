import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("ERROR: GEMINI_API_KEY .env mein nahi mili.")
else:
    client = genai.Client(api_key=api_key)

    models_to_try = [
        "gemini-2.5-flash",
        "gemini-3.5-flash",
        "gemini-flash-lite-latest",
    ]

    for model_name in models_to_try:
        print(f"\nTesting: {model_name}")

        try:
            response = client.models.generate_content(
                model=model_name,
                contents=(
                    "You are a cybersecurity assistant. "
                    "Reply in one short sentence: "
                    "Cyber AI Assistant connection successful."
                ),
            )

            print("SUCCESS!")
            print(response.text)
            print(f"\nWorking model: {model_name}")
            break

        except Exception as e:
            print(f"Failed: {e}")

    else:
        print("\nNo model worked. Check the errors above.")