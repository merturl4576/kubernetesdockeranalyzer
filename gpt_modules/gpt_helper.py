import os     #It uses operating system variables to get the API key from the .env file.
import openai
from dotenv import load_dotenv    #Loads variables from the .env file into the Python environment
from models.finding import Finding

load_dotenv()   #Reads the .env file, you can call it with os.getenv(“OPENAI_API_KEY”).

def get_gpt_suggestions(content):
    try:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            raise ValueError("OpenAI API key is missing in .env file.")

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # or gpt-4 if you have access
            messages=[
                {"role": "system", "content": "You're a container security expert. Provide recommendations."},
                {"role": "user", "content": f"Analyze this Dockerfile or Kubernetes YAML and give 3 security hardening suggestions:\n\n{content}"}
            ]
        )

        suggestions = response.choices[0].message.content.strip().split("\n")  
        #  gpt can answer differently response.choices[0] will take the first response   
        #  message.content → Get the actual text of that reply 
        # .strip() → Remove first and last spaces so it will fit nicely as a response
        # .split(“\n”) → Convert to a line-by-line list

        findings = []   #Simply starts an empty list.
        #Goal: Turn every suggestion into a "Finding" object and put it in this list.

        for s in suggestions:    #Loop for each row
            suggestion_text = s.strip("- ").strip()   #Removes the "-"" and space characters at the beginning of a string:  “ - Avoid root” → ”Avoid root”

            # Determine severity based on keywords
            if "root" in suggestion_text.lower() or "password" in suggestion_text.lower():
                level = "HIGH"
            elif "version" in suggestion_text.lower():
                level = "MEDIUM"
            else:
                level = "LOW"

            findings.append(Finding(level, "GPT Suggestion", suggestion_text))

        return findings  #The purpose of the function is to export these findings

    except Exception as e:  #Catches most types of errors and does not let the program crush but an detailed else print gpt error
        print(f"[GPT ERROR] {e}")
        return []   #this means that It couldn't get data from the GPT, but the system doesn't crash, so the function should continue to work