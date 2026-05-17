"""
Sample OpenAI-based application with security vulnerabilities.
This demonstrates common LLM security issues that FORGE detects.
"""

import openai
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ❌ VULNERABILITY: LLM06 - Hardcoded API key
openai.api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"

@app.route('/')
def index():
    return '''
    <html>
        <body>
            <h1>AI Summarizer</h1>
            <form action="/summarize" method="post">
                <textarea name="text" rows="10" cols="50"></textarea><br>
                <input type="submit" value="Summarize">
            </form>
        </body>
    </html>
    '''

@app.route('/summarize', methods=['POST'])
def summarize():
    user_text = request.form.get('text', '')
    
    # ❌ VULNERABILITY: LLM01 - Prompt injection (unsanitized user input)
    prompt = f"Summarize the following text: {user_text}"
    
    # ❌ VULNERABILITY: LLM04 - No rate limiting or timeout
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=None  # No token limit!
    )
    
    llm_output = response.choices[0].message.content
    
    # ❌ VULNERABILITY: LLM02 - Insecure output handling (XSS)
    return f'''
    <html>
        <body>
            <h1>Summary</h1>
            <div>{llm_output}</div>
            <a href="/">Back</a>
        </body>
    </html>
    '''

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze user data - demonstrates PII exposure."""
    name = request.form.get('name', '')
    email = request.form.get('email', '')
    ssn = request.form.get('ssn', '')
    
    # ❌ VULNERABILITY: LLM06 - PII in prompts
    prompt = f"Analyze this user profile: Name: {name}, Email: {email}, SSN: {ssn}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    # ❌ VULNERABILITY: LLM06 - PII in logs
    print(f"Analyzed user: {name}, SSN: {ssn}")
    
    return response.choices[0].message.content

@app.route('/execute', methods=['POST'])
def execute():
    """Execute commands - demonstrates excessive agency."""
    user_command = request.form.get('command', '')
    
    # Get LLM to generate system command
    prompt = f"Generate a bash command to: {user_command}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    command = response.choices[0].message.content
    
    # ❌ VULNERABILITY: LLM08 - Unrestricted command execution
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return f"Output: {result.stdout}\nError: {result.stderr}"

if __name__ == '__main__':
    # ❌ VULNERABILITY: Running in debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
