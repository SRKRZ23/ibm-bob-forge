"""
Vulnerable LLM Application - Demo for FORGE
Contains intentional security vulnerabilities across OWASP LLM Top 10
"""

import openai
import os
import subprocess
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ❌ LLM06: Hardcoded API key
openai.api_key = "sk-proj-DEMO123456789abcdefghijklmnopqrstuvwxyz"

# ❌ LLM05: Unpinned dependency (see requirements.txt)

@app.route('/chat', methods=['POST'])
def chat():
    """Chat endpoint with multiple vulnerabilities."""
    user_message = request.json.get('message', '')
    
    # ❌ LLM01: Prompt injection - unsanitized user input
    prompt = f"You are a helpful assistant. User says: {user_message}"
    
    # ❌ LLM04: No rate limiting, no timeout
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=None  # No limit!
    )
    
    output = response.choices[0].message.content
    
    # ❌ LLM02: Insecure output handling - direct HTML rendering
    return f"<html><body><p>{output}</p></body></html>"


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze user data - PII exposure."""
    data = request.json
    name = data.get('name', '')
    email = data.get('email', '')
    ssn = data.get('ssn', '')
    credit_card = data.get('credit_card', '')
    
    # ❌ LLM06: PII in prompts
    prompt = f"""
    Analyze this user profile:
    Name: {name}
    Email: {email}
    SSN: {ssn}
    Credit Card: {credit_card}
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    # ❌ LLM06: PII in logs
    print(f"Analyzed user: {name}, SSN: {ssn}, CC: {credit_card}")
    
    return jsonify({"analysis": response.choices[0].message.content})


@app.route('/execute', methods=['POST'])
def execute():
    """Execute commands - excessive agency."""
    command = request.json.get('command', '')
    
    # Get LLM to generate command
    prompt = f"Generate a bash command to: {command}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    llm_command = response.choices[0].message.content
    
    # ❌ LLM08: Unrestricted command execution
    result = subprocess.run(
        llm_command,
        shell=True,  # DANGEROUS!
        capture_output=True,
        text=True,
        timeout=None  # No timeout!
    )
    
    return jsonify({
        "command": llm_command,
        "output": result.stdout,
        "error": result.stderr
    })


@app.route('/fetch', methods=['POST'])
def fetch():
    """Fetch URL - network vulnerability."""
    url = request.json.get('url', '')
    
    # ❌ LLM08: Unrestricted network access
    try:
        response = requests.get(url, timeout=None)  # No timeout!
        return jsonify({"content": response.text})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/file', methods=['POST'])
def file_operation():
    """File operations - filesystem vulnerability."""
    operation = request.json.get('operation', '')
    path = request.json.get('path', '')
    content = request.json.get('content', '')
    
    # ❌ LLM08: Unrestricted file system access
    if operation == 'read':
        with open(path, 'r') as f:
            return jsonify({"content": f.read()})
    elif operation == 'write':
        with open(path, 'w') as f:
            f.write(content)
        return jsonify({"status": "written"})
    elif operation == 'delete':
        os.remove(path)
        return jsonify({"status": "deleted"})


@app.route('/sql', methods=['POST'])
def sql_query():
    """SQL query - injection vulnerability."""
    user_query = request.json.get('query', '')
    
    # Get LLM to generate SQL
    prompt = f"Generate SQL query for: {user_query}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    sql = response.choices[0].message.content
    
    # ❌ LLM02: SQL injection via LLM output
    # In real app: db.execute(sql)  # DANGEROUS!
    
    return jsonify({"sql": sql})


if __name__ == '__main__':
    # ❌ Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
