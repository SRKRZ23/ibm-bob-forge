"""
Pytest configuration and shared fixtures for FORGE test suite.
"""
import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def empty_repo(tmp_path):
    """Create an empty repository directory."""
    repo = tmp_path / "empty_repo"
    repo.mkdir()
    return repo


@pytest.fixture
def repo_with_openai(tmp_path):
    """Create a repository with OpenAI SDK calls."""
    repo = tmp_path / "openai_repo"
    repo.mkdir()
    
    (repo / "app.py").write_text('''
import openai

def generate_summary(user_input):
    """Generate summary using OpenAI."""
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Summarize: {user_input}"}]
    )
    return response.choices[0].message.content
''')
    
    (repo / "config.py").write_text('''
# Configuration file
api_key = "sk-proj-abc123xyz789abcdefghijklmnop"
MODEL = "gpt-4"
''')
    
    return repo


@pytest.fixture
def repo_with_anthropic(tmp_path):
    """Create a repository with Anthropic SDK calls."""
    repo = tmp_path / "anthropic_repo"
    repo.mkdir()
    
    (repo / "claude_app.py").write_text('''
import anthropic

client = anthropic.Anthropic(api_key="sk-ant-xyz")

def chat(message):
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        messages=[{"role": "user", "content": message}]
    )
    return response.content[0].text
''')
    
    return repo


@pytest.fixture
def repo_with_langchain(tmp_path):
    """Create a repository with LangChain usage."""
    repo = tmp_path / "langchain_repo"
    repo.mkdir()
    
    (repo / "agent.py").write_text('''
from langchain import LLMChain, PromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.agents import AgentExecutor, Tool
import subprocess

llm = ChatOpenAI(temperature=0)

def execute_command(cmd):
    """Execute system command - LLM08 risk."""
    return subprocess.run(cmd, shell=True, capture_output=True)

tools = [
    Tool(name="Execute", func=execute_command, description="Run commands")
]

prompt = PromptTemplate(
    input_variables=["user_input"],
    template="Process: {user_input}"
)

chain = LLMChain(llm=llm, prompt=prompt)
''')
    
    return repo


@pytest.fixture
def repo_with_vulnerabilities(tmp_path):
    """Create a repository with multiple vulnerability types."""
    repo = tmp_path / "vuln_repo"
    repo.mkdir()
    
    # LLM01: Prompt injection
    (repo / "injection.py").write_text('''
def process_query(user_input):
    prompt = f"Answer this: {user_input}"  # LLM01
    return llm.complete(prompt)

def format_prompt(query):
    return "System: " + query  # LLM01: concat
''')
    
    # LLM02: Insecure output handling
    (repo / "output.py").write_text('''
def get_response():
    response = openai.ChatCompletion.create(...)
    return response.choices[0].message.content  # LLM02: no validation
''')
    
    # LLM04: DoS risk
    (repo / "dos.py").write_text('''
while True: response = llm.chat.completions.create(...)  # LLM04: unbounded loop
''')
    
    # LLM05: Supply chain
    (repo / "imports.py").write_text('''
from langchain import *  # LLM05: unpinned import
import llama_index
''')
    
    # LLM06: Credential exposure
    (repo / "secrets.py").write_text('''
API_KEY = "sk-proj-1234567890abcdef"  # LLM06: hardcoded key
PASSWORD = "admin123"
SSN_TEMPLATE = f"SSN: {user_ssn}"  # LLM06: PII in template
''')
    
    # LLM08: Excessive agency
    (repo / "agent.py").write_text('''
import os
import subprocess

def run_command(cmd):
    os.system(cmd)  # LLM08: dangerous exec
    subprocess.run(["rm", "-rf", path])  # LLM08
''')
    
    return repo


@pytest.fixture
def repo_with_binary_files(tmp_path):
    """Create a repository with binary files that should be skipped."""
    repo = tmp_path / "binary_repo"
    repo.mkdir()
    
    # Text file with LLM call
    (repo / "app.py").write_text('''
import openai
openai.ChatCompletion.create(model="gpt-4")
''')
    
    # Binary files
    (repo / "image.png").write_bytes(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
    (repo / "data.bin").write_bytes(b'\x00\x01\x02\x03' * 50)
    
    # Should-skip directories
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "package.py").write_text("import openai")
    
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "cache.pyc").write_bytes(b'\x00' * 50)
    
    return repo


@pytest.fixture
def repo_with_large_file(tmp_path):
    """Create a repository with a large file."""
    repo = tmp_path / "large_repo"
    repo.mkdir()
    
    # Create a large file with repeated LLM calls
    large_content = []
    for i in range(1000):
        large_content.append(f'''
def function_{i}(input_{i}):
    prompt = f"Process: {{input_{i}}}"  # LLM01
    return openai.ChatCompletion.create(model="gpt-4", messages=[{{"role": "user", "content": prompt}}])
''')
    
    (repo / "large_file.py").write_text('\n'.join(large_content))
    
    return repo


@pytest.fixture
def sample_scan_result():
    """Create a sample ScanResult for testing policy generation."""
    from scanner.repo_scanner import ScanResult, LLMCallSite
    
    call_sites = [
        LLMCallSite(
            file="/test/app.py",
            line=10,
            code='prompt = f"Summarize: {user_input}"',
            pattern_name="fstring_injection",
            owasp_id="LLM01",
            owasp_name="Prompt Injection",
            severity="HIGH",
            suggested_action="Add SOUF AI DPI input sanitisation"
        ),
        LLMCallSite(
            file="/test/app.py",
            line=15,
            code='return response.choices[0].message.content',
            pattern_name="raw_output_use",
            owasp_id="LLM02",
            owasp_name="Insecure Output Handling",
            severity="HIGH",
            suggested_action="Add output validation"
        ),
    ]
    
    governance_gaps = [
        LLMCallSite(
            file="/test/config.py",
            line=5,
            code='API_KEY = "sk-proj-abc123"',
            pattern_name="hardcoded_api_key",
            owasp_id="LLM06",
            owasp_name="Sensitive Information Disclosure",
            severity="HIGH",
            suggested_action="Move credentials to env vars"
        ),
    ]
    
    return ScanResult(
        repo_path="/test",
        scan_time_ms=100.0,
        total_files_scanned=3,
        total_lines_scanned=150,
        call_sites=call_sites,
        governance_gaps=governance_gaps,
    )
