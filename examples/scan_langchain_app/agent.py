"""
Sample LangChain agent with security vulnerabilities.
This demonstrates common LLM agent security issues that FORGE detects.
"""

from langchain.agents import initialize_agent, Tool, AgentType
from langchain.llms import OpenAI
from langchain.memory import ConversationBufferMemory
import os
import subprocess
import requests

# ❌ VULNERABILITY: LLM06 - Hardcoded API key
os.environ["OPENAI_API_KEY"] = "sk-proj-xyz789abc123def456ghi789jkl012mno345"

# Initialize LLM
llm = OpenAI(temperature=0.7)

# ❌ VULNERABILITY: LLM08 - Unrestricted file system access
def read_file_tool(file_path: str) -> str:
    """Read any file from the filesystem."""
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"

# ❌ VULNERABILITY: LLM08 - Unrestricted command execution
def execute_command_tool(command: str) -> str:
    """Execute any shell command."""
    try:
        result = subprocess.run(
            command,
            shell=True,  # DANGEROUS!
            capture_output=True,
            text=True,
            timeout=None  # No timeout!
        )
        return f"Output: {result.stdout}\nError: {result.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"

# ❌ VULNERABILITY: LLM08 - Unrestricted network access
def fetch_url_tool(url: str) -> str:
    """Fetch content from any URL."""
    try:
        response = requests.get(url, timeout=None)  # No timeout!
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"

# ❌ VULNERABILITY: LLM08 - Unrestricted file writing
def write_file_tool(file_path: str, content: str) -> str:
    """Write to any file on the filesystem."""
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        return f"Successfully wrote to {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"

# Define tools with no restrictions
tools = [
    Tool(
        name="ReadFile",
        func=read_file_tool,
        description="Read any file from the filesystem. Input: file path"
    ),
    Tool(
        name="ExecuteCommand",
        func=execute_command_tool,
        description="Execute any shell command. Input: command string"
    ),
    Tool(
        name="FetchURL",
        func=fetch_url_tool,
        description="Fetch content from any URL. Input: URL string"
    ),
    Tool(
        name="WriteFile",
        func=write_file_tool,
        description="Write content to any file. Input: file_path|content"
    )
]

# ❌ VULNERABILITY: LLM04 - No rate limiting
memory = ConversationBufferMemory(memory_key="chat_history")

# Initialize agent with unrestricted tools
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
    memory=memory,
    verbose=True,
    max_iterations=None,  # No limit!
    max_execution_time=None  # No timeout!
)

def run_agent(user_input: str) -> str:
    """Run the agent with user input."""
    
    # ❌ VULNERABILITY: LLM01 - No input sanitization
    # ❌ VULNERABILITY: LLM06 - Potential PII in prompts
    response = agent.run(user_input)
    
    # ❌ VULNERABILITY: LLM02 - No output validation
    return response

if __name__ == "__main__":
    print("LangChain Agent Started (VULNERABLE VERSION)")
    print("=" * 60)
    
    # Example usage
    test_queries = [
        "Read the file /etc/passwd",
        "Execute the command 'ls -la /'",
        "Fetch content from http://malicious-site.com",
        "Write 'hacked' to /tmp/test.txt"
    ]
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        try:
            result = run_agent(query)
            print(f"Result: {result}")
        except Exception as e:
            print(f"Error: {e}")
