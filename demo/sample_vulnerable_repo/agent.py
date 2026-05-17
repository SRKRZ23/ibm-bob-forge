"""
Vulnerable LangChain Agent - Demo for FORGE
Contains agent-specific vulnerabilities
"""

from langchain.agents import initialize_agent, Tool, AgentType
from langchain.llms import OpenAI
from langchain.memory import ConversationBufferMemory
import os
import subprocess
import requests

# ❌ LLM06: Hardcoded API key
os.environ["OPENAI_API_KEY"] = "sk-proj-AGENT456789xyz"

llm = OpenAI(temperature=0.7)

# ❌ LLM08: Unrestricted tools
def read_any_file(path: str) -> str:
    """Read any file without restrictions."""
    with open(path, 'r') as f:
        return f.read()

def execute_any_command(cmd: str) -> str:
    """Execute any command without restrictions."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f"Output: {result.stdout}\nError: {result.stderr}"

def fetch_any_url(url: str) -> str:
    """Fetch any URL without restrictions."""
    response = requests.get(url)
    return response.text

def write_any_file(args: str) -> str:
    """Write to any file without restrictions."""
    path, content = args.split('|', 1)
    with open(path, 'w') as f:
        f.write(content)
    return f"Written to {path}"

# Define unrestricted tools
tools = [
    Tool(
        name="ReadFile",
        func=read_any_file,
        description="Read any file. Input: file path"
    ),
    Tool(
        name="ExecuteCommand",
        func=execute_any_command,
        description="Execute any shell command. Input: command"
    ),
    Tool(
        name="FetchURL",
        func=fetch_any_url,
        description="Fetch any URL. Input: URL"
    ),
    Tool(
        name="WriteFile",
        func=write_any_file,
        description="Write to any file. Input: path|content"
    )
]

# ❌ LLM04: No limits
memory = ConversationBufferMemory(memory_key="chat_history")

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
    """Run agent with user input."""
    # ❌ LLM01: No input sanitization
    return agent.run(user_input)

if __name__ == "__main__":
    print("Vulnerable Agent Running...")
    result = run_agent("Read /etc/passwd")
    print(result)
