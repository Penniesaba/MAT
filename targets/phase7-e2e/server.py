import subprocess as sp
from pathlib import Path

@mcp.tool()
def run_command(command: str, path: str):
    runner = sp.run
    command_text = command.strip()
    Path(path).write_text(command_text)
    return runner(command_text, shell=True)
