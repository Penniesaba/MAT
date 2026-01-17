#!/usr/bin/env python3
"""
eBPF Monitor for MCP Security Dynamic Analysis

This script loads eBPF programs to monitor system calls and outputs
CEF (Common Event Format) logs for security analysis.

Requirements:
- BCC (BPF Compiler Collection) installed
- Python 3.13+
- Running in privileged container
"""

import os
import sys
import time
import socket
import struct
from datetime import datetime
from ctypes import c_uint32, c_uint64, c_char, c_uint8
from bcc import BPF

# CEF (Common Event Format) configuration from environment
CEF_VERSION = os.getenv("CEF_VERSION", "0")
DEVICE_VENDOR = os.getenv("DEVICE_VENDOR", "MCP-Security")
DEVICE_PRODUCT = os.getenv("DEVICE_PRODUCT", "Dynamic-Detector")
DEVICE_VERSION = os.getenv("DEVICE_VERSION", "1.0")

# Event type mapping
EVENT_TYPES = {
    1: "FILE_OPEN",
    2: "FILE_READ",
    3: "FILE_WRITE",
    4: "FILE_UNLINK",
    5: "NET_SOCKET",
    6: "NET_CONNECT",
    7: "NET_SEND",
    8: "NET_RECV",
    9: "PROC_EXEC",
    10: "PROC_FORK",
    11: "ENV_ACCESS",
}

# Severity mapping (0-10 scale)
SEVERITY_MAP = {
    "FILE_OPEN": 4,
    "FILE_READ": 5,
    "FILE_WRITE": 6,
    "FILE_UNLINK": 8,
    "NET_SOCKET": 5,
    "NET_CONNECT": 7,
    "NET_SEND": 6,
    "NET_RECV": 5,
    "PROC_EXEC": 8,
    "PROC_FORK": 7,
    "ENV_ACCESS": 6,
}

# Sensitive paths for enhanced severity
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh", "/home/.ssh", "/.aws/credentials",
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.env",
]

# Suspicious commands
SUSPICIOUS_COMMANDS = [
    "bash", "sh", "nc", "netcat", "wget", "curl",
    "python", "perl", "ruby", "php", "chmod", "chown"
]


class EventData:
    """Structure matching the BPF event_data struct"""
    _fields_ = [
        ("event_type", c_uint32),
        ("pid", c_uint32),
        ("uid", c_uint32),
        ("comm", c_char * 16),
        ("path", c_char * 256),
        ("timestamp", c_uint64),
        ("size", c_uint64),
        ("flags", c_uint32),
        ("fd", c_uint32),
        ("addr_family", c_uint32),
        ("port", c_uint32),
        ("ip", c_uint8 * 16),
    ]


class CEFLogger:
    """CEF (Common Event Format) logger"""

    def __init__(self, log_file="/logs/events.cef"):
        self.log_file = log_file
        self.file_handle = open(log_file, "w", buffering=1)  # Line buffered
        self.event_count = 0

    def format_cef(self, signature_id, name, severity, extensions):
        """
        Format CEF message:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        header = f"CEF:{CEF_VERSION}|{DEVICE_VENDOR}|{DEVICE_PRODUCT}|{DEVICE_VERSION}|{signature_id}|{name}|{severity}"
        extension_str = " ".join([f"{k}={v}" for k, v in extensions.items()])
        return f"{header}|{extension_str}"

    def log_event(self, event_type, data, extensions):
        """Log event in CEF format"""
        severity = SEVERITY_MAP.get(event_type, 5)

        # Enhance severity for sensitive operations
        if "dst" in extensions:
            dst = extensions["dst"]
            if any(sensitive in dst for sensitive in SENSITIVE_PATHS):
                severity = min(10, severity + 3)

        if "dproc" in extensions:
            dproc = extensions["dproc"]
            if any(cmd in dproc for cmd in SUSPICIOUS_COMMANDS):
                severity = min(10, severity + 2)

        cef_message = self.format_cef(event_type, data["name"], severity, extensions)
        self.file_handle.write(cef_message + "\n")
        self.event_count += 1

    def close(self):
        """Close log file"""
        self.file_handle.close()


class eBPFMonitor:
    """eBPF-based behavior monitor"""

    def __init__(self, bpf_program_path="/monitor/bpf_programs.c"):
        # Rename process to allow filtering in BPF
        try:
            import ctypes
            libc = ctypes.cdll.LoadLibrary('libc.so.6')
            # PR_SET_NAME = 15
            libc.prctl(15, b"ebpf-monitor", 0, 0, 0)
        except Exception as e:
            print(f"[!] Failed to rename process: {e}", file=sys.stderr)

        self.logger = CEFLogger()
        self.start_time = time.time()

        # Load BPF program
        print(f"[*] Loading eBPF program from {bpf_program_path}", file=sys.stderr)
        with open(bpf_program_path, "r") as f:
            bpf_code = f.read()

        self.bpf = BPF(text=bpf_code)

        # Ignore own PID to prevent recursive logging loops
        self._ignore_pid(os.getpid())

        # Attach probes
        self._attach_probes()

        # Open perf buffer
        self.bpf["events"].open_perf_buffer(self._handle_event)

        print("[*] eBPF monitor started. Capturing events...", file=sys.stderr)

    def _ignore_pid(self, pid):
        """Add PID to ignored list"""
        try:
            ignored_pids = self.bpf.get_table("ignored_pids")
            ignored_pids[c_uint32(pid)] = c_uint8(1)
            print(f"[*] Ignoring events from PID {pid}", file=sys.stderr)
        except Exception as e:
            print(f"[!] Failed to ignore PID {pid}: {e}", file=sys.stderr)

    def _attach_probes(self):
        """Attach eBPF probes to system calls using tracepoints"""
        print(f"[*] Attaching tracepoints (tracepoints are architecture-independent)", file=sys.stderr)
        
        # Tracepoints are already attached via TRACEPOINT_PROBE macros in BPF code
        # No manual attachment needed - BCC handles this automatically
        
        print(f"[+] Tracepoints attached automatically via BPF program", file=sys.stderr)

    def _handle_event(self, cpu, data, size):
        """Handle events from BPF perf buffer"""
        event = self.bpf["events"].event(data)

        event_type = EVENT_TYPES.get(event.event_type, "UNKNOWN")
        comm = event.comm.decode("utf-8", errors="ignore")
        path = event.path.decode("utf-8", errors="ignore")
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

        # Build CEF extensions based on event type
        extensions = {
            "rt": timestamp,
            "suser": self._get_username(event.uid),
            "sproc": comm,
            "spid": str(event.pid),
            "outcome": "success",
        }

        # File system events
        if event_type in ["FILE_OPEN", "FILE_READ", "FILE_WRITE", "FILE_UNLINK"]:
            extensions["dst"] = path or f"fd:{event.fd}"
            extensions["act"] = event_type.split("_")[1].lower()

            if event_type in ["FILE_READ", "FILE_WRITE"]:
                extensions["bytesIn" if event_type == "FILE_READ" else "bytesOut"] = str(event.size)

            if event_type == "FILE_OPEN":
                extensions["fileType"] = self._guess_file_type(path)
                extensions["cs1"] = str(event.flags)
                extensions["cs1Label"] = "OpenFlags"

        # Network events
        elif event_type in ["NET_SOCKET", "NET_CONNECT", "NET_SEND", "NET_RECV"]:
            if event_type == "NET_CONNECT":
                if event.addr_family == 1:  # AF_UNIX
                    extensions["dst"] = path
                    extensions["proto"] = "unix"
                else:
                    ip_str = self._format_ip(event.ip, event.addr_family)
                    extensions["dst"] = f"{ip_str}:{event.port}"
                    extensions["dpt"] = str(event.port)
                    extensions["proto"] = "tcp" if event.addr_family == 2 else "udp"
                
                extensions["cs1"] = str(event.addr_family)
                extensions["cs1Label"] = "Family"

            elif event_type in ["NET_SEND", "NET_RECV"]:
                extensions["bytesOut" if event_type == "NET_SEND" else "bytesIn"] = str(event.size)
                extensions["fd"] = str(event.fd)

            elif event_type == "NET_SOCKET":
                extensions["cs1"] = f"family={event.addr_family},type={event.flags}"
                extensions["cs1Label"] = "SocketParams"

        # Process events
        elif event_type in ["PROC_EXEC", "PROC_FORK"]:
            if event_type == "PROC_EXEC":
                extensions["dproc"] = path
                extensions["cs1"] = path
                extensions["cs1Label"] = "Command"
            else:
                extensions["cs1"] = "fork/clone"
                extensions["cs1Label"] = "Action"

        # Log to CEF
        self.logger.log_event(
            event_type,
            {"name": self._event_name(event_type, extensions)},
            extensions
        )

    def _event_name(self, event_type, extensions):
        """Generate human-readable event name"""
        if event_type == "FILE_READ":
            dst = extensions.get("dst", "")
            if any(s in dst for s in SENSITIVE_PATHS):
                return "Sensitive File Read"
            return "File Read"
        elif event_type == "FILE_WRITE":
            return "File Write"
        elif event_type == "FILE_OPEN":
            return "File Open"
        elif event_type == "FILE_UNLINK":
            return "File Delete"
        elif event_type == "NET_CONNECT":
            return "Outbound Connection"
        elif event_type == "PROC_EXEC":
            cmd = extensions.get("dproc", "")
            if any(s in cmd for s in SUSPICIOUS_COMMANDS):
                return "Suspicious Command Execution"
            return "Command Execution"
        elif event_type == "PROC_FORK":
            return "Process Fork"
        return event_type

    def _format_ip(self, ip_bytes, family):
        """Format IP address from bytes"""
        if family == 2:  # AF_INET
            return socket.inet_ntop(socket.AF_INET, bytes(ip_bytes[:4]))
        elif family == 10:  # AF_INET6
            return socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))
        return "0.0.0.0"

    def _get_username(self, uid):
        """Get username from UID"""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except:
            return str(uid)

    def _guess_file_type(self, path):
        """Guess file type from extension"""
        if not path:
            return "unknown"
        ext = path.split(".")[-1].lower()
        type_map = {
            "py": "python", "js": "javascript", "json": "json",
            "sh": "shell", "txt": "text", "log": "log",
            "conf": "config", "yaml": "config", "toml": "config",
        }
        return type_map.get(ext, "unknown")

    def run(self, timeout=30):
        """Run monitor for specified timeout"""
        print(f"[*] Monitoring for {timeout} seconds...", file=sys.stderr)
        end_time = time.time() + timeout

        try:
            while time.time() < end_time:
                self.bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user", file=sys.stderr)

        print(f"[*] Monitoring complete. Captured {self.logger.event_count} events", file=sys.stderr)
        self.logger.close()


def main():
    """Main entry point"""
    timeout = int(os.getenv("MONITOR_TIMEOUT", "30"))

    try:
        monitor = eBPFMonitor()
        monitor.run(timeout=timeout)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
