#!/usr/bin/env python3
"""Test-only guard: toggle only the preidentified win11/101/net0 link."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

VMID = "101"
MAC = "BC:24:11:BE:0E:E0"


def command(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=10).stdout.strip()


def config(current=False):
    args = ["/usr/sbin/qm", "config", VMID]
    if current:
        args += ["--current", "1"]
    return dict(line.split(": ", 1) for line in command(*args).splitlines()
                if ": " in line and not line.startswith("#"))


def down_value(original):
    parts = original.split(",")
    if parts[0].upper() != "VIRTIO=" + MAC:
        raise RuntimeError("Refusing a different NIC model or MAC")
    flags = [part for part in parts if part.startswith("link_down=")]
    if flags not in ([], ["link_down=0"]):
        raise RuntimeError("Original NIC is already down or ambiguous")
    return ",".join(part for part in parts if not part.startswith("link_down=")) + ",link_down=1"


def unchanged_files():
    files = [p for p in Path("/etc/pve/qemu-server").glob("*.conf") if p.name != "101.conf"]
    files += [Path("/etc/network/interfaces"), Path("/etc/pve/storage.cfg")]
    files += list(Path("/etc/network/interfaces.d").glob("*"))
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(files) if p.is_file()}


def write_json(path, value):
    temporary = path.with_suffix(".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def main(action, token):
    if not re.fullmatch(r"[A-Za-z0-9]{6}", token):
        raise RuntimeError("Invalid unique fixture token")
    directory = Path("/run/photon-win11-link-" + token)
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != 0:
        raise RuntimeError("Invalid owned guard directory")
    state_path = directory / "state.json"
    unit = "photon-win11-link-" + token

    def event(kind, **fields):
        entry = {"utc": datetime.now(timezone.utc).isoformat(), "event": kind, **fields}
        with (directory / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(entry) + "\n")
        print(json.dumps(entry), flush=True)

    def verify(state):
        now = config(True)
        if config() != now or now.get("net0") != state["net0"]:
            raise RuntimeError("Restored current/pending net0 differs from original")
        if {k: v for k, v in now.items() if k != "net0"} != state["other_config"]:
            raise RuntimeError("Other win11 configuration changed")
        if unchanged_files() != state["unchanged_files"]:
            raise RuntimeError("Other VM, host network or storage configuration changed")
        if command("/usr/sbin/qm", "status", VMID) != "status: running":
            raise RuntimeError("win11 is no longer running")

    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action in ("down", "arm-only"):
            if state_path.exists():
                raise RuntimeError("Refusing to reuse an armed fixture")
            before = config(True)
            if before != config() or before.get("name") != "win11" or "lock" in before:
                raise RuntimeError("Wrong VM, pending configuration or VM lock")
            if command("/usr/sbin/qm", "status", VMID) != "status: running":
                raise RuntimeError("win11 must already be running")
            original = before["net0"]
            down = down_value(original)
            state = {"vmid": VMID, "name": "win11", "net0": original, "down": down,
                     "other_config": {k: v for k, v in before.items() if k != "net0"},
                     "unchanged_files": unchanged_files(), "phase": "armed", "arm_only": action == "arm-only"}
            write_json(state_path, state)
            # Independent host timer is armed and checked BEFORE changing net0.
            command("/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + unit,
                    "--on-active=45s", "--timer-property=AccuracySec=1s",
                    "/usr/bin/python3", str(directory / "guard.py"), "restore", token)
            if command("/usr/bin/systemctl", "is-active", unit + ".timer") != "active":
                raise RuntimeError("Independent restore timer was not armed")
            event("watchdog-armed", vmid=VMID, original=original, seconds=45)
            if action == "arm-only":
                event("watchdog-check-only", vmid=VMID, net0_unchanged=True)
                return
            command("/usr/sbin/qm", "set", VMID, "--net0", down)
            if config(True).get("net0") != down or config().get("net0") != down:
                raise RuntimeError("Link-down did not apply to the running VM")
            state["phase"] = "down"
            write_json(state_path, state)
            event("link-down", vmid=VMID, net0=down)
        elif action in ("restore", "cleanup"):
            if state_path.exists():
                state = json.loads(state_path.read_text())
                if state["vmid"] != VMID or state["name"] != "win11" or down_value(state["net0"]) != state["down"]:
                    raise RuntimeError("Invalid restore ownership")
                current = config(True)
                pending = config()
                if current.get("name") != "win11" or current.get("net0") not in (state["net0"], state["down"]):
                    raise RuntimeError("Unexpected net0; refusing to overwrite an external change")
                if pending.get("net0") != current.get("net0"):
                    raise RuntimeError("External pending net0 change; refusing to overwrite it")
                if not state["arm_only"] and current["net0"] == state["down"]:
                    command("/usr/sbin/qm", "set", VMID, "--net0", state["net0"])
                verify(state)
                state["phase"] = "restored"
                write_json(state_path, state)
                event("restored", vmid=VMID, net0=state["net0"], other_configuration_unchanged=True)
            else:
                event("unarmed", vmid=VMID, net0_unchanged=True)
            if action == "cleanup":
                # Only our unique one-shot timer, never the host or VM itself.
                subprocess.run(["/usr/bin/systemctl", "stop", unit + ".timer"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                active = subprocess.run(["/usr/bin/systemctl", "is-active", unit + ".timer"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                if active.returncode == 0:
                    raise RuntimeError("Restore timer remains active")
                shutil.rmtree(directory)
                print("PVE_LINK_GUARD_CLEANUP_PASS", flush=True)
        else:
            raise RuntimeError("Unsupported guard action")


if __name__ == "__main__":
    main(*sys.argv[1:])
