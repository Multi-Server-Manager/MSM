#!/usr/bin/env python3
"""Drive the panel in a real pty and check every screen.

Two passes:

1. interactive — the binary in a pty: pair with a discovered node, list it,
   open the node, run an update, hand the terminal to ``ssh``, come back, quit;
2. headless — ``msm --render nodes|pair|detail|logs`` and a check that each
   screen drew what it should.

The panel redraws by moving the cursor to what changed, so the raw byte stream
never contains a whole line. This probe therefore keeps a small screen buffer and
matches against what a person would actually see.

Usage (inside the console container):

    tui_probe.py --state-dir /root/.msm-tui --code 7K3M9QXA --expect-label msmenv-1
"""

import argparse
import fcntl
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"ok   {name}")


def bad(name, detail=""):
    global FAIL
    FAIL += 1
    print(f"FAIL {name}{(': ' + detail) if detail else ''}")


def check(name, condition, detail=""):
    if condition:
        ok(name)
    else:
        bad(name, detail)


class Screen:
    """Just enough of a terminal to know what is on screen."""

    def __init__(self, width, height):
        self.width = width
        self.height = height
        self.grid = [[" "] * width for _ in range(height)]
        self.row = 0
        self.col = 0
        self.pending = ""

    def clear(self):
        self.grid = [[" "] * self.width for _ in range(self.height)]
        self.row = 0
        self.col = 0

    def feed(self, text):
        data = self.pending + text
        index = 0
        while index < len(data):
            char = data[index]
            if char == "\x1b":
                consumed = self.escape(data, index)
                if consumed is None:
                    # Incomplete sequence: keep it for the next read.
                    self.pending = data[index:]
                    return
                index = consumed
                continue
            if char == "\r":
                self.col = 0
            elif char == "\n":
                self.row = min(self.row + 1, self.height - 1)
            elif char == "\b":
                self.col = max(self.col - 1, 0)
            elif char >= " ":
                if self.row < self.height and self.col < self.width:
                    self.grid[self.row][self.col] = char
                self.col += 1
                if self.col >= self.width:
                    self.col = 0
                    self.row = min(self.row + 1, self.height - 1)
            index += 1
        self.pending = ""

    def escape(self, data, start):
        end = start + 1
        if end >= len(data):
            return None
        kind = data[end]
        if kind == "[":
            end += 1
            body = ""
            while end < len(data) and not ("@" <= data[end] <= "~"):
                body += data[end]
                end += 1
            if end >= len(data):
                return None
            self.csi(body, data[end])
            return end + 1
        if kind == "]":
            # OSC ends with BEL or ST; bash's shell integration uses ST.
            bel = data.find("\x07", end)
            st = data.find("\x1b\\", end)
            stops = [stop for stop in (bel, st) if stop >= 0]
            if not stops:
                return None
            stop = min(stops)
            return stop + 2 if stop == st else stop + 1
        return end + 1

    def csi(self, body, final):
        if final in "Hf":
            parts = body.split(";")
            row = int(parts[0]) - 1 if parts[0] else 0
            col = int(parts[1]) - 1 if len(parts) > 1 and parts[1] else 0
            self.row = max(0, min(row, self.height - 1))
            self.col = max(0, min(col, self.width - 1))
        elif final == "J":
            if body in ("2", "3"):
                self.clear()
        elif final == "K":
            for col in range(self.col, self.width):
                self.grid[self.row][col] = " "
        elif final == "A":
            self.row = max(0, self.row - (int(body) if body else 1))
        elif final == "B":
            self.row = min(self.height - 1, self.row + (int(body) if body else 1))
        elif final == "C":
            self.col = min(self.width - 1, self.col + (int(body) if body else 1))
        elif final == "D":
            self.col = max(0, self.col - (int(body) if body else 1))
        elif final in "hl" and body.startswith("?1049"):
            # Entering or leaving the alternate screen: the old contents are gone.
            self.clear()

    def text(self):
        return "\n".join("".join(row).rstrip() for row in self.grid)


class Panel:
    """A child process on its own pty, with a screen of what it drew."""

    def __init__(self, argv, width=100, height=30):
        self.width = width
        self.height = height
        self.screen = Screen(width, height)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execvp(argv[0], argv)
        self.resize(width, height)
        self.status = None

    @property
    def text(self):
        return self.screen.text()

    def drain(self):
        """Read whatever the child has produced and apply it to the screen."""
        while True:
            ready, _, _ = select.select([self.fd], [], [], 0)
            if not ready:
                return
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.screen.feed(chunk.decode("utf-8", "replace"))

    def read_until(self, needle, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([self.fd], [], [], 0.15)
            if ready:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    self.screen.feed(chunk.decode("utf-8", "replace"))
            if needle in self.text:
                return True
            if self.status is not None and self.status.exit_code() is not None:
                return needle in self.text
        return needle in self.text

    def expect(self, name, needle, timeout=20.0):
        found = self.read_until(needle, timeout)
        check(name, found, f"missing {needle!r} on screen")
        return found

    def send(self, text, delay=0.15):
        os.write(self.fd, text.encode())
        time.sleep(delay)

    def resize(self, width, height):
        self.width = width
        self.height = height
        self.screen = Screen(width, height)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

    def wait(self, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = Panel._Status(status)
                return self.status
            self.drain()
            time.sleep(0.05)
        return None

    class _Status:
        def __init__(self, raw):
            self.raw = raw

        def exit_code(self):
            return os.waitstatus_to_exitcode(self.raw)


def interactive(binary, state_dir, code, expect_label):
    print("== interactive pty")
    panel = Panel([binary, "--state-dir", state_dir])
    try:
        panel.expect("panel starts on the node list", "msm  nodes")
        check("empty list is honest", "no paired nodes" in panel.text)

        panel.send("p")
        panel.expect("pair screen opens", "msm  pair")

        panel.send("d")
        found = panel.expect("mDNS discovery lists the node", expect_label, timeout=15)
        if found:
            check(
                "discovery shows an address and port",
                re.search(r"\d+\.\d+\.\d+\.\d+:\d+", panel.text) is not None,
            )

        panel.send("\r")
        panel.expect("choosing a discovery result fills the address", "address")
        check(
            "the address field carries the discovered endpoint",
            re.search(r"address\s+\[\d+\.\d+\.\d+\.\d+:\d+[_ ]?\]", panel.text) is not None,
            panel.text,
        )

        panel.send(code)
        panel.send("\r")
        panel.expect("pairing succeeds", "paired with", timeout=30)

        panel.expect("back on the node list", "msm  nodes")
        check("the node is listed", expect_label in panel.text)

        panel.send("g")
        panel.expect("an action updates the row in place", "metrics:", timeout=20)

        panel.send("\r")
        panel.expect("node screen opens", "msm  " + expect_label, timeout=10)
        panel.expect("metrics history arrives", "samples", timeout=25)
        check("memory is shown in MiB", "MiB" in panel.text)

        # Stay put so the history grows into a real sparkline.
        time.sleep(9)
        panel.drain()
        series = re.search(r"^\s+([.:\-=+*#@]{2,})\s*$", panel.text, re.M)
        check("the sparkline plots a series of samples", series is not None, panel.text)
        counts = re.search(r"(\d+) samples", panel.text)
        check(
            "the history keeps more than one sample",
            counts is not None and int(counts.group(1)) >= 3,
            panel.text,
        )

        panel.send("u")
        panel.expect("update runs against the node", "pkg.update", timeout=30)
        finished = panel.read_until("exit 0 via", timeout=150)
        check("update reported a real result", finished, panel.text[-400:])

        panel.send("i")
        panel.expect("the install prompt opens", "install package", timeout=10)
        panel.send("sl", delay=0.3)
        panel.expect("the prompt shows what was typed", "install package: sl_", timeout=5)
        panel.send("\r")
        panel.expect("install runs against the node", "pkg.install sl", timeout=30)
        check(
            "install reported a real result",
            panel.read_until("exit 0 via", timeout=150),
            panel.text[-400:],
        )

        panel.send("s")
        opened = panel.read_until("root@", timeout=20)
        check("ssh took the terminal", opened, panel.text[-300:])
        panel.send("echo SSH-OK\r", delay=0.7)
        panel.expect("a command runs inside the ssh session", "SSH-OK", timeout=20)
        panel.send("exit\r", delay=0.7)
        panel.expect("the panel comes back after ssh", "msm  " + expect_label, timeout=25)
        check("the panel redrew the node screen", "load" in panel.text or "samples" in panel.text)

        panel.send("f")
        panel.expect("sftp takes the terminal with the same key", "sftp>", timeout=20)
        panel.send("bye\r", delay=0.7)
        panel.expect("the panel comes back after sftp", "msm  " + expect_label, timeout=25)

        panel.resize(80, 20)
        time.sleep(0.5)
        panel.send("q")
        status = panel.wait(timeout=15)
        check(
            "the panel exits cleanly",
            status is not None and status.exit_code() == 0,
            "no exit status",
        )
    finally:
        if panel.status is None:
            try:
                os.kill(panel.pid, 9)
            except OSError:
                pass
        try:
            os.close(panel.fd)
        except OSError:
            pass
    return panel


def render_pass(binary, state_dir):
    print("== headless renders")
    screens = {
        "nodes": ["msm  nodes", "LABEL", "ADDRESS", "STATUS"],
        "pair": ["msm  pair", "_msm-node._tcp", "address", "code"],
        "detail": ["msm  ", "load", "memory", "samples"],
        "logs": ["msm  logs"],
    }
    for screen, needles in screens.items():
        result = subprocess.run(
            [binary, "--state-dir", state_dir, "--render", screen,
             "--render-width", "100", "--render-height", "30"],
            capture_output=True, text=True, timeout=40,
        )
        text = result.stdout
        print(f"--- {screen}")
        print(text.rstrip())
        print()
        check(f"render {screen} exited 0", result.returncode == 0, result.stderr.strip())
        for needle in needles:
            check(f"render {screen} shows {needle!r}", needle in text)
        check(
            f"render {screen} stays inside 100 columns",
            all(len(line) <= 100 for line in text.splitlines()),
        )

    unknown = subprocess.run(
        [binary, "--state-dir", state_dir, "--render", "nope"],
        capture_output=True, text=True, timeout=30,
    )
    check("render rejects an unknown screen", unknown.returncode != 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="msm")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--code", required=True)
    parser.add_argument("--expect-label", default="msmenv-1")
    args = parser.parse_args()

    # Pair first: the headless pass then renders a real node, with real samples.
    panel = interactive(args.binary, args.state_dir, args.code, args.expect_label)
    if FAIL:
        print("\n--- final screen ---")
        print(panel.text)
    render_pass(args.binary, args.state_dir)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
