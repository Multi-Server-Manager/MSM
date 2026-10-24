# MSM wire protocol — version 1

This document is the **single source of truth** for the bytes exchanged between
`msm` (the Rust console) and `msm-node` (the Go agent). Both implementations are
written against this file and neither may diverge from it. If an implementation
and this document disagree, the implementation is wrong.

It is deliberately short: protocol version 1 carries identity exchange, pairing
and a single informational request. New message types are added here first.

- Status: stable, v1
- Domain separator for every derived value: `MSM-PAIR-V1`

---

## 1. Transport

- TCP, **TLS 1.3 only**. `min_version` and `max_version` are both TLS 1.3; TLS
  1.2 and below are refused, not downgraded.
- **Mutual authentication by certificate.** The listener requests a client
  certificate and both sides always present one.
- Certificates are self-signed X.509 v3 with an **Ed25519** subject key. The
  certificate's SubjectPublicKeyInfo (SPKI) **is** the identity.
- Certificate authorities are not used. There is no CA bundle, no hostname
  validation and no chain building. Trust comes from pinning the SPKI, and
  during pairing from the one-time code.
- Certificate profile (both roles):
  - `subject.CN` = `msm-node` or `msm-client`
  - single SAN DNS name, same string as the CN
  - `basicConstraints: CA:TRUE` (an unconstrained self-signed CA, so a peer that
    does validate a chain still accepts it)
  - `keyUsage: digitalSignature`
  - validity: now − 1 h … now + 1 y (not part of trust)
- The Ed25519 SPKI encoding is fixed at 44 bytes:
  `302a300506032b6570032100 || <32-byte public key>`.
  Implementations accept **only** that encoding as an identity. A peer offering
  any other key type is rejected.

## 2. Framing

```
uint32  length        big endian, number of payload bytes that follow
byte[]  payload       UTF-8 JSON object, exactly `length` bytes
```

- `1 <= length <= 1048576` (1 MiB).
- `length == 0` → close with `bad_frame`.
- `length > 1048576` → close with `bad_frame`.
- An implementation **must not** allocate or buffer more than
  `1048576 + 4` bytes for a frame header/payload pair.
- The payload must be a JSON **object**, not an array or scalar.
- Required members of every payload: `"t"` (string, message type) and `"v"`
  (integer, protocol version).
- `"v" != 1` → `bad_version`, then close.
- An unrecognised `"t"` → `unknown_type`, then close.
- Trailing bytes after the JSON object, invalid UTF-8, or malformed JSON →
  `bad_frame`, then close.
- A party that sends `bad_frame`, `unknown_type` or `bad_version` **closes the
  connection immediately**; there is no resynchronisation.

## 3. Encoding conventions

| Kind | Encoding |
|---|---|
| Binary field | standard base64, RFC 4648 §4, **with** padding |
| Node / client id | 16 random bytes, base64 |
| SPKI | base64 of the 44-byte DER above |
| Address | `host:port`; IPv6 literal in `[brackets]` |
| Integers | JSON numbers, non-negative, no exponent |
| Timestamps | not used on the wire in v1 |

## 4. Pairing code

- 40 bits from a CSPRNG, rendered as **8 characters** of Crockford Base32:
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I`, `L`, `O`, `U`).
- Five random bytes are read and encoded most-significant-bit first.
- Printed uppercase. Accepted input is normalised before use:
  1. remove `-`, space and tab,
  2. uppercase ASCII,
  3. map `I` → `1`, `L` → `1`, `O` → `0`,
  4. must be exactly 8 characters, all in the alphabet.
- Lifetime: 300 s from generation (configurable on the node).
- Single use. A code that produced a successful pairing is destroyed.
- Three failed proofs by default, then the node destroys the code, generates a
  new one, resets the attempt counter and restarts the lifetime.

## 5. Identities

| | Node | Client |
|---|---|---|
| Key | Ed25519 | Ed25519 |
| id | 16 random bytes, stable for the key's life | 16 random bytes per client identity |
| Pinned value | base64 SPKI | base64 SPKI |

Pins are compared with a constant-time equality check.

## 6. Pairing state machine

```
        client                                          node
          |                                                |
          |=== TLS 1.3, client certificate presented =====>|
          |                                                |
          |------- pair.hello ---------------------------->|
          |                                                |
          |<------------------------------ pair.challenge -|
          |                                                |
          |------- pair.proof ---------------------------->|
          |                                                |
          |<----------------------------------- pair.ok ----|
          |                                                |
          |  (node persists the client, burns the code)    |
```

The client always speaks first. The node answers exactly one request and then
closes the connection. Any failure is reported with `error` (see §10) and the
connection is closed. A TLS failure is not an `error` message — it is a
handshake failure.

### 6.1 `pair.hello` — client → node

| field | type | value |
|---|---|---|
| `t` | string | `"pair.hello"` |
| `v` | integer | `1` |
| `eph` | b64(32) | client ephemeral X25519 public key |
| `nonce` | b64(16) | client nonce, CSPRNG |

### 6.2 `pair.challenge` — node → client

| field | type | value |
|---|---|---|
| `t` | string | `"pair.challenge"` |
| `v` | integer | `1` |
| `eph` | b64(32) | node ephemeral X25519 public key |
| `nonce` | b64(16) | node nonce, CSPRNG |
| `node_id` | b64(16) | node identity id |
| `node_spki` | b64(44) | node identity SPKI |
| `op_port` | integer | port of the operational listener |
| `ttl_left` | integer | seconds until the code expires |
| `trials_left` | integer | failed proofs still allowed |

### 6.3 `pair.proof` — client → node

| field | type | value |
|---|---|---|
| `t` | string | `"pair.proof"` |
| `v` | integer | `1` |
| `mac` | b64(32) | `client_mac` from §7 |
| `client_id` | b64(16) | client identity id |
| `client_spki` | b64(44) | client identity SPKI |
| `setup` | object | optional; the console's answers to the setup questions (§8.13). Absent keeps whatever the node already has, and so does an empty field inside it |

### 6.4 `pair.ok` — node → client

| field | type | value |
|---|---|---|
| `t` | string | `"pair.ok"` |
| `v` | integer | `1` |
| `mac` | b64(32) | `node_mac` from §7 |
| `node_id` | b64(16) | repeated, must match the challenge |
| `node_spki` | b64(44) | repeated, must match the challenge |
| `op_port` | integer | repeated, must match the challenge |
| `ssh_key` | string | optional; the node's own `ssh-ed25519` line, for the return direction |
| `setup` | object | optional; the answers the node now uses |
| `warn` | string | optional; why the answers cannot work yet, e.g. the node may not escalate to `run_as` |

## 7. Transcript, key schedule and proofs

### 7.1 Shared secret

`shared` is the X25519 output (32 bytes) of the client ephemeral key and the node
ephemeral key. An all-zero output is a protocol violation and must be rejected.

### 7.2 Transcript

`th` binds every value that a party could otherwise be tricked into accepting
from a different session. Fields are concatenated in this exact order, each
prefixed with its length as `uint16` big endian:

```
"MSM-PAIR-V1"                        (11 ASCII bytes, no terminator)
u16be || client_eph     (32)
u16be || node_eph       (32)
u16be || client_nonce   (16)
u16be || node_nonce     (16)
u16be || node_id        (16)
u16be || node_spki      (44)
u16be || client_id      (16)
u16be || client_spki    (44)

th = SHA-256( the concatenation above )
```

### 7.3 Key schedule

`code_ascii` is the 8 normalised ASCII bytes of the code.

```
prk1 = HMAC-SHA256(key = "msm-pair-v1 code seal", msg = code_ascii)
prk2 = HMAC-SHA256(key = prk1,                   msg = shared)
c2n  = HKDF-Expand-SHA256(prk2, info = "msm-pair-v1 client proof", L = 32)
n2c  = HKDF-Expand-SHA256(prk2, info = "msm-pair-v1 node proof",   L = 32)
```

The two `HMAC` lines are HKDF-Extract (RFC 5869 §2.2). `HKDF-Expand` is RFC 5869
§2.3 with SHA-256. `prk1` uses a fixed string as the HMAC key, so the code is the
input keying material.

### 7.4 Proofs

```
client_mac = HMAC-SHA256(key = c2n, msg = "MSM-PAIR-V1 client" || th)
node_mac   = HMAC-SHA256(key = n2c, msg = "MSM-PAIR-V1 node"   || th)
```

The node verifies `client_mac`; on success it replies with `node_mac`, which the
client verifies. Both comparisons are constant time.

### 7.5 Certificate binding

- The client asserts `node_spki` from `pair.challenge` equals the SPKI of the
  certificate presented in the TLS handshake. A mismatch aborts pairing.
- The node asserts `client_spki` from `pair.proof` equals the SPKI of the client
  certificate. A mismatch is treated as `bad_proof`.

This binds the proof to the TLS identities, so a recorded proof cannot be
replayed over a connection with a different key.

### 7.6 Why this resists offline guessing

Deriving `c2n` requires both the code **and** `shared`. An eavesdropper who sees
the whole handshake has neither the X25519 private keys nor the code, so they
cannot compute a candidate `prk2` and test code guesses offline. Every guess
requires an active man-in-the-middle attempt against a live connection, which is
limited to three tries and a five-minute window, with the code rotating
afterwards.

## 8. Operational channel

After a successful pairing the node listens on `op_port` (default 7333). Clients
connect with mutual TLS and the peer SPKI must equal the pin recorded at pairing
time. Unpinned clients receive `error` with `unauthorized` and are closed.

One request per connection. The node answers with exactly one `result` (or one
`error` when the connection itself is refused) and closes.

A request that is well framed and authorised **always** receives a `result`,
even when the command is refused: refusals are `ok: false` plus a `code`, not
`error`. `error` is reserved for framing, version, authorisation and transport
failures that happen before a command is dispatched.

### 8.1 `info` — client → node

| field | type | value |
|---|---|---|
| `t` | string | `"info"` |
| `v` | integer | `1` |

### 8.2 `info.ok` — node → client

| field | type | value |
|---|---|---|
| `t` | string | `"info.ok"` |
| `v` | integer | `1` |
| `node_id` | b64(16) | node identity id |
| `hostname` | string | node hostname |
| `os` | string | `GOOS/GOARCH` |
| `version` | string | node binary version |
| `pinned_clients` | integer | number of pinned client identities |
| `ssh_key` | string | optional; the node's own `ssh-ed25519` line |
| `setup` | object | optional; the answers now in force (§8.13) |

### 8.3 Command requests

Every command carries a request id, which the node echoes unchanged. The id is
`[A-Za-z0-9_-]{1,64}`; anything else is `bad_argument`.

| `t` | extra fields |
|---|---|
| `pkg.update` | — |
| `pkg.install` | `name`: `[a-zA-Z0-9_][a-zA-Z0-9._:+-]{0,63}` |
| `svc.restart` | `unit`: empty, `self`, `msm-node`, or `[a-zA-Z0-9@_][a-zA-Z0-9@._:-]{0,63}` |
| `host.reboot` | `confirm`: must be exactly `reboot` |
| `metrics.sample` | — |
| `logs.tail` | `lines`: integer `1…500` |

All requests have `v: 1` and the `id` member.

Neither `name` nor `unit` may begin with `-`, `+`, `.` or `:`. The element after
the verb is what `dnf`, `apt-get`, `pacman`, `apk` and `systemctl` read as a flag
or a path, so those leading characters are `bad_argument` even though the rest
of the charset allows them. An empty `name` is always `bad_argument`.

Commands run as the account named by the node's `setup.run_as` (§8.13), which
defaults to the account the agent itself runs as. A node that already is that
account starts the process directly; a node running as root switches the child's
credentials; any other node prefixes `sudo -n --` (or `sudo -n -u <account> --`).
`sudo` is never allowed to prompt: when it would, the request is refused with
`failed` and a detail naming the sudoers rule that would fix it. The `commands`
member of a package payload carries the argv that really ran, `sudo` included.

A non-zero exit reports the manager's own explanation in `detail`, not just the
exit code: the line naming the failure is preferred over a trailing hint line.

### 8.4 `result` — node → client

| field | type | value |
|---|---|---|
| `t` | string | `"result"` |
| `v` | integer | `1` |
| `id` | string | the request id, echoed |
| `ok` | boolean | whether the command succeeded |
| `code` | string | present only when `ok` is false; see §10 |
| `detail` | string | present only when `ok` is false; human readable, no secrets |
| `data` | object | present when there is a payload; may accompany `ok: false` |

Members that do not apply are **absent**, not empty strings or nulls.

### 8.5 `pkg.update` data

```
{ "manager": "dnf|apt|pacman|apk",
  "commands": [["dnf","-y","upgrade"]],
  "exit_code": 0,
  "output": "…",
  "summary": "3 packages were updated" }
```

`commands` is the exact argv sequence that was executed, in order. The node
detects one manager and refuses with `unsupported` when none is present.

`summary` is the outcome in one sentence, read from the manager's own report:
`there were no updates`, `<n> packages were updated` (or `1 package was
updated`), `<name> was installed`, `<name> was already installed`, and `the
update finished` when the report was not in the output tail. It is **display
text only** — `exit_code` still decides whether the run succeeded — and it is
absent when the run did not reach the manager. A console that does not know the
member ignores it and falls back to `exit_code` and `manager`.

### 8.6 `pkg.install` data

Same shape as §8.5. The package name is validated against its charset **before**
any process starts and is always passed as a single argv element; no shell is
involved at any point.

### 8.7 `svc.restart` data

```
{ "unit": "msm-node", "method": "exec|systemd" }
```

- empty `unit`, or `msm-node`, or `self`: the node answers first and then
  re-executes its own binary in place (`method: "exec"`). The result is sent
  before the restart, so the client sees success and simply reconnects.
- any other unit: `systemctl restart <unit>` when systemd is the running init,
  otherwise `unsupported`.

### 8.8 `host.reboot` data

```
{ "method": "systemd" }
```

Without `confirm` exactly equal to `reboot` the node refuses with
`confirmation_required` and does nothing. With a valid token it refuses with
`unsupported` when systemd is not the running init, which is the case inside a
container; it never reboots a host that cannot reboot itself cleanly. A node
that is not root refuses with `failed`, because `systemctl reboot` would fail
anyway.

### 8.9 `metrics.sample` data

```
{ "load1": 0.12, "load5": 0.10, "load15": 0.09,
  "cpu_count": 8,
  "mem_total_kb": 8123456, "mem_available_kb": 4123456,
  "uptime_s": 98123,
  "disk_total_kb": 51234567, "disk_available_kb": 21234567 }
```

Read from `/proc/loadavg`, `/proc/meminfo`, `/proc/uptime` and `statfs("/")`.
A node without a readable `/proc` refuses with `unsupported`.

### 8.10 `logs.tail` data

```
{ "lines": ["…"], "dropped": 0 }
```

Returns the agent's own recent log lines — the same lines it prints on stdout —
newest last. `dropped` counts lines discarded from the ring buffer before the
oldest returned line. The ring holds at most 2000 lines and each line is
truncated to 512 bytes.

### 8.11 `ssh.authorize` — client → node

```
{ "t": "ssh.authorize", "v": 1, "id": "…",
  "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… msm-console" }
```

One line in OpenSSH `authorized_keys` format. The node validates it strictly
before touching any file:

- exactly `ssh-ed25519 <blob> [comment]`, one space between the fields;
- `<blob>` is standard base64 of `string("ssh-ed25519") || string(<32-byte key>)`,
  i.e. 51 bytes decoding to a 0x0000000b prefix, the type name, a 0x00000020
  length and exactly 32 key bytes;
- the optional comment is `[A-Za-z0-9@._-]{0,64}`.

Anything else is `bad_argument` and no file is read or written.

| field | type | value |
|---|---|---|
| `user` | string | optional; the account the line is installed for. Absent means the node's configured `setup.ssh_user` |

The account is resolved on the node, and the line is appended to that account's
`~/.ssh/authorized_keys` (directory 0700, file 0600) only when the same blob is
not already present, so pairing twice is idempotent. Writing another account's
file uses the same privilege path as a command: credential switching when the
agent is root, `sudo -n` otherwise. A node that cannot write the file answers
`failed`.

Data:

```
{ "path": "/root/.ssh/authorized_keys", "added": true, "user": "root" }
```

`added` is false when the key was already installed. The key is exchanged over
the channel the pairing pin already authenticated, so the pairing transcript and
every derived value are unchanged.

The reverse direction uses `pair.ok`: the node's own `ssh_key` is written to the
console account's `~/.ssh/authorized_keys` by the console. Both sides therefore
hold an MSM-managed keypair and can log in to each other without a password.

### 8.13 `node.setup` — client → node

```
{ "t": "node.setup", "v": 1, "id": "…",
  "run_as": "root", "ssh_user": "admin", "ssh_port": 22 }
```

Changes the answers the node's first pairing asked for:

| field | type | value |
|---|---|---|
| `run_as` | string | `[a-z_][a-z0-9_.-]{0,31}`: account package and service commands run as |
| `ssh_user` | string | same charset: account console SSH keys are installed for |
| `ssh_port` | integer | `1…65535`: port a console dials for SSH |

In `node.setup` all three are required. In `pair.proof` each may be empty (or
port `0`), which means "keep the answer this node already has" — that is how a
console that typed nothing defers to the node's own accounts instead of forcing
root. The node resolves the accounts before storing anything: a name this host
does not have is `failed` and nothing changes. A bad charset or port is
`bad_argument`. On success the node applies the change without a restart
and answers:

```
{ "run_as": "root", "ssh_user": "admin", "ssh_port": 22, "warn": "…" }
```

`warn` is present only when the answers were stored but cannot be used yet —
the node cannot become `run_as` and said why. The change is still applied: an
operator may fix the sudoers rule while the node is reachable, and the console
shows the same sentence instead of letting every command fail.

The same object travels in `pair.proof` and in both `pair.ok` and `info.ok`, so a
console always knows the answers in force. `run_as` is also what the node prints
at startup (`SETUP run_as=… ssh_user=… ssh_port=…`).

### 8.12 Limits and serialisation

- Exactly one command runs per node at a time. A request that arrives while
  another is running is refused with `busy`; it is not queued.
- Captured process output is bounded to 32 KiB and the last 40 lines.
- Command timeouts: `pkg.update` and `pkg.install` 300 s, `svc.restart` and
  `host.reboot` 30 s. `metrics.sample` and `logs.tail` read local state only and
  need no budget of their own. A timeout is `failed` with a detail saying so.
- A command that exits non-zero is `failed`, with `data` still present so the
  client can show the output.

## 9. Service discovery

Not a wire message: the node advertises itself so a console can find it before
anything is paired. Two transports carry the same information, because mDNS
never leaves one LAN and a pair is often on another network.

### mDNS (one local network)

- Service type: `_msm-node._tcp.local.`
- Instance: `<label>._msm-node._tcp.local.`, where `<label>` is the node's
  hostname; it is also the target of the SRV record (`<label>.local.`).
- SRV port: the port that accepts a new console *right now* — the pairing port
  while unpaired, the operational port once a console is pinned. The node
  re-announces when that changes, so a browse never returns a closed port.
- TXT: `id=<base64 node id>`, `spki=<base64 pin>`, `v=1`.
- A record for `<label>.local.` carrying a **LAN** address. A Tailscale address
  (`100.64.0.0/10`) is useless to a multicast peer and is only used when the
  host has nothing else.
- Transport: UDP multicast to `224.0.0.251:5353`, TTL 120 s, announced at
  startup and on request, joining the interface that owns the advertised
  address. A query from a source port other than 5353 is answered unicast to
  that source (RFC 6762 §6.7).

### Tailscale (any network on the tailnet)

- The node listens for pairing on the fixed port **7334** (`--pair-listen`). A
  fixed port is what makes a peer askable without reading the node's console;
  a node started with port 0 is only visible to mDNS.
- The console reads the peer list from `tailscale status --json`, keeps online
  peers with an IPv4 address, and opens the pairing connection to
  `<peer>:7334`, presenting its own certificate.
- The advertisement *is* the normal `pair.hello` → `pair.challenge` exchange
  (§6): `node_id`, `node_spki` and `op_port` come from the challenge. The
  console stops there and sends no `pair.proof`, so a probe cannot consume a
  pairing attempt or pair anything by accident.
- A peer that answers nothing, or does not complete a TLS 1.3 handshake as an
  Ed25519 identity, is not listed.

Discovery only suggests a target. Trust still comes from pairing: the node's
pin arrives in the challenge and is verified against the certificate that
actually presented it, exactly as §6 requires.

## 10. Errors

```
{ "t": "error", "v": 1, "code": "<code>", "detail": "<human readable>" }
```

`detail` is for a human. It **must not** contain the pairing code, any key
material, any MAC, or any other secret.

| code | meaning | connection |
|---|---|---|
| `bad_frame` | zero-length, oversized, malformed JSON or non-object payload | closed |
| `unknown_type` | `t` is not a message type in this document | closed |
| `bad_version` | `v` is not 1 | closed |
| `bad_proof` | MAC mismatch, or SPKI binding mismatch | closed, attempt consumed |
| `expired` | the code's lifetime elapsed | closed, code rotated |
| `abuse` | attempts exhausted | closed, code rotated |
| `unauthorized` | operational request from an unpinned identity | closed |
| `internal` | unexpected local failure | closed |

`result` codes (these arrive inside a `result`, never as an `error` message):

| code | meaning |
|---|---|
| `bad_argument` | a field is missing, malformed or outside its documented range |
| `unsupported` | the node cannot perform this: no package manager, no init system, no `/proc` |
| `confirmation_required` | `host.reboot` without `confirm: "reboot"` |
| `failed` | the process ran and exited non-zero, or the command timed out |
| `busy` | another command is already running on this node |

## 11. Conformance requirements

An implementation is conformant for v1 only if its automated tests cover every
row that applies to it. Both repositories use these exact test names; the Go
suite prefixes them with `Test_`, which is the only difference. Rows marked
*node* test state that only the agent has (its log ring, its `logs.tail`
handling), so they exist in the Go suite alone.

The expected values in `hkdf_rfc5869` are the published RFC 5869 test case 1
vectors. The values in `derive_vectors` were produced by an independent Python
implementation of §7, so a mistake in one language cannot hide a mistake in the
other.

| requirement | test | side |
|---|---|---|
| frame round-trip | `frame_roundtrip` | both |
| zero-length frame rejected | `frame_zero_length` | both |
| frame over 1 MiB rejected | `frame_cap` | both |
| unknown `t` rejected | `frame_unknown_type` | both |
| `v != 1` rejected | `frame_bad_version` | both |
| code alphabet and length | `code_generate` | both |
| code normalisation and rejection | `code_normalise` | both |
| HKDF matches RFC 5869 test case 1 | `hkdf_rfc5869` | both |
| transcript and proofs are deterministic and code-sensitive | `derive_vectors` | both |
| Ed25519 SPKI is the fixed 44-byte form | `spki_ed25519` | both |
| every request and `result` round-trips | `command_roundtrip` | both |
| package name charset is enforced | `package_name_charset` | both |
| unit charset is enforced | `unit_charset` | both |
| request id charset is enforced | `request_id_charset` | both |
| `result` envelope carries or omits members correctly | `command_result_envelope` | both |
| `logs.tail` bounds are enforced | `logs_tail_bounds` | node |
| log ring keeps the newest lines and counts drops | `log_ring` | node |
| `ssh.authorize` validates before writing anything | `ssh_authorize` | node |
| account names cannot smuggle flags or paths | `account_charset` | both |
| `pair.proof` omits `setup` when it was not answered | `setup_travels_only_when_answered` | both |
| `node.setup` applies, persists and refuses a bad account | `node_setup_command` | node |
| the console trusts the node key and reuses it across sessions | `ssh_key_trust` | client |
| the mDNS answer carries PTR, SRV, TXT and A | `mdns_response` | node |
| an mDNS answer parses into one endpoint | `mdns_parses_an_answer` | client |
| the console SSH key round-trips through its OpenSSH encoding | `ssh_key_roundtrip` | client |
