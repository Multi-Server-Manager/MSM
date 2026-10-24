# Testing without touching the real repository

The rule: **nothing below writes to `repo.nebuff.xyz`, `install.nebuff.xyz`, or a
release page.** Builds are local, packages are signed with a staging key, and
the staging repository is served from a loopback port. `./publish.sh` is only
ever run after the gates at the bottom of this file pass, and never from a test
branch.

Every layer is cheap to re-run and leaves nothing behind: throwaway state
directories, throwaway keys, containers removed with `--rm`.

## 0. Unit tests (seconds)

```sh
cd MSM      && cargo test
cd MSMNode  && go test ./...
```

Covers the frame codec, the pairing derivation vectors, the pin/SPKI rules, the
panel's headless rendering, the pairer's expiry and attempt budget, and the
address ordering (Tailscale before LAN).

## 1. Loopback end-to-end (one host, no root)

`scripts/e2e.sh` starts a real node per scenario on random ports with a
throwaway state directory, then drives the real console against it.

```sh
cd MSM
go build -C ../MSMNode -o /tmp/msmt/msm-node ./cmd/msm-node
cargo build
NODE_BIN=/tmp/msmt/msm-node CLIENT_BIN=$PWD/target/debug/msm \
  WORK=/tmp/msm-e2e DIAL_HOST=127.0.0.1 ./scripts/e2e.sh
```

What it proves: pairing succeeds once and only once, a wrong code burns an
attempt, the code rotates on abuse, a pinned console is the only one the
operational port answers, and every command returns a structured result.

Two things it cannot prove, which is why the next layers exist: multicast and
the tailnet.

## 2. Discovery on a real network, and a fake tailnet

mDNS is what breaks silently in the field (access points that drop multicast, a
default route that ends in a tunnel). The panel's own probe is the test:

```sh
# terminal 1: a node, announced the way the package starts it
/tmp/msmt/msm-node --state-dir /tmp/lab/node        # pair port 7334

# terminal 2: a fresh console
msm --state-dir /tmp/lab/console
#   p  →  d  →  the node is listed with a host:port that accepts a connection
#   enter        (during the browse: it must be remembered, not dropped)
#   <code>  →  enter
```

The tailnet path is exercised deterministically with a stub CLI, no second
machine and no Tailscale account:

```sh
mkdir -p /tmp/lab/bin
cat > /tmp/lab/bin/tailscale <<'EOF'
#!/bin/sh
[ "$1" = status ] || exit 1
cat <<'JSON'
{"Peer":{"k1":{"HostName":"tailbox","Online":true,"TailscaleIPs":["127.0.0.1"]},
         "k2":{"HostName":"offline-box","Online":false,"TailscaleIPs":["127.0.0.2"]}}}
JSON
EOF
chmod +x /tmp/lab/bin/tailscale

MSM_TAILSCALE=/tmp/lab/bin/tailscale msm discover --tailnet-only
#   tailbox   127.0.0.1:7334   <base64 node id>
MSM_TAILSCALE=/tmp/lab/bin/tailscale msm discover
#   exactly one row: the same node must not appear twice (mDNS + tailnet)
```

What this covers: peer listing, the IPv4 filter, the offline filter, the
greeting probe (a real `pair.hello` against a real node), the dedupe, and the
`PAIR ... addrs=` line naming the Tailscale address first. `scripts/e2e.sh`
scenario `t13` runs the same thing automatically; it reads a random pairing
port from `MSM_TAILNET_PORT` instead of binding the real 7334, so the suite can
run on a busy host.

The same test catches the regression that made discovery look broken: after
pairing, the node must re-announce the **operational** port and close the
pairing one. Check the node's log for a second `MDNS ... port=` line after
`PAIRING closed`, confirm the pairing port refuses connections, and run
`msm discover` again — the endpoint must be reachable. `t13` asserts all three.

## 3. The panel in a pty

```sh
cd MSM
python3 scripts/tui_probe.py --binary target/debug/msm \
  --state-dir /tmp/lab/tui --code <code> --expect-label <hostname>
```

It types into a real terminal: pair from a discovered result, list the node,
open it, wait for the sparkline, run an update and an install, open an SSH
login in the panel, detach it with `ctrl-\` (the byte `0x1c`, which needs no
keyboard protocol), resume it with `s` and see the output that arrived while it
was detached, detach again with `esc`, end it with `x` from the panel, hand the
terminal to `sftp` and come back, resize, quit. A redraw bug or a swallowed key
shows up here and nowhere else.

Sizing is covered twice: `tui/tests.rs` renders every screen at 80x24, 100x30
and 40x15 and asserts the panel fills the terminal exactly (header on the first
row, help on the last, no extra row), and the live pty run prints a marker on
the remote's own last row and on a resized terminal, so the SSH grid is proven
to be sized from the measured chrome rather than a guessed constant.

## 4. Packages, from a staging repository

This is the layer the real repository used to be needed for. `./publish.sh`
pushes to sanas and purges the CDN; the staging loop does neither.

1. **Staging key, generated once, never the release key**

   ```sh
   mkdir -p build/staging/gnupg && chmod 700 build/staging/gnupg
   gpg --homedir build/staging/gnupg --batch --passphrase '' --quick-gen-key \
       'MSM Staging <staging@invalid>' ed25519 sign never
   ```

2. **Build the packages into a staging pool** (`MSMBuilds/build-packages.sh`
   with `OUT=$PWD/build/staging/repo` and `GNUPGHOME=../build/staging/gnupg`),
   version stamped `X.Y.Z~staging.N` so a staging build can never be mistaken
   for a release.

3. **Index it with the same script the real repo uses**

   ```sh
   REPO_GNUPGHOME=$PWD/build/staging/gnupg REPO_URL=http://127.0.0.1:8099/repo \
     ./bin/repo-index.sh --mirror build/staging/repo
   ```

4. **Serve it on loopback**

   ```sh
   python3 -m http.server 8099 --bind 127.0.0.1 --directory build/staging
   ```

5. **Install from it in a disposable container**, one per family, so the real
   managers run against the staging URL:

   ```sh
   podman run --rm --network host -v $PWD/build/staging:/staging:ro archlinux:latest bash -lc '
     printf "[msm-staging]\nSigLevel = Optional TrustAll\nServer = http://127.0.0.1:8099/repo/arch\n" \
       > /etc/pacman.conf.d/staging 2>/dev/null || true
     pacman -Sy --noconfirm msm msm-node
     msm --version && msm-node --version'
   ```

   The same shape for `fedora:latest` (`dnf install` with `gpgcheck=0` and
   `repo_gpgcheck=0` against `/repo/rpm`), `debian:stable` (`apt-get` with
   `[trusted=yes]` against `/repo/deb`), `alpine:latest` (`apk` with
   `--allow-untrusted` against `/repo/apk`). Trust flags are only acceptable
   because the key is a staging key and the URL is loopback.

6. **Upgrade path**: install `X.Y.Z~staging.1`, then rebuild and re-index
   `X.Y.Z~staging.2`, and check that `pacman -Syu` / `dnf upgrade` /
   `apt-get upgrade` / `apk upgrade` moves the version. This is the cache
   question the real repository asks, tested without the CDN in the way.

## 5. Two machines on a test tailnet (manual, occasional)

Only when the discovery code changes. Join a spare VM to a *test* tailnet
(never the production one), start a node there, and from the console:

- `msm discover` lists it with the `100.x` address, not the LAN one;
- `msm pair --addr 100.x.y.z:7334 --code ...` pairs;
- `msm metrics --node <label>` and the panel's detail screen work over the
  tunnel;
- the panel's `s` opens SSH over the tailnet.

## 6. What still cannot be automated

- **ARM**: packages are built, signed and indexed for `aarch64`/`arm` but never
  executed. An arm runner, or one spare board, is the only fix.
- **A real tailnet**: the stub proves the code path, not Tailscale's own ACLs,
  MagicDNS or an exit node.
- **The CDN**: cache behaviour only exists on the real edge. The deploy script
  purges and then verifies every metadata spelling, which is the closest a
  local test can get.

## Gates before `./publish.sh`

Run in this order; stop at the first failure.

1. `cargo test` and `go test ./...` clean.
2. `scripts/e2e.sh` clean against freshly built binaries.
3. `scripts/tui_probe.py` clean (pair, update, install, ssh, sftp, resize).
4. Staging install + upgrade in all four package families.
5. `bin/repo-index.sh --check` on the real mirror *after* deploy, which the
   deploy itself already insists on.
6. Version, `VERSION` files, listing pages and `versions.json` agree — the
   release script's own check, run before the tag, not after.
