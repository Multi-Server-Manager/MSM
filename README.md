# msm

The MSM management console. A Rust binary that pairs with [MSM Console](https://github.com/Multi-Server-Manager/MSMNode).

The wire format lives in [docs/PROTOCOL.md](docs/PROTOCOL.md). That file is the
single source of truth for both this repository and the Go node agent, nothing
here may contradict it.

## Install

*Installs & stays updated via Nebuff Repo*

```sh
curl -sSL https://install.nebuff.xyz/msm | bash
```

## Build

```sh
cargo build --release
```

## Use

```sh
msm                      
# the panel, over the nodes in ~/.msm
msm discover                              
# unpaired nodes, mDNS and tailnet
msm pair --addr 100.74.163.8:7334 --code 7K3M9QXA --label sanas
msm nodes
msm info sanas
```

## Testing & Contributing
[docs/TESTING.md](docs/TESTING.md) is the full plan for testing changes.
[CONTRIBUTING.md](CONTRIBUTING.md) is going to be created soon.