# msm

The MSM management console. A Rust binary that pairs with [MSM Nodes](https://github.com/Multi-Server-Manager/MSMNode).

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
msm pair --addr 100.74.163.8:7334 --code 7K3M9QXA --label sanas \
         --run-as root --ssh-user root --ssh-port 22
msm nodes
msm info sanas
msm setup sanas --ssh-port 2200            # change the answers, no restart
```

## The panel

| key | what it does |
|---|---|
| `j` / `k`, `space`, `a` | move, mark, mark all |
| `enter` | open a node |
| `u` `i` `r` `l` | update, install, restart, logs |
| `s` | SSH login **inside the panel** |
| `e` | edit name, address, ssh user/port and the account commands run as |
| `x` | end the SSH login of the highlighted node |
| `f` | sftp (hands the terminal over) |
| `p`, `q` | pair, quit |

## Testing & Contributing
[docs/TESTING.md](docs/TESTING.md) is the full plan for testing changes.
[CONTRIBUTING.md](CONTRIBUTING.md) is going to be created soon.