//! `msm` — the MSM management console.

mod discovery;
mod fanout;
mod human;
mod mdns;
mod net;
mod render;
mod session;
mod sshkey;
mod store;
mod tailnet;
mod tui;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use msm_protocol::ProtocolError;
use msm_protocol::commands::Command as Request;
use msm_protocol::messages::Setup;

use crate::fanout::Outcome;
use crate::store::NodeRecord;

#[derive(Debug, Parser)]
#[command(name = "msm", version, about = "Multi Server Manager console")]
struct Cli {
    /// Directory holding the console identity and node pins.
    #[arg(long, global = true, value_name = "DIR", default_value_os_t = store::default_state_dir())]
    state_dir: PathBuf,

    /// Render one screen headlessly and print it. For tests and screenshots.
    #[arg(long, global = true, value_name = "SCREEN", hide = true)]
    render: Option<String>,

    /// Width of the headless render.
    #[arg(long, global = true, default_value_t = 80, hide = true)]
    render_width: u16,

    /// Height of the headless render.
    #[arg(long, global = true, default_value_t = 24, hide = true)]
    render_height: u16,

    #[command(subcommand)]
    command: Option<Invocation>,
}

/// Which nodes a command goes to.
#[derive(Debug, Args)]
struct Selection {
    /// Node label or id. Repeat to fan out.
    #[arg(long = "node", value_name = "TARGET")]
    nodes: Vec<String>,

    /// Every paired node.
    #[arg(long, conflicts_with = "nodes")]
    all: bool,

    /// Print one JSON object per node instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum Invocation {
    /// Pair with a node using the one-time code it printed.
    Pair {
        /// Address printed by the node, e.g. 100.74.163.8:41234.
        #[arg(long, value_name = "HOST:PORT")]
        addr: String,
        /// The eight-character code printed by the node.
        #[arg(long, value_name = "CODE")]
        code: String,
        /// Name to store for this node.
        #[arg(long, value_name = "NAME", default_value = "")]
        label: String,
        /// Account commands on the node run as; blank keeps the node's answer.
        #[arg(long, value_name = "ACCOUNT", default_value = "")]
        run_as: String,
        /// Account the console's SSH key is installed for; blank keeps the
        /// node's answer.
        #[arg(long, value_name = "ACCOUNT", default_value = "")]
        ssh_user: String,
        /// Port the console dials for SSH; 0 keeps the node's answer.
        #[arg(long, value_name = "PORT", default_value_t = 0)]
        ssh_port: u16,
    },

    /// List paired nodes.
    Nodes,

    /// Change where a node runs commands and where SSH logins land.
    Setup {
        /// Node label, or node id.
        target: String,
        /// Account commands on the node run as.
        #[arg(long, value_name = "ACCOUNT")]
        run_as: Option<String>,
        /// Account the console's SSH key is installed for.
        #[arg(long, value_name = "ACCOUNT")]
        ssh_user: Option<String>,
        /// Port the console dials for SSH.
        #[arg(long, value_name = "PORT")]
        ssh_port: Option<u16>,
    },

    /// Look for nodes that are waiting to be paired.
    Discover {
        /// How long to wait for multicast DNS answers, in milliseconds.
        #[arg(long, default_value_t = 1200)]
        wait: u64,
        /// Skip mDNS and only ask Tailscale peers (port 7334).
        #[arg(long)]
        tailnet_only: bool,
    },

    /// Ask a paired node for its identity.
    Info {
        /// Node label, or node id.
        target: String,
    },

    /// Upgrade every installed package.
    Update {
        #[command(flatten)]
        selection: Selection,
    },

    /// Install one package.
    Install {
        /// Package name, e.g. dpkg, ripgrep.
        name: String,
        #[command(flatten)]
        selection: Selection,
    },

    /// Restart a service, or the agent itself when no unit is given.
    Restart {
        /// systemd unit name; omit to restart msm-node itself.
        unit: Option<String>,
        #[command(flatten)]
        selection: Selection,
    },

    /// Reboot the machine. The node refuses without --confirm reboot.
    Reboot {
        /// Must be exactly `reboot`; anything else (or nothing) is refused.
        #[arg(long, value_name = "TOKEN")]
        confirm: Option<String>,
        #[command(flatten)]
        selection: Selection,
    },

    /// Sample load, memory, disk and uptime.
    Metrics {
        #[command(flatten)]
        selection: Selection,
    },

    /// Show the node's own recent log lines.
    Logs {
        /// How many lines, 1-500.
        lines: u32,
        #[command(flatten)]
        selection: Selection,
    },
}

/// A failure that is not a node refusal: usage mistakes and transport errors.
#[derive(Debug)]
enum Failure {
    Usage(String),
    Protocol(ProtocolError),
    /// A failure already phrased for an operator, used where a protocol error
    /// needs the address it was aimed at (`human::pairing`).
    Message(String),
}

impl From<ProtocolError> for Failure {
    fn from(err: ProtocolError) -> Self {
        Self::Protocol(err)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(Failure::Usage(message)) => {
            eprintln!("msm: {message}");
            ExitCode::from(2)
        }
        Err(Failure::Protocol(err)) => {
            eprintln!("msm: {err}");
            ExitCode::FAILURE
        }
        Err(Failure::Message(message)) => {
            eprintln!("msm: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut cli: Cli) -> Result<ExitCode, Failure> {
    if let Some(screen) = cli.render.clone() {
        return render_screen(&cli, &screen);
    }

    let command = match cli.command.take() {
        Some(command) => command,
        None => {
            if !std::io::stdout().is_terminal() {
                return Err(Failure::Usage(
                    "the panel needs a terminal; run a subcommand instead".into(),
                ));
            }
            tui::run(&cli.state_dir)?;
            return Ok(ExitCode::SUCCESS);
        }
    };

    match command {
        Invocation::Pair {
            addr,
            code,
            label,
            run_as,
            ssh_user,
            ssh_port,
        } => {
            let setup = Setup {
                run_as,
                ssh_user,
                ssh_port,
            };
            let outcome = net::pair(&cli.state_dir, &addr, &code, &label, &setup)
                .map_err(|err| Failure::Message(human::pairing(&err, &addr)))?;
            let record = outcome.record;
            println!(
                "PAIRED node_id={} label={} host={} op_port={}",
                record.node_id,
                name_of(&record.label),
                record.host,
                record.op_port
            );
            println!(
                "SETUP run_as={} ssh_user={} ssh_port={}",
                record.run_as, record.ssh_user, record.ssh_port
            );
            match outcome.ssh_warning {
                Some(warning) => eprintln!("msm: {warning}"),
                None => println!(
                    "SSH keys traded: console key installed for {}@{}, node key trusted here",
                    record.ssh_user, record.host
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Nodes => {
            list_nodes(&cli.state_dir)?;
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Setup {
            target,
            run_as,
            ssh_user,
            ssh_port,
        } => {
            let record = store::find_node(&cli.state_dir, &target)?;
            let setup = Setup {
                run_as: run_as.unwrap_or_else(|| record.run_as.clone()),
                ssh_user: ssh_user.unwrap_or_else(|| record.ssh_user.clone()),
                ssh_port: ssh_port.unwrap_or(record.ssh_port),
            };
            let (updated, warning) = net::configure(&cli.state_dir, &record, &setup)?;
            if let Some(warning) = &warning {
                eprintln!("msm: {warning}");
            }

            // The key has to be in the new account's file, or the next login
            // would be refused.
            if updated.ssh_user != record.ssh_user {
                let key = crate::sshkey::SshKey::load_or_create(&cli.state_dir)?;
                let result = net::authorize_ssh_key(
                    &cli.state_dir,
                    &updated,
                    &key.public_line,
                    &updated.ssh_user,
                )?;
                println!("SSH key installed in {} ({})", result.user, result.path);
            }
            println!(
                "SETUP run_as={} ssh_user={} ssh_port={}",
                updated.run_as, updated.ssh_user, updated.ssh_port
            );
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Discover { wait, tailnet_only } => {
            let found = if tailnet_only {
                discovery::browse_tailnet(&cli.state_dir)
            } else {
                discovery::browse(&cli.state_dir, Duration::from_millis(wait))
            };
            if found.is_empty() {
                if tailnet_only {
                    println!("no nodes answered on the tailnet");
                } else {
                    println!("no nodes answered on the LAN or the tailnet");
                }
                println!(
                    "a node on another network must listen on port {}",
                    tailnet::PAIR_PORT
                );
                return Ok(ExitCode::SUCCESS);
            }
            for node in found {
                println!(
                    "{:<20} {:<26} {}",
                    node.label,
                    node.endpoint(),
                    node.node_id.as_deref().unwrap_or("-")
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Info { target } => {
            let summary = net::info(&cli.state_dir, &target)?;
            println!(
                "node_id={} hostname={} os={} version={} pinned_clients={}",
                summary.node_id,
                summary.hostname,
                summary.os,
                summary.version,
                summary.pinned_clients
            );
            if let Some(setup) = summary.setup {
                println!(
                    "SETUP run_as={} ssh_user={} ssh_port={}",
                    setup.run_as, setup.ssh_user, setup.ssh_port
                );
            }
            if !summary.ssh_key.is_empty() {
                println!("SSH key {}", summary.ssh_key);
            }
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Update { selection } => {
            dispatch(&cli.state_dir, &selection, Request::PkgUpdate)
        }
        Invocation::Install { name, selection } => {
            dispatch(&cli.state_dir, &selection, Request::PkgInstall(name))
        }
        Invocation::Restart { unit, selection } => dispatch(
            &cli.state_dir,
            &selection,
            Request::SvcRestart(unit.unwrap_or_default()),
        ),
        Invocation::Reboot { confirm, selection } => dispatch(
            &cli.state_dir,
            &selection,
            Request::HostReboot(confirm.unwrap_or_default()),
        ),
        Invocation::Metrics { selection } => {
            dispatch(&cli.state_dir, &selection, Request::MetricsSample)
        }
        Invocation::Logs { lines, selection } => {
            dispatch(&cli.state_dir, &selection, Request::LogsTail(lines))
        }
    }
}

/// Draw one screen at a fixed size and print it, with no terminal involved.
fn render_screen(cli: &Cli, name: &str) -> Result<ExitCode, Failure> {
    let screen = tui::ui::screen_by_name(name).ok_or_else(|| {
        Failure::Usage(format!(
            "unknown screen {name:?}; try nodes, pair, detail or logs"
        ))
    })?;

    let mut app = tui::App::new(&cli.state_dir)?;
    app.screen = screen;
    if screen == tui::Screen::Logs {
        app.open_logs();
    }

    // Screens that show live data wait for it, but never longer than a node
    // that does not answer would be worth.
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        app.tick();
        let ready = match screen {
            // A single sample makes a one-character sparkline; wait for a
            // series so the render shows what the screen really looks like.
            tui::Screen::Detail => app
                .current()
                .map(|view| view.history.len() >= 4)
                .unwrap_or(true),
            tui::Screen::Logs => !app.logs.lines.is_empty(),
            _ => true,
        };
        if ready {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    print!(
        "{}",
        tui::ui::render_screen(&mut app, screen, cli.render_width, cli.render_height)
    );
    Ok(ExitCode::SUCCESS)
}

/// Run one request against the selected nodes and report every answer.
fn dispatch(
    state_dir: &Path,
    selection: &Selection,
    request: Request,
) -> Result<ExitCode, Failure> {
    let nodes = resolve(state_dir, selection)?;
    let outcomes = fanout::execute(&nodes, state_dir, &request);

    let width = outcomes
        .iter()
        .map(|outcome| outcome.label.len())
        .max()
        .unwrap_or(5)
        .max(5);

    for outcome in &outcomes {
        if selection.json {
            println!("{}", json_line(outcome));
            continue;
        }
        for line in render::lines(outcome, &request, width) {
            println!("{line}");
        }
    }

    let failed = outcomes.iter().filter(|o| !o.succeeded()).count();
    if !selection.json && outcomes.len() > 1 {
        println!(
            "{} nodes: {} ok, {failed} failed",
            outcomes.len(),
            outcomes.len() - failed
        );
    }

    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Turn `--node` / `--all` into the node records to contact.
fn resolve(state_dir: &Path, selection: &Selection) -> Result<Vec<NodeRecord>, Failure> {
    if selection.all {
        let nodes = store::load_nodes(state_dir)?;
        if nodes.is_empty() {
            return Err(Failure::Usage("no paired nodes to act on".into()));
        }
        return Ok(nodes);
    }
    if selection.nodes.is_empty() {
        return Err(Failure::Usage(
            "choose nodes with --node <TARGET> (repeatable) or --all".into(),
        ));
    }

    selection
        .nodes
        .iter()
        .map(|target| store::find_node(state_dir, target).map_err(Failure::Protocol))
        .collect()
}

fn json_line(outcome: &Outcome) -> String {
    let value = match &outcome.reply {
        Ok(message) => serde_json::json!({
            "node": outcome.label,
            "endpoint": outcome.endpoint,
            "ok": outcome.succeeded(),
            "took_ms": outcome.elapsed.as_millis(),
            "result": message,
        }),
        Err(err) => serde_json::json!({
            "node": outcome.label,
            "endpoint": outcome.endpoint,
            "ok": false,
            "error": err.to_string(),
        }),
    };
    value.to_string()
}

fn list_nodes(state_dir: &Path) -> msm_protocol::Result<()> {
    let nodes = store::load_nodes(state_dir)?;
    if nodes.is_empty() {
        println!("no paired nodes");
        return Ok(());
    }
    let label_width = nodes
        .iter()
        .map(|node| name_of(&node.label).len())
        .max()
        .unwrap_or(5)
        .max(5);
    let host_width = nodes
        .iter()
        .map(|node| node.host.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!(
        "{:<label_width$} {:<host_width$} {:<6} NODE ID",
        "LABEL", "HOST", "PORT"
    );
    for node in nodes {
        println!(
            "{:<label_width$} {:<host_width$} {:<6} {}",
            name_of(&node.label),
            node.host,
            node.op_port,
            node.node_id
        );
    }
    Ok(())
}

fn name_of(label: &str) -> &str {
    if label.is_empty() { "-" } else { label }
}
