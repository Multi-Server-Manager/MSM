//! Headless render tests: every screen draws, at a fixed size, with no terminal.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use msm_protocol::commands::Command;

use super::app::{App, NodeView, Screen, Status};
use super::ui::{bar, render_screen, sparkline};
use super::worker::Sample;
use crate::store::{self, NodeRecord};

static NEXT: AtomicU32 = AtomicU32::new(1);

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(nodes: usize) -> Self {
        Self::build(nodes, "10.89.0", 7333)
    }

    /// A sandbox whose nodes answer on `127.0.0.x:port`; port 1 refuses
    /// instantly, which is how the tests below exercise the failure path.
    fn unreachable(nodes: usize) -> Self {
        Self::build(nodes, "127.0.0", 1)
    }

    fn build(nodes: usize, host: &str, port: u16) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "msm-tui-test-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the sandbox");

        for index in 0..nodes {
            let label = format!("node-{}", index + 1);
            let record = NodeRecord {
                node_id: format!("id-{index}"),
                spki: "spki".to_string(),
                label,
                host: format!("{host}.{}", index + 3),
                op_port: port,
                paired_at: 0,
                ssh_user: "root".to_string(),
                ssh_port: 22,
                run_as: "root".to_string(),
                node_ssh_key: String::new(),
            };
            store::save_node(&dir, record).expect("save a node");
        }

        Self { dir }
    }

    fn app(&self) -> App {
        App::new(&self.dir).expect("build the panel")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn tui_nodes_screen() {
    let sandbox = Sandbox::new(2);
    let mut app = sandbox.app();
    app.screen = Screen::Nodes;

    let text = render_screen(&mut app, Screen::Nodes, 80, 20);
    assert!(text.contains("msm  nodes"), "{text}");
    assert!(text.contains("2 nodes"), "{text}");
    assert!(text.contains("node-1"), "{text}");
    assert!(text.contains("node-2"), "{text}");
    assert!(text.contains("LABEL"), "{text}");
    assert!(text.contains("ADDRESS"), "{text}");
    assert!(text.contains("10.89.0.3:7333"), "{text}");
    assert!(text.contains("root@10.89.0.3:22"), "{text}");
    // The first row is selected and the only row is not marked.
    let selected = text
        .lines()
        .find(|line| line.contains("node-1"))
        .expect("the first row");
    assert!(selected.trim_start().starts_with('>'), "{selected}");
    assert!(text.contains("q quit"), "{text}");
}

#[test]
fn tui_pair_screen() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.pair.address = "10.89.0.5:41234".to_string();
    app.pair.code = "7K3M9QXA".to_string();

    let text = render_screen(&mut app, Screen::Pair, 80, 20);
    assert!(text.contains("msm  pair"), "{text}");
    assert!(text.contains("_msm-node._tcp"), "{text}");
    assert!(text.contains("10.89.0.5:41234"), "{text}");
    assert!(text.contains("7K3M9QXA"), "{text}");
    assert!(text.contains("d discover"), "{text}");
}

#[test]
fn tui_detail_screen_shows_a_sparkline() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let node = app.nodes.get_mut(0).expect("one node");
    node.status = Status::Ok;
    for load in [0.05, 0.4, 0.2, 0.9, 0.3] {
        node.history.push_back(Sample {
            load1: load,
            memory_pct: 41.0,
            memory_total_kb: 2_048_000,
            disk_pct: 12.0,
        });
    }
    node.last = "metrics  ok".to_string();

    let text = render_screen(&mut app, Screen::Detail, 80, 22);
    assert!(text.contains("msm  node-1"), "{text}");
    assert!(text.contains("load"), "{text}");
    assert!(text.contains("5 samples"), "{text}");
    assert!(text.contains("41% of 2000 MiB"), "{text}");
    assert!(text.contains('@'), "the peak sample should reach the top of the ramp: {text}");
    assert!(text.contains("metrics  ok"), "{text}");
}

#[test]
fn tui_logs_screen() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.logs.node = Some("id-0".to_string());
    app.logs.lines = vec![
        "MSM-NODE id=abc version=0.1.0".to_string(),
        "LISTEN addr=[::]:7333".to_string(),
        "COMMAND dnf -y upgrade".to_string(),
    ];

    let text = render_screen(&mut app, Screen::Logs, 80, 20);
    assert!(text.contains("msm  logs  node-1"), "{text}");
    assert!(text.contains("3 lines"), "{text}");
    assert!(text.contains("COMMAND dnf -y upgrade"), "{text}");
}

#[test]
fn tui_actions_target_the_highlighted_or_marked_nodes() {
    let sandbox = Sandbox::new(2);
    let mut app = sandbox.app();

    assert_eq!(app.targets().len(), 1, "one node by default");
    app.selected = 1;
    assert_eq!(app.targets()[0].label, "node-2");

    app.marked.insert("id-0".to_string());
    app.marked.insert("id-1".to_string());
    assert_eq!(app.targets().len(), 2, "the marked set wins");

    app.prompt = Some(super::app::Prompt {
        title: "install package".to_string(),
        value: "ripgrep".to_string(),
    });
    let text = render_screen(&mut app, Screen::Nodes, 80, 20);
    assert!(text.contains("install package: ripgrep_"), "{text}");
}

#[test]
fn tui_fan_out_updates_every_marked_node() {
    // Both nodes refuse the connection, which is the real failure path: every
    // marked row must go running and then failed, on its own thread.
    let sandbox = Sandbox::unreachable(2);
    let mut app = sandbox.app();
    app.marked = app.nodes.iter().map(|view| view.record.node_id.clone()).collect();
    app.start(Command::MetricsSample);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        app.tick();
        if app.nodes.iter().all(|view| view.status == Status::Failed) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    for view in &app.nodes {
        assert_eq!(view.status, Status::Failed, "{} did not fail", view.name());
        assert!(!view.last.is_empty(), "{} has no result", view.name());
    }
    assert!(
        app.nodes.iter().all(|view| {
            ((view.last.contains("listening") || view.last.contains("cannot reach"))
                && view.last.contains(":1"))
                || view.last.contains("msm-node")
        }),
        "the panel should show why: {:?}",
        app.nodes.iter().map(|view| &view.last).collect::<Vec<_>>()
    );

    // The node list paints that state.
    let text = render_screen(&mut app, Screen::Nodes, 80, 20);
    assert_eq!(text.matches("failed").count(), 2, "{text}");
}

#[test]
fn tui_sparkline_and_bar() {
    let ramp = sparkline(&[0.0, 0.5, 1.0], 8);
    assert_eq!(ramp.chars().count(), 3);
    assert!(ramp.starts_with(' '), "{ramp}");
    assert!(ramp.ends_with('@'), "{ramp}");

    assert_eq!(bar(0.0, 4), "[....]");
    assert_eq!(bar(50.0, 4), "[##..]");
    assert_eq!(bar(100.0, 4), "[####]");
    assert_eq!(bar(200.0, 2), "[##]");

    // A width smaller than the series keeps the newest samples.
    let clipped = sparkline(&[1.0, 1.0, 0.0, 1.0], 2);
    assert_eq!(clipped.chars().count(), 2);
}

#[test]
fn tui_commands_are_the_protocol_commands() {
    // The panel must drive the same requests the CLI does.
    assert_eq!(
        Command::PkgInstall("aero".into()).describe(),
        "pkg.install aero"
    );
    let view = NodeView::new(NodeRecord {
        node_id: "id".to_string(),
        spki: "spki".to_string(),
        label: String::new(),
        host: "host".to_string(),
        op_port: 1,
        paired_at: 0,
        ssh_user: "root".to_string(),
        ssh_port: 22,
        run_as: "root".to_string(),
        node_ssh_key: String::new(),
    });
    assert_eq!(view.name(), "id", "an unlabelled node shows its id");
}

fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}

fn discovered(label: &str, host: &str, port: u16) -> crate::mdns::Discovered {
    crate::mdns::Discovered {
        label: label.to_string(),
        address: host.parse().expect("an IP address"),
        port,
        node_id: Some(format!("id-{label}")),
        spki: Some("spki".to_string()),
    }
}

#[test]
fn enter_during_discovery_is_remembered() {
    // Enter arriving while the browse is still running used to be dropped,
    // which is the "sometimes enter does nothing" report: the answer arrived a
    // second later and the field stayed empty.
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    app.screen = Screen::Pair;
    app.pair.busy = true;

    app.on_key(key(crossterm::event::KeyCode::Enter));
    assert!(app.pair.pick_when_found, "the press must be remembered");

    app.apply(super::worker::Msg::Discovered(vec![discovered(
        "tailbox",
        "10.89.0.3",
        7334,
    )]));
    assert_eq!(app.pair.address, "10.89.0.3:7334");
    assert_eq!(app.pair.focus, super::app::Focus::Code);
    assert!(!app.pair.pick_when_found);
}

#[test]
fn enter_with_nothing_to_open_explains_itself() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    app.on_key(key(crossterm::event::KeyCode::Enter));
    assert!(app.status.contains("press p"), "status was {:?}", app.status);
}

#[test]
fn empty_discovery_points_at_the_agent() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    app.screen = Screen::Pair;
    app.pair.busy = true;
    app.apply(super::worker::Msg::Discovered(Vec::new()));
    assert!(!app.pair.busy);
    assert!(
        app.status.contains("msm-node"),
        "status was {:?}",
        app.status
    );
}

#[test]
fn progress_bar_moves_and_keeps_its_width() {
    use std::time::Duration;
    let first = super::ui::progress_bar(Duration::ZERO, 16);
    let later = super::ui::progress_bar(Duration::from_millis(900), 16);
    assert_eq!(first.chars().count(), 18, "brackets plus 16 cells");
    assert_eq!(later.chars().count(), 18);
    assert_ne!(first, later, "the band has to move");
    assert!(first.starts_with('[') && first.ends_with(']'));
    assert_eq!(super::ui::progress_bar(Duration::from_secs(4), 16).matches('=').count(), 4);
}

#[test]
fn clock_reads_as_seconds_then_minutes() {
    use std::time::Duration;
    assert_eq!(super::ui::clock(Duration::ZERO), "0s");
    assert_eq!(super::ui::clock(Duration::from_secs(14)), "14s");
    assert_eq!(super::ui::clock(Duration::from_secs(64)), "1m 04s");
    assert_eq!(super::ui::clock(Duration::from_secs(600)), "10m 00s");
}

#[test]
fn activity_line_names_the_work_and_counts_nodes() {
    use std::time::Duration;
    let line = super::ui::activity_line(
        "updating packages",
        Duration::from_secs(12),
        Some((1, 3)),
        100,
    );
    assert!(line.contains("updating packages..."), "{line}");
    assert!(line.contains("12s"), "{line}");
    assert!(line.contains("(1/3 nodes)"), "{line}");
    assert!(!line.contains("running"), "{line}");
}

#[test]
fn a_command_shows_what_it_is_doing_and_then_its_error() {
    use std::time::{Duration, Instant};
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.busy = Some(super::app::Busy {
        id: 7,
        what: "pkg.install htop".to_string(),
        label: "installing htop".to_string(),
        started: Instant::now() - Duration::from_secs(3),
        total: 1,
        remaining: 1,
    });

    app.apply(super::worker::Msg::Started {
        node: "id-0".to_string(),
        id: 7,
    });
    assert_eq!(app.nodes[0].doing.as_deref(), Some("installing htop"));

    // The row and the status area both say what is happening, with a bar and a
    // clock instead of the word "running".
    let text = render_screen(&mut app, Screen::Nodes, 100, 24);
    assert!(text.contains("installing htop"), "{text}");
    assert!(text.contains("..."), "{text}");
    assert!(text.contains("3s"), "{text}");

    app.apply(super::worker::Msg::Finished {
        node: "id-0".to_string(),
        id: 7,
        ok: false,
        summary: "nothing is listening at 10.0.0.3:1; is msm-node running?".to_string(),
    });
    assert!(app.busy.is_none(), "the bar has to stop");
    assert!(app.nodes[0].doing.is_none());
    assert!(app.status.contains("pkg.install htop"), "{}", app.status);
    assert!(app.status.contains("error:"), "{}", app.status);
    assert!(app.status.contains("listening"), "{}", app.status);
}

#[test]
fn a_background_refresh_does_not_wipe_the_last_message() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.status = "paired with node-1, SSH key installed".to_string();

    app.apply(super::worker::Msg::Finished {
        node: "id-0".to_string(),
        id: super::worker::BACKGROUND,
        ok: true,
        summary: "ok".to_string(),
    });
    assert_eq!(app.status, "paired with node-1, SSH key installed");
}

#[test]
fn a_long_pairing_error_wraps_and_keeps_every_word() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    app.screen = Screen::Pair;
    app.apply(super::worker::Msg::Failed(
        "cannot reach 100.74.163.8:7334; check the network or the tailnet, and that the node's firewall allows TCP 7333-7334".to_string(),
    ));

    let text = render_screen(&mut app, Screen::Pair, 80, 24);
    assert!(text.contains("cannot reach 100.74.163.8:7334"), "{text}");
    // The tail used to be cut at the terminal edge, which is the one word an
    // operator needs when a firewall is the reason nothing answered.
    assert!(text.contains("7333-7334"), "{text}");
}

#[test]
fn a_pairing_failure_is_marked_and_explained() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    app.screen = Screen::Pair;

    app.apply(super::worker::Msg::Failed(
        "the node rejected that code. Check the eight characters and try again".to_string(),
    ));
    assert!(app.status.starts_with("error: "), "{}", app.status);
    assert!(app.status.contains("rejected that code"), "{}", app.status);
    assert!(!app.pair.busy);
}

#[test]
fn pair_screen_asks_where_things_run() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();

    let text = render_screen(&mut app, Screen::Pair, 80, 26);
    assert!(text.contains("setup (blank = the node's own answer)"), "{text}");
    assert!(text.contains("ssh user"), "{text}");
    assert!(text.contains("ssh port"), "{text}");
    assert!(text.contains("commands as"), "{text}");
    assert!(text.contains("name"), "{text}");
}

#[test]
fn the_edit_dialog_renames_and_repoints_a_node() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.screen = Screen::Nodes;

    app.on_key(key(crossterm::event::KeyCode::Char('e')));
    assert!(app.edit.is_some(), "e did not open the editor");

    // The label field holds the old name; replace it.
    for _ in 0..app.edit.as_ref().map(|form| form.label.len()).unwrap_or(0) {
        app.on_key(key(crossterm::event::KeyCode::Backspace));
    }
    for character in "prod".chars() {
        app.on_key(key(crossterm::event::KeyCode::Char(character)));
    }

    // host, ssh user, ssh port.
    for _ in 0..3 {
        app.on_key(key(crossterm::event::KeyCode::Tab));
    }
    for _ in 0..4 {
        app.on_key(key(crossterm::event::KeyCode::Backspace));
    }
    for character in "2200".chars() {
        app.on_key(key(crossterm::event::KeyCode::Char(character)));
    }

    let text = render_screen(&mut app, Screen::Nodes, 80, 30);
    assert!(text.contains("edit node"), "{text}");
    assert!(text.contains("prod"), "{text}");

    app.on_key(key(crossterm::event::KeyCode::Enter));
    assert!(app.edit.is_none(), "enter did not save");

    let nodes = store::load_nodes(&sandbox.dir).expect("reload");
    assert_eq!(nodes[0].label, "prod");
    assert_eq!(nodes[0].ssh_port, 2200);
    assert_eq!(app.nodes[0].record.label, "prod");
}

#[test]
fn the_edit_dialog_refuses_an_impossible_account() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.on_key(key(crossterm::event::KeyCode::Char('e')));

    // label -> host -> ssh user.
    app.on_key(key(crossterm::event::KeyCode::Tab));
    app.on_key(key(crossterm::event::KeyCode::Tab));
    for _ in 0..4 {
        app.on_key(key(crossterm::event::KeyCode::Backspace));
    }
    for character in "Root".chars() {
        app.on_key(key(crossterm::event::KeyCode::Char(character)));
    }

    app.on_key(key(crossterm::event::KeyCode::Enter));
    assert!(app.edit.is_some(), "a bad account closed the dialog");
    assert!(app.status.contains("not an account name"), "{}", app.status);
    let nodes = store::load_nodes(&sandbox.dir).expect("reload");
    assert_eq!(nodes[0].ssh_user, "root", "a refused edit was persisted");
}

#[test]
fn a_session_leaves_room_for_the_panel() {
    assert_eq!(super::app::session_size((80, 24)), (80, 20));
    assert_eq!(super::app::session_size((10, 2)), (20, 4));
}

#[test]
fn the_session_screen_draws_what_the_remote_wrote() {
    use crate::session::Session;
    use super::app::SessionView;

    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    let (_event_tx, events) = std::sync::mpsc::channel();
    let (input, _input_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut parser = vt100::Parser::new(
        std::num::NonZeroU16::new(5).expect("rows"),
        std::num::NonZeroU16::new(40).expect("cols"),
        100,
    );
    parser.process(b"hello from the node\r\n$ ls\r\nfile-a  file-b\r\n");

    app.session = Some(SessionView {
        ssh: Session { events, input },
        parser,
        title: "root@10.89.0.3".to_string(),
        origin: Screen::Nodes,
        size: (40, 5),
        closed: None,
    });
    let text = render_screen(&mut app, Screen::Session, 40, 12);
    assert!(text.contains("msm  ssh  root@10.89.0.3"), "{text}");
    assert!(text.contains("hello from the node"), "{text}");
    assert!(text.contains("file-a  file-b"), "{text}");
    assert!(text.contains("ctrl-\\ detach"), "{text}");
}

#[test]
fn q_is_a_letter_while_pairing() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();
    app.screen = Screen::Pair;
    app.pair.focus = super::app::Focus::Label;

    app.on_key(key(crossterm::event::KeyCode::Char('q')));
    assert!(!app.should_quit, "q quit the panel instead of typing");
    assert_eq!(app.pair.label, "q");

    // Outside a text field it still quits.
    app.screen = Screen::Nodes;
    app.on_key(key(crossterm::event::KeyCode::Char('q')));
    assert!(app.should_quit);
}
