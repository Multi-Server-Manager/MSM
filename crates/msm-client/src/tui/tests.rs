//! Headless render tests: every screen draws, at a fixed size, with no terminal.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use msm_protocol::commands::Command;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Style};

use super::app::{
    App, EditForm, Focus, LogsView, NodeView, Prompt, Screen, SessionView, Severity, Status,
};
use super::ui::render_screen;
use super::ui::widgets::{bar, sparkline};
use super::worker::Sample;
use crate::mdns::Discovered;
use crate::session::{Input, Session};
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
        let dir = std::env::temp_dir().join(format!("msm-tui-test-{}-{id}", std::process::id()));
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
    // With an address typed, `d` is a letter in that field, not discovery.
    assert!(
        !text.contains("d discover"),
        "the help offered discovery where d types: {text}"
    );
    assert!(text.contains("tab field"), "{text}");
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
    assert!(
        text.contains('@'),
        "the peak sample should reach the top of the ramp: {text}"
    );
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
fn the_log_tail_walks_back_from_the_newest_line() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.logs = LogsView {
        node: Some("id-0".to_string()),
        lines: (1..=100).map(|n| format!("line {n}")).collect(),
        waiting: false,
        first: 0,
        follow: true,
    };
    app.set_panel_size(80, 24);

    let text = render_screen(&mut app, Screen::Logs, 80, 24);
    assert!(
        text.contains("line 100"),
        "the tail ends on the newest line:\n{text}"
    );

    let body = app.view_rows();
    let (tail, room) = super::ui::log_window(&app.logs, body);
    assert_eq!(tail, 100 - room);
    assert_eq!(
        room,
        body - 2,
        "the log header keeps two of the body's rows"
    );

    // The first key after the tail moves the view: the screen and the keys ask
    // one window, so the follow clamp cannot swallow it.
    app.on_key(key(KeyCode::Char('k')));
    assert!(!app.logs.follow);
    assert_eq!(app.logs_first(body), tail - 1);

    // `G` pins the newest line again.
    app.on_key(key(KeyCode::Char('G')));
    assert!(app.logs.follow);
    assert_eq!(app.logs_first(body), tail);
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
    app.marked = app
        .nodes
        .iter()
        .map(|view| view.record.node_id.clone())
        .collect();
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

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn control(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::CONTROL)
}

/// A session as the panel holds it: the channels, the emulator and its screen.
/// The returned receiver is the session thread's side, so a test can prove that
/// nothing was sent — or that a Close was.
fn session_view(
    node_id: &str,
    text: &str,
) -> (SessionView, tokio::sync::mpsc::UnboundedReceiver<Input>) {
    let (_event_tx, events) = std::sync::mpsc::channel();
    let (input, input_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut parser = vt100::Parser::new(
        std::num::NonZeroU16::new(5).expect("rows"),
        std::num::NonZeroU16::new(40).expect("cols"),
        100,
    );
    parser.process(text.as_bytes());
    let view = SessionView {
        node_id: node_id.to_string(),
        ssh: Session { events, input },
        parser,
        title: "root@10.89.0.3".to_string(),
        origin: Screen::Nodes,
        size: (40, 5),
        closed: None,
    };
    (view, input_rx)
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
    assert!(
        app.notice().text().contains("press p"),
        "status was {:?}",
        app.notice().text()
    );
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
        app.notice().text().contains("msm-node"),
        "status was {:?}",
        app.notice().text()
    );
}

#[test]
fn progress_bar_moves_and_keeps_its_width() {
    use std::time::Duration;
    let first = super::ui::widgets::progress_bar(Duration::ZERO, 16);
    let later = super::ui::widgets::progress_bar(Duration::from_millis(900), 16);
    assert_eq!(first.chars().count(), 18, "brackets plus 16 cells");
    assert_eq!(later.chars().count(), 18);
    assert_ne!(first, later, "the band has to move");
    assert!(first.starts_with('[') && first.ends_with(']'));
    assert_eq!(
        super::ui::widgets::progress_bar(Duration::from_secs(4), 16)
            .matches('=')
            .count(),
        4
    );
}

#[test]
fn clock_reads_as_seconds_then_minutes() {
    use std::time::Duration;
    assert_eq!(super::ui::widgets::clock(Duration::ZERO), "0s");
    assert_eq!(super::ui::widgets::clock(Duration::from_secs(14)), "14s");
    assert_eq!(super::ui::widgets::clock(Duration::from_secs(64)), "1m 04s");
    assert_eq!(
        super::ui::widgets::clock(Duration::from_secs(600)),
        "10m 00s"
    );
}

#[test]
fn activity_line_names_the_work_and_counts_nodes() {
    use std::time::Duration;
    let line = super::ui::widgets::activity_line(
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
    assert!(
        app.notice().text().contains("pkg.install htop"),
        "{}",
        app.notice().text()
    );
    assert!(
        app.notice().text().contains("error:"),
        "{}",
        app.notice().text()
    );
    assert!(
        app.notice().text().contains("listening"),
        "{}",
        app.notice().text()
    );
}

#[test]
fn a_background_refresh_does_not_wipe_the_last_message() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.report(Severity::Info, "paired with node-1, SSH key installed");

    app.apply(super::worker::Msg::Finished {
        node: "id-0".to_string(),
        id: super::worker::BACKGROUND,
        ok: true,
        summary: "ok".to_string(),
    });
    assert_eq!(app.notice().text(), "paired with node-1, SSH key installed");
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
    assert!(
        app.notice().text().starts_with("error: "),
        "{}",
        app.notice().text()
    );
    assert!(
        app.notice().text().contains("rejected that code"),
        "{}",
        app.notice().text()
    );
    assert_eq!(
        app.notice().severity(),
        Severity::Error,
        "not drawn as an error"
    );
    assert!(!app.pair.busy);
}

#[test]
fn pair_screen_asks_where_things_run() {
    let sandbox = Sandbox::new(0);
    let mut app = sandbox.app();

    let text = render_screen(&mut app, Screen::Pair, 80, 26);
    assert!(
        text.contains("setup (blank = the node's own answer)"),
        "{text}"
    );
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
    assert!(
        app.notice().text().contains("not an account name"),
        "{}",
        app.notice().text()
    );
    let nodes = store::load_nodes(&sandbox.dir).expect("reload");
    assert_eq!(nodes[0].ssh_user, "root", "a refused edit was persisted");
}

/// Render a screen at a size, and hand back its rows the way the terminal
/// shows them.
fn rows_at(app: &mut App, screen: Screen, width: u16, height: u16) -> Vec<String> {
    app.panel = (width, height);
    let text = render_screen(app, screen, width, height);
    text.lines().map(str::to_string).collect()
}

/// A login on screen, with its grid sized the way the panel sizes the remote.
fn session_on(app: &mut App, width: u16, height: u16, transcript: &str, closed: Option<&str>) {
    app.panel = (width, height);
    let (view, _input) = session_view("id-0", transcript);
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;
    if let Some(reason) = closed
        && let Some(view) = app.sessions.get_mut("id-0")
    {
        view.closed = Some(reason.to_string());
    }

    let (cols, rows) = app.session_area(width, height);
    let view = app.sessions.get_mut("id-0").expect("the login");
    view.size = (cols, rows);
    view.parser.set_size(
        std::num::NonZeroU16::new(rows).expect("rows"),
        std::num::NonZeroU16::new(cols).expect("cols"),
    );
}

/// The panel filled the terminal exactly, and the end of the help line — the
/// first thing a short window loses — is still on it.
fn assert_fits(rows: &[String], screen: Screen, width: u16, height: u16, app: &App) {
    assert_eq!(
        rows.len(),
        height as usize,
        "{screen:?} at {width}x{height} drew {} rows",
        rows.len()
    );
    let flat = rows.join(" ");
    let (_, last) = super::ui::hints::hints(app)
        .last()
        .copied()
        .expect("a hint");
    let tail = last.rsplit(' ').next().expect("a label");
    assert!(
        flat.contains(tail),
        "{screen:?} at {width}x{height} lost the end of the help line:\n{flat}"
    );
}

#[test]
fn every_screen_fits_the_terminal_it_is_drawn_in() {
    let sandbox = Sandbox::new(3);
    let mut app = sandbox.app();
    app.report(Severity::Info, "ready");

    for (width, height) in [(80, 24), (100, 30), (40, 15)] {
        for screen in [Screen::Nodes, Screen::Pair, Screen::Detail, Screen::Logs] {
            let rows = rows_at(&mut app, screen, width, height);
            assert_fits(&rows, screen, width, height, &app);
        }
    }

    // The pairing form is the first thing to clip on a short terminal.
    let rows = rows_at(&mut app, Screen::Pair, 40, 15);
    let flat = rows.join(" ");
    for label in [
        "address",
        "code",
        "name",
        "ssh user",
        "ssh port",
        "commands as",
    ] {
        assert!(
            flat.contains(label),
            "{label} was clipped at 40x15:\n{flat}"
        );
    }

    // A live login: the longest help line and the remote's first rows both
    // fit, and the grid is exactly the rows the footer left.
    for (width, height) in [(80, 24), (100, 30), (40, 15)] {
        app.ctrl_m = true;
        session_on(&mut app, width, height, "$ make\r\nbuilding\r\n", None);
        let rows = rows_at(&mut app, Screen::Session, width, height);
        assert_fits(&rows, Screen::Session, width, height, &app);
        assert!(rows[0].contains("msm  ssh  root@"), "{rows:?}");
        assert!(
            rows[3].contains("building"),
            "the grid lost its first rows: {rows:?}"
        );
        for hint in ["ctrl-m detach", "ctrl-\\ detach", "ctrl-[ sends esc"] {
            assert!(
                rows.join(" ").contains(hint),
                "clipped at {hint} at {width}x{height}"
            );
        }
        let (cols, grid) = app.session_area(width, height);
        assert_eq!(cols, width);
        assert_eq!(
            grid as usize + super::ui::chrome_rows(&app, width as usize) + 2,
            height as usize,
            "{width}x{height}: the grid does not match the chrome"
        );
    }

    // A closed login spends one more row on the reason, so the grid loses one
    // rather than the footer being pushed off.
    app.ctrl_m = false;
    session_on(&mut app, 40, 15, "$ exit\r\n", Some("exit status 0"));
    let rows = rows_at(&mut app, Screen::Session, 40, 15);
    assert_fits(&rows, Screen::Session, 40, 15, &app);
    let flat = rows.join(" ");
    assert!(rows[0].contains("msm  ssh  root@"), "{rows:?}");
    assert!(flat.contains("exit status 0"), "{rows:?}");
    for hint in ["esc back", "s ssh again"] {
        assert!(flat.contains(hint), "clipped at {hint}:\n{flat}");
    }
}

#[test]
fn a_long_node_list_scrolls_with_the_cursor() {
    let sandbox = Sandbox::new(30);
    let mut app = sandbox.app();

    for index in 0..30 {
        if index > 0 {
            app.on_key(key(KeyCode::Char('j')));
        }
        let name = app.current().expect("a node").name().to_string();
        let rows = rows_at(&mut app, Screen::Nodes, 40, 15);
        let selected = rows
            .iter()
            .find(|row| row.starts_with('>'))
            .unwrap_or_else(|| panic!("no selected row at {name}\n{}", rows.join("\n")));
        assert!(
            selected.contains(&name),
            "the cursor left the window at {name}: {selected}"
        );
    }
    let last = app.nodes.last().expect("a node").name().to_string();
    let rows = rows_at(&mut app, Screen::Nodes, 40, 15);
    assert!(
        rows.iter().any(|row| row.contains(&last)),
        "the last node never became visible:\n{}",
        rows.join("\n")
    );
}

#[test]
fn a_long_log_reaches_every_line() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.panel = (40, 15);
    app.screen = Screen::Logs;
    app.logs = LogsView {
        node: Some("id-0".to_string()),
        lines: (1..=200).map(|n| format!("line-{n}")).collect(),
        waiting: false,
        first: 0,
        follow: true,
    };

    let rows = rows_at(&mut app, Screen::Logs, 40, 15);
    assert!(rows.join("\n").contains("line-200"), "not at the tail");
    assert!(
        !rows.join("\n").contains("line-1 "),
        "the whole log is on screen"
    );

    app.on_key(key(KeyCode::Char('g')));
    let rows = rows_at(&mut app, Screen::Logs, 40, 15);
    assert!(
        rows.join("\n").contains("line-1"),
        "the oldest line is unreachable:\n{}",
        rows.join("\n")
    );

    app.on_key(key(KeyCode::Char('G')));
    let rows = rows_at(&mut app, Screen::Logs, 40, 15);
    assert!(
        rows.join("\n").contains("line-200"),
        "G did not return to the tail"
    );
}

#[test]
fn the_session_screen_draws_what_the_remote_wrote() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.ctrl_m = true;
    let (view, _input) = session_view("id-0", "hello from the node\r\n$ ls\r\nfile-a  file-b\r\n");
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());

    let text = render_screen(&mut app, Screen::Session, 40, 12);
    assert!(text.contains("msm  ssh  root@10.89.0.3"), "{text}");
    assert!(text.contains("hello from the node"), "{text}");
    assert!(text.contains("file-a  file-b"), "{text}");
    // The help line wraps at 40 columns, so match on the unwrapped text.
    let flat = text.split('\n').collect::<Vec<_>>().join(" ");
    assert!(flat.contains("ctrl-\\ detach"), "{text}");
    assert!(flat.contains("ctrl-m detach"), "{text}");
    assert!(flat.contains("ctrl-[ sends esc"), "{text}");
}

#[test]
fn esc_detaches_and_still_delivers_the_escape() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (view, mut input) = session_view("id-0", "$ tail -f app.log\r\nlistening\r\n");
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;

    app.on_key(key(KeyCode::Esc));

    // Out of the screen, all the way to the list, and still connected.
    assert_eq!(app.screen, Screen::Nodes);
    assert!(app.sessions.contains_key("id-0"), "esc dropped the session");
    assert!(app.active_session.is_none());
    // A prompt gets nothing: readline would hold the ESC and turn the next key
    // into a Meta chord, which reads as a swallowed keystroke.
    assert!(
        input.try_recv().is_err(),
        "esc sent something to a shell prompt"
    );

    let text = render_screen(&mut app, Screen::Nodes, 80, 20);
    assert!(text.contains("detached"), "{text}");
    assert!(text.contains("s resumes it"), "{text}");

    // And s brings the same session back, with what it printed meanwhile.
    app.panel = (40, 12);
    app.on_key(key(KeyCode::Char('s')));
    assert_eq!(app.screen, Screen::Session);
    assert_eq!(app.active_session.as_deref(), Some("id-0"));
    assert!(
        app.notice().text().contains("resumed"),
        "{}",
        app.notice().text()
    );
    let text = render_screen(&mut app, Screen::Session, 40, 12);
    assert!(text.contains("listening"), "{text}");
    assert!(text.contains("live"), "{text}");

    // A full-screen program (vim, less) is the case that gets the escape
    // itself: the alternate screen is how the panel tells it from a prompt.
    while input.try_recv().is_ok() {} // the resize the resume sent
    app.sessions
        .get_mut("id-0")
        .expect("the login")
        .parser
        .process(b"\x1b[?1049h");
    app.on_key(key(KeyCode::Esc));
    assert_eq!(app.screen, Screen::Nodes, "esc did not detach");
    assert!(
        matches!(input.try_recv(), Ok(Input::Data(bytes)) if bytes == b"\x1b"),
        "the full-screen program never got its escape"
    );
    assert!(app.sessions.contains_key("id-0"));
}

#[test]
fn ctrl_m_detaches_to_where_the_login_started() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (mut view, mut input) = session_view("id-0", "$ ls\r\n");
    view.origin = Screen::Detail;
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;

    // Enter belongs to the shell: it arrives as a carriage return and never
    // detaches, whatever the terminal can report.
    app.on_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Session, "enter detached the session");
    assert!(
        matches!(input.try_recv(), Ok(Input::Data(bytes)) if bytes == b"\r"),
        "enter did not reach the shell"
    );

    // Ctrl-M is CR too. A kitty-protocol terminal reports it as Enter with
    // CONTROL, and that is the only form that detaches.
    app.on_key(control(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Detail, "ctrl-m left the wrong screen");
    assert!(app.sessions.contains_key("id-0"));
    assert_eq!(
        app.notice().severity(),
        Severity::Warn,
        "a detach is a warning, not an error"
    );
    assert!(input.try_recv().is_err());
}

#[test]
fn ctrl_m_then_x_ends_a_detached_session() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (view, mut input) = session_view("id-0", "$ sleep 300\r\n");
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;

    app.on_key(control(KeyCode::Char('m')));
    assert_eq!(app.screen, Screen::Nodes);
    assert!(app.sessions.contains_key("id-0"));

    app.on_key(key(KeyCode::Char('X')));
    assert!(app.sessions.is_empty(), "x left the session behind");
    assert!(app.active_session.is_none());
    assert!(
        matches!(input.try_recv(), Ok(Input::Close)),
        "x did not close the connection"
    );
    assert!(
        app.notice().text().contains("terminated"),
        "{}",
        app.notice().text()
    );

    // x on a node without one says so instead of inventing a session.
    app.on_key(key(KeyCode::Char('x')));
    assert!(
        app.notice().text().contains("no ssh session"),
        "{}",
        app.notice().text()
    );
}

#[test]
fn ctrl_backslash_detaches_even_when_the_terminal_calls_it_ctrl_4() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (view, mut input) = session_view("id-0", "$ tail -f app.log\r\n");
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;
    // No keyboard-enhancement flags: crossterm reports the 0x1c byte as ctrl-4,
    // not ctrl-\, and that is exactly the terminal this chord exists for.
    app.ctrl_m = false;

    app.on_key(control(KeyCode::Char('4')));
    assert_eq!(app.screen, Screen::Nodes, "ctrl-\\ did not detach");
    assert!(
        app.sessions.contains_key("id-0"),
        "detach dropped the login"
    );
    assert!(
        input.try_recv().is_err(),
        "the detach byte was sent to the shell"
    );

    // A plain 4 is still the shell's, on the same view.
    app.screen = Screen::Session;
    app.active_session = Some("id-0".to_string());
    app.on_key(key(KeyCode::Char('4')));
    assert!(
        matches!(input.try_recv(), Ok(Input::Data(bytes)) if bytes == b"4"),
        "a plain 4 did not reach the shell"
    );
}

#[test]
fn the_help_line_only_names_chords_the_terminal_can_send() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (view, _input) = session_view("id-0", "$ \r\n");
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.ctrl_m = false;

    let text = render_screen(&mut app, Screen::Session, 120, 20);
    assert!(text.contains("ctrl-\\"), "{text}");
    assert!(
        !text.contains("ctrl-m"),
        "advertised ctrl-m on a terminal that cannot send it: {text}"
    );
    assert!(
        !text.contains("ctrl-["),
        "advertised ctrl-[ where it is the same byte as Esc: {text}"
    );

    app.active_session = Some("id-0".to_string());
    app.ctrl_m = true;
    let text = render_screen(&mut app, Screen::Session, 120, 20);
    assert!(text.contains("ctrl-m"), "{text}");
    assert!(
        text.contains("ctrl-["),
        "a terminal that can tell ctrl-[ from Esc is not offered it: {text}"
    );
}

/// The key events a hint's key token stands for. Every token the help line can
/// show must be pressable here, or the test below proves nothing about it.
fn hint_keys(token: &str) -> Vec<KeyEvent> {
    let ctrl = |code: KeyCode| KeyEvent::new(code, KeyModifiers::CONTROL);
    match token {
        "j/k" => vec![key(KeyCode::Char('j')), key(KeyCode::Char('k'))],
        "g/G" => vec![key(KeyCode::Char('g')), key(KeyCode::Char('G'))],
        "up/down" => vec![key(KeyCode::Up), key(KeyCode::Down)],
        "PgUp/PgDn" => vec![key(KeyCode::PageUp), key(KeyCode::PageDown)],
        "space" => vec![key(KeyCode::Char(' '))],
        "enter" => vec![key(KeyCode::Enter)],
        "tab" => vec![key(KeyCode::Tab)],
        "esc" => vec![key(KeyCode::Esc)],
        "ctrl-m" => vec![ctrl(KeyCode::Enter)],
        "ctrl-\\" => vec![ctrl(KeyCode::Char('\\'))],
        "ctrl-[" => vec![ctrl(KeyCode::Char('['))],
        single if single.chars().count() == 1 => {
            vec![key(KeyCode::Char(single.chars().next().expect("one char")))]
        }
        other => panic!("the help line advertises {other:?}, which this test cannot press"),
    }
}

/// Every state with its own help line: the five screens, a closed login, and
/// the two dialogs that own the keyboard while they are open.
#[derive(Debug, Clone, Copy)]
enum Case {
    Nodes,
    Pair,
    Detail,
    Logs,
    Session,
    ClosedSession,
    Edit,
    Prompt,
}

impl Case {
    const ALL: [Self; 8] = [
        Self::Nodes,
        Self::Pair,
        Self::Detail,
        Self::Logs,
        Self::Session,
        Self::ClosedSession,
        Self::Edit,
        Self::Prompt,
    ];
}

/// A panel in `case`, in the state that state's help line assumes: a
/// markable list, a discovered node to choose, a tail to scroll, a login, a
/// dialog with a field in it. A fresh one per key press, so one key's
/// consequence cannot set up the next.
fn case_app(case: Case) -> (Sandbox, App) {
    let sandbox = Sandbox::new(3);
    let mut app = sandbox.app();
    app.panel = (100, 30);
    app.screen = match case {
        Case::Nodes | Case::Edit | Case::Prompt => Screen::Nodes,
        Case::Pair => Screen::Pair,
        Case::Detail => Screen::Detail,
        Case::Logs => Screen::Logs,
        Case::Session | Case::ClosedSession => Screen::Session,
    };
    match case {
        Case::Nodes | Case::Detail => {}
        Case::Pair => {
            app.pair.discovered = ["alpha", "beta"]
                .iter()
                .enumerate()
                .map(|(index, label)| Discovered {
                    label: (*label).to_string(),
                    address: std::net::Ipv4Addr::new(10, 89, 0, 7 + index as u8).into(),
                    port: 7333,
                    node_id: Some(format!("id-{label}")),
                    spki: None,
                })
                .collect();
            app.pair.focus = Focus::Address;
        }
        Case::Logs => {
            app.logs.node = Some("id-0".to_string());
            app.logs.lines = (1..=100).map(|n| format!("line {n}")).collect();
        }
        Case::Session | Case::ClosedSession => {
            let (mut view, _input) = session_view("id-0", "$ echo hi\r\nhi\r\n");
            if matches!(case, Case::ClosedSession) {
                view.closed = Some("exit status 0".to_string());
            }
            app.sessions.insert("id-0".to_string(), view);
            app.active_session = Some("id-0".to_string());
            // The longest help line: both detach chords are listed.
            app.ctrl_m = true;
        }
        Case::Edit => {
            let record = app.nodes[0].record.clone();
            app.edit = Some(EditForm::for_record(record));
        }
        Case::Prompt => {
            app.prompt = Some(Prompt {
                title: "install package".to_string(),
                value: String::new(),
            });
        }
    }
    (sandbox, app)
}

#[test]
fn a_screen_does_not_advertise_a_key_it_cannot_use() {
    // Nothing paired: every command but `p` and `q` has no target, and `l`,
    // `s`, `e`, `x` and `f` are ignored outright.
    let sandbox = Sandbox::new(0);
    let app = sandbox.app();
    assert_eq!(
        super::ui::hints::hints(&app),
        vec![("p", "pair"), ("q", "quit")]
    );

    // Pairing: discovery only works in an empty address field, and choosing
    // only once there is something discovered.
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.screen = Screen::Pair;
    let empty = super::ui::hints::hints(&app);
    assert!(empty.iter().any(|(key, _)| *key == "d"), "{empty:?}");
    assert!(
        !empty.iter().any(|(key, _)| *key == "up/down"),
        "offered a list that does not exist: {empty:?}"
    );

    app.pair.address = "10.89.0.9:7333".to_string();
    let typed = super::ui::hints::hints(&app);
    assert!(
        !typed.iter().any(|(key, _)| *key == "d"),
        "d types into the address here: {typed:?}"
    );

    app.pair.address.clear();
    app.pair.discovered = vec![discovered("alpha", "10.89.0.7", 7333)];
    let found = super::ui::hints::hints(&app);
    assert!(
        found.iter().any(|(key, _)| *key == "up/down"),
        "a result is choosable but not offered: {found:?}"
    );
}

#[test]
fn every_advertised_key_is_handled_where_it_is_shown() {
    for case in Case::ALL {
        let (sandbox, probe) = case_app(case);
        let advertised = super::ui::hints::hints(&probe);
        drop(sandbox);
        assert!(!advertised.is_empty(), "{case:?} advertises no key at all");

        for (token, label) in advertised {
            for event in hint_keys(token) {
                let (_sandbox, mut app) = case_app(case);
                assert!(
                    app.on_key(event),
                    "{case:?} advertises {token:?} {label:?}, \
                     but on_key did not take the key"
                );
            }
        }
    }
}

/// A dialog is a text field: the keys it advertises are its own, and a letter
/// is a letter. The footer must say so, because it is the only place the
/// operator learns which keyboard they are typing into.
#[test]
fn the_help_matches_the_dialog_that_owns_the_keyboard() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.on_key(key(KeyCode::Char('e')));
    assert!(app.edit.is_some(), "e did not open the edit dialog");
    assert_eq!(
        super::ui::hints::hints(&app),
        vec![("tab", "field"), ("enter", "save"), ("esc", "cancel")]
    );
    let text = render_screen(&mut app, Screen::Nodes, 80, 24);
    assert!(text.contains("enter save"), "{text}");
    assert!(!text.contains("q quit"), "{text}");
    assert!(!text.contains("space mark"), "{text}");
    // One help line, not the same words twice over.
    let last = text
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .unwrap_or("");
    assert_eq!(last, "tab field enter save esc cancel", "{text}");

    app.on_key(key(KeyCode::Char('q')));
    assert!(!app.should_quit, "q quit the panel from the edit dialog");
    assert!(
        app.edit
            .as_ref()
            .expect("the dialog is still open")
            .label
            .ends_with('q'),
        "q did not land in the focused field"
    );

    // The install prompt is a text field for the same reason.
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    app.on_key(key(KeyCode::Char('i')));
    assert_eq!(
        super::ui::hints::hints(&app),
        vec![("enter", "install"), ("esc", "cancel")]
    );
    let text = render_screen(&mut app, Screen::Nodes, 80, 24);
    assert!(text.contains("install package:"), "{text}");
    assert!(!text.contains("q quit"), "{text}");

    app.on_key(key(KeyCode::Char('q')));
    assert!(!app.should_quit, "q quit the panel from the prompt");
    assert_eq!(
        app.prompt.as_ref().expect("the prompt is still open").value,
        "q"
    );
}

/// A cell's foreground, with "unset" normalised to `None` (ratatui writes an
/// unset colour into the buffer as `Reset`).
fn fg(style: Style) -> Option<Color> {
    match style.fg {
        Some(Color::Reset) => None,
        colour => colour,
    }
}

/// The style of the first non-blank cell on the footer row that contains
/// `needle`, read from a real draw rather than inferred from the text.
fn footer_style(app: &mut App, needle: &str) -> Style {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test backend");
    terminal
        .draw(|frame| super::ui::draw(frame, app))
        .expect("draw the footer");
    let buffer = terminal.backend().buffer();
    for y in 0..30 {
        let mut row = String::new();
        for x in 0..100 {
            row.push_str(buffer.get(x, y).symbol());
        }
        if row.contains(needle) {
            for x in 0..100 {
                let cell = buffer.get(x, y);
                if cell.symbol() != " " {
                    return cell.style();
                }
            }
        }
    }
    panic!("no footer row contains {needle:?}");
}

#[test]
fn the_footer_takes_its_colour_from_the_kind_not_the_words() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();

    // The one mapping: kind -> palette. No string is inspected anywhere.
    assert_eq!(
        super::ui::notice_style(Severity::Warn),
        super::theme::warn()
    );
    assert_eq!(
        super::ui::notice_style(Severity::Error),
        super::theme::failed()
    );
    assert_eq!(super::ui::notice_style(Severity::Info), Style::default());

    app.report(Severity::Warn, "error: these words are only a warning");
    assert_eq!(
        fg(footer_style(&mut app, "only a warning")),
        fg(super::ui::notice_style(Severity::Warn)),
        "a warning is drawn with the warning colour"
    );

    app.report(Severity::Error, "plain words with no prefix at all");
    assert_eq!(
        fg(footer_style(&mut app, "plain words with no prefix")),
        fg(super::ui::notice_style(Severity::Error)),
        "an error is drawn with the error colour"
    );

    // The footer used to search for `error:`, `detach` and `no ssh session`
    // in the text. A message that merely says those words must not be red.
    app.report(Severity::Info, "error: no ssh session detached");
    assert_eq!(
        fg(footer_style(&mut app, "error: no ssh session detached")),
        fg(super::ui::notice_style(Severity::Info)),
        "an info line is drawn with the info style, whatever it says"
    );
    if super::theme::enabled() {
        assert_ne!(
            fg(super::ui::notice_style(Severity::Warn)),
            fg(super::ui::notice_style(Severity::Error)),
            "the kinds must not share one colour"
        );
    }
}

#[test]
fn s_on_a_finished_login_starts_a_new_one() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (mut view, mut input) = session_view("id-0", "$ exit\r\n");
    view.closed = Some("exit status 0".to_string());
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;

    app.on_key(key(KeyCode::Char('s')));
    assert!(
        matches!(input.try_recv(), Ok(Input::Close)),
        "the dead thread was never closed"
    );
    let fresh = app.sessions.get("id-0").expect("a new login");
    assert!(fresh.closed.is_none(), "the finished screen was kept");
    assert_eq!(app.active_session.as_deref(), Some("id-0"));
    assert!(app.screen == Screen::Session, "the new login did not open");
}

#[test]
fn ctrl_bracket_is_the_escape_a_shell_needs() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (view, mut input) = session_view("id-0", "$ vim notes\r\n");
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;

    app.on_key(control(KeyCode::Char('[')));
    assert_eq!(app.screen, Screen::Session, "ctrl-[ detached");
    assert!(
        matches!(input.try_recv(), Ok(Input::Data(bytes)) if bytes == b"\x1b"),
        "ctrl-[ did not send the escape byte"
    );

    // A resize reaches the remote, and a detached session is left alone.
    app.set_panel_size(100, 30);
    assert!(matches!(input.try_recv(), Ok(Input::Resize(100, 26))));
}

#[test]
fn a_detached_session_keeps_receiving_while_the_panel_is_elsewhere() {
    let sandbox = Sandbox::new(1);
    let mut app = sandbox.app();
    let (event_tx, events) = std::sync::mpsc::channel();
    let (input, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    let view = SessionView {
        node_id: "id-0".to_string(),
        ssh: Session { events, input },
        parser: vt100::Parser::new(
            std::num::NonZeroU16::new(5).expect("rows"),
            std::num::NonZeroU16::new(40).expect("cols"),
            100,
        ),
        title: "root@10.89.0.3".to_string(),
        origin: Screen::Nodes,
        size: (40, 5),
        closed: None,
    };
    app.sessions.insert("id-0".to_string(), view);
    app.active_session = Some("id-0".to_string());
    app.screen = Screen::Session;

    app.on_key(key(KeyCode::Esc));
    assert!(app.sessions.contains_key("id-0"));
    // A prompt gets nothing on the way out.
    assert!(input_rx.try_recv().is_err());

    // The connection keeps writing while the panel is on the node list.
    event_tx
        .send(crate::session::Event::Data(b"still working\r\n".to_vec()))
        .expect("data");
    app.tick();
    assert!(input_rx.try_recv().is_err());

    app.on_key(key(KeyCode::Char('s')));
    let text = render_screen(&mut app, Screen::Session, 40, 12);
    assert!(text.contains("still working"), "{text}");
}

#[test]
fn colour_is_emphasis_and_every_state_still_says_its_name() {
    if !super::theme::enabled() {
        return;
    }
    assert_eq!(super::theme::ok().fg, Some(ratatui::style::Color::Green));
    assert_eq!(super::theme::failed().fg, Some(ratatui::style::Color::Red));

    let sandbox = Sandbox::new(2);
    let mut app = sandbox.app();
    app.nodes[0].status = Status::Ok;
    app.nodes[1].status = Status::Failed;

    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 24)).expect("backend");
    terminal
        .draw(|frame| super::ui::draw(frame, &app))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let mut colours = BTreeSet::new();
    for y in 0..24 {
        for x in 0..100 {
            colours.insert(format!("{:?}", buffer.get(x, y).fg));
        }
    }
    assert!(colours.len() >= 4, "the panel is monochrome: {colours:?}");
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
