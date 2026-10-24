//! The panel: a spare, monospace view of the paired nodes.
//!
//! The terminal belongs to the panel for the whole run. An SSH login is drawn
//! in the same screen (see `session`); only `sftp`, a file browser rather than
//! a shell, borrows the terminal and gives it back when it exits.
//!
//! The code is split by concern: `app` owns the state and the key handling,
//! `ui` draws that state and never writes it, and `crate::session` is the SSH
//! transport underneath both. See the module docs of `app` and `ui` for the
//! file map and for the sizes that have a single owner.

pub mod app;
#[cfg(test)]
mod tests;
pub mod theme;
pub mod ui;
mod worker;

use std::io::{self, IsTerminal};
use std::path::Path;
use std::time::Duration;

use crossterm::event::{
    self, Event, KeyEventKind, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use crossterm::terminal::{
    self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
    enable_raw_mode,
};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use msm_protocol::{ProtocolError, Result};

pub use app::{App, Screen};

type Panel = Terminal<CrosstermBackend<io::Stdout>>;

/// Run the panel until the user quits.
pub fn run(state_dir: &Path) -> Result<()> {
    if !io::stdout().is_terminal() {
        return Err(ProtocolError::Internal(
            "the panel needs a terminal; run a subcommand instead".into(),
        ));
    }

    let mut app = App::new(state_dir)?;
    let (mut panel, ctrl_m) = enter()?;
    app.ctrl_m = ctrl_m;
    let outcome = event_loop(&mut panel, &mut app);
    leave(&mut panel, ctrl_m)?;
    outcome
}

/// Take the terminal for the panel. The second answer says whether Ctrl-M can
/// be told apart from Enter, which decides whether `ctrl-m` is a detach chord.
///
/// The byte for Ctrl-M is CR, exactly what Enter sends, so without the kitty
/// keyboard protocol a terminal cannot report it as anything but Enter. Asking
/// for the disambiguated codes costs nothing where it is unsupported and keeps
/// Enter free for the shell everywhere.
fn enter() -> Result<(Panel, bool)> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, Clear(ClearType::All))?;

    let ctrl_m = terminal::supports_keyboard_enhancement().unwrap_or(false);
    if ctrl_m {
        execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
    }

    let panel = Terminal::new(CrosstermBackend::new(stdout))
        .map_err(|err| ProtocolError::Internal(format!("cannot start the panel: {err}")))?;
    Ok((panel, ctrl_m))
}

fn leave(panel: &mut Panel, ctrl_m: bool) -> Result<()> {
    if ctrl_m {
        execute!(panel.backend_mut(), PopKeyboardEnhancementFlags)?;
    }
    disable_raw_mode()?;
    execute!(
        panel.backend_mut(),
        LeaveAlternateScreen,
        cursor::Show,
        Clear(ClearType::All)
    )?;
    panel.show_cursor()?;
    Ok(())
}

fn event_loop(panel: &mut Panel, app: &mut App) -> Result<()> {
    while !app.should_quit {
        // The session's terminal and the panel share one window; tell the
        // remote the size it really has before drawing it.
        let size = panel
            .size()
            .map_err(|err| ProtocolError::Internal(format!("cannot read the panel size: {err}")))?;
        app.set_panel_size(size.width, size.height);

        panel
            .draw(|frame| ui::draw(frame, app))
            .map_err(|err| ProtocolError::Internal(format!("cannot draw: {err}")))?;

        app.tick();

        if let Some(shell) = app.shell.take() {
            match hand_over(panel, &shell) {
                Ok(status) => {
                    let code = status.code();
                    let kind = match code {
                        Some(0) | None => app::Severity::Info,
                        Some(_) => app::Severity::Error,
                    };
                    app.report(
                        kind,
                        format!(
                            "{}{}",
                            shell.program,
                            match code {
                                Some(code) => format!(" exited {code}"),
                                None => " ended".to_string(),
                            }
                        ),
                    );
                }
                Err(err) => app.report(app::Severity::Error, err),
            }
            continue;
        }

        // Busy work animates, so redraw often enough for the bar to move; idle
        // screens can wait longer.
        let wait = if app.busy.is_some() || app.pair.busy {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(150)
        };

        // Wait for input, then take everything that is already queued. Reading
        // one event per redraw made a fast key sequence (a typed code and then
        // Enter) arrive at the speed of the redraw instead of the keyboard, and
        // a press that landed on a non-key event was easy to lose.
        if event::poll(wait)? {
            loop {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        app.on_key(key);
                    }
                    // Resize is handled by the next draw; releases and focus
                    // changes carry no command.
                    _ => {}
                }
                if app.should_quit || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Give the terminal to a child process, then take it back.
fn hand_over(
    panel: &mut Panel,
    shell: &app::Shell,
) -> std::result::Result<std::process::ExitStatus, String> {
    disable_raw_mode().map_err(|err| err.to_string())?;
    execute!(panel.backend_mut(), LeaveAlternateScreen, cursor::Show)
        .map_err(|err| err.to_string())?;

    let outcome = std::process::Command::new(&shell.program)
        .args(&shell.args)
        .status()
        .map_err(|err| format!("cannot start {}: {err}", shell.program));

    enable_raw_mode().map_err(|err| err.to_string())?;
    execute!(panel.backend_mut(), EnterAlternateScreen).map_err(|err| err.to_string())?;
    panel
        .clear()
        .map_err(|err| format!("cannot redraw the panel: {err}"))?;

    outcome
}
