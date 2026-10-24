//! An SSH session drawn inside the panel.
//!
//! The panel never hands the terminal to another program: one thread owns an
//! SSH connection, and the screen you see is a small terminal emulator fed by
//! that connection. `msm`'s own keypair authenticates it, so the login works
//! whenever the node has the console's key — no password, no external `ssh`
//! binary, no alternate-screen hand-over.
//!
//! The thread speaks russh on a current-thread Tokio runtime; the panel talks
//! to it over two channels, so drawing and typing never wait on the network.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use russh::ChannelMsg;
use russh::client::Msg as ChannelStream;
use russh::keys::PublicKeyOrCertificate;

/// What the panel must know about a session.
pub enum Event {
    /// The shell was requested; the screen may show the prompt.
    Opened,
    /// Bytes the remote wrote.
    Data(Vec<u8>),
    /// The session ended, with the reason when there is one.
    Closed(String),
}

/// What the panel sends to the session.
pub enum Input {
    /// Bytes typed at the remote.
    Data(Vec<u8>),
    /// The window changed size.
    Resize(u16, u16),
    /// Close the session as if the user had typed `exit`.
    Close,
}

/// A running session: the panel side of the two channels.
pub struct Session {
    pub events: Receiver<Event>,
    pub input: UnboundedSender<Input>,
}

/// Everything the worker thread needs to connect.
pub struct Start {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Private key file, written by `sshkey`.
    pub key: PathBuf,
    /// Where host keys are remembered between sessions.
    pub known_hosts: PathBuf,
    pub cols: u16,
    pub rows: u16,
    pub label: String,
}

/// Connect, allocate a PTY and run the login shell.
pub fn start(config: Start) -> Session {
    let (event_tx, events) = channel();
    // The panel sends without waiting, so typing never blocks on the network.
    let (input, input_rx) = unbounded_channel();

    let label = config.label.clone();
    std::thread::Builder::new()
        .name(format!("msm-ssh-{label}"))
        .spawn(move || {
            let result = run(config, input_rx, event_tx.clone());
            if let Err(reason) = result {
                let _ = event_tx.send(Event::Closed(reason));
            }
        })
        .expect("spawn the SSH session thread");

    Session { events, input }
}

fn run(
    config: Start,
    mut input_rx: UnboundedReceiver<Input>,
    events: Sender<Event>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the SSH runtime: {err}"))?;

    runtime.block_on(async move {
        let key_text = std::fs::read_to_string(&config.key)
            .map_err(|err| format!("cannot read {}: {err}", config.key.display()))?;
        let key = russh::keys::decode_secret_key(&key_text, None)
            .map_err(|err| format!("cannot load the console SSH key: {err}"))?;

        let handler = Handler {
            host: config.host.clone(),
            port: config.port,
            known_hosts: config.known_hosts.clone(),
            events: events.clone(),
        };
        let ssh = Arc::new(russh::client::Config {
            nodelay: true,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            ..Default::default()
        });

        let mut handle = russh::client::connect(ssh, (config.host.as_str(), config.port), handler)
            .await
            .map_err(|err| format!("cannot connect to {}:{}: {err}", config.host, config.port))?;

        let auth = handle
            .authenticate_publickey(
                config.user.clone(),
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None),
            )
            .await
            .map_err(|err| format!("authentication failed: {err}"))?;
        if !auth.success() {
            return Err(format!(
                "the node refused the console key for {}@{}; pair again so the key is installed",
                config.user, config.host
            ));
        }

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|err| format!("cannot open a session: {err}"))?;
        channel
            .request_pty(
                true,
                "xterm-256color",
                u32::from(config.cols.max(1)),
                u32::from(config.rows.max(1)),
                0,
                0,
                &[],
            )
            .await
            .map_err(|err| format!("cannot request a terminal: {err}"))?;
        channel
            .request_shell(true)
            .await
            .map_err(|err| format!("cannot start a shell: {err}"))?;
        let _ = events.send(Event::Opened);

        let (mut read, write) = channel.split();
        loop {
            tokio::select! {
                message = read.wait() => match message {
                    Some(ChannelMsg::Data { data }) => {
                        if events.send(Event::Data(data.to_vec())).is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if events.send(Event::Data(data.to_vec())).is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        let _ = events.send(Event::Closed("the remote closed the session".into()));
                        break;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let _ = events.send(Event::Closed(format!("exit status {exit_status}")));
                    }
                    Some(_) => {}
                },
                command = input_rx.recv() => match command {
                    Some(Input::Data(bytes)) => {
                        if let Err(err) = write.data_bytes(bytes).await {
                            let _ = events.send(Event::Closed(format!("connection lost: {err}")));
                            break;
                        }
                    }
                    Some(Input::Resize(cols, rows)) => {
                        let _ = write
                            .window_change(u32::from(cols), u32::from(rows), 0, 0)
                            .await;
                    }
                    Some(Input::Close) | None => {
                        let _ = write.eof().await;
                        break;
                    }
                },
            }
        }

        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok::<(), String>(())
    })
}

/// Verifies the node's host key, trusting it on first use and refusing a
/// changed one — the same bargain `ssh` offers, in a file beside the pins.
struct Handler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    events: Sender<Event>,
}

impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        match russh::keys::check_known_hosts_path(&self.host, self.port, &key, &self.known_hosts) {
            Ok(true) => Ok(true),
            Ok(false) => {
                // First contact: remember it, and say so in the status line.
                let _ = russh::keys::known_hosts::learn_known_hosts_path(
                    &self.host,
                    self.port,
                    &key,
                    &self.known_hosts,
                );
                let _ = self.events.send(Event::Data(
                    format!(
                        "msm: new host key for {}:{} recorded in {}\r\n",
                        self.host,
                        self.port,
                        self.known_hosts.display()
                    )
                    .into_bytes(),
                ));
                Ok(true)
            }
            Err(err) => {
                let _ = self.events.send(Event::Closed(format!(
                    "the host key for {}:{} changed ({err}); remove it from {} to trust the new one",
                    self.host,
                    self.port,
                    self.known_hosts.display()
                )));
                Ok(false)
            }
        }
    }
}

impl Start {
    /// Where host keys are remembered for a console state directory.
    pub fn known_hosts_for(state_dir: &Path) -> PathBuf {
        state_dir.join("ssh").join("known_hosts")
    }
}

/// Translate one key press into the bytes a terminal would send.
///
/// The panel owns the keyboard, so everything that is not the detach key has to
/// be re-encoded here: control characters, arrows and the editing keys are the
/// ones a shell actually uses.
pub fn key_bytes(key: KeyEvent) -> Vec<u8> {
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    let mut bytes = match key.code {
        KeyCode::Char(character) => {
            if control {
                control_byte(character)
                    .map(|byte| vec![byte])
                    .unwrap_or_default()
            } else {
                character.to_string().into_bytes()
            }
        }
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Backspace => b"\x7f".to_vec(),
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Esc => b"\x1b".to_vec(),
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::F(number) => function_key(number),
        _ => Vec::new(),
    };

    // Alt is an ESC prefix, which is how a terminal spells Meta.
    if alt && !bytes.is_empty() && !matches!(key.code, KeyCode::Esc) {
        bytes.insert(0, 0x1b);
    }
    bytes
}

fn control_byte(character: char) -> Option<u8> {
    match character {
        'a'..='z' => Some(character as u8 & 0x1f),
        'A'..='Z' => Some(character as u8 & 0x1f),
        '@' | ' ' => Some(0),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        '?' => Some(0x7f),
        _ => None,
    }
}

fn function_key(number: u8) -> Vec<u8> {
    match number {
        1 => b"\x1bOP".to_vec(),
        2 => b"\x1bOQ".to_vec(),
        3 => b"\x1bOR".to_vec(),
        4 => b"\x1bOS".to_vec(),
        5 => b"\x1b[15~".to_vec(),
        6 => b"\x1b[17~".to_vec(),
        7 => b"\x1b[18~".to_vec(),
        8 => b"\x1b[19~".to_vec(),
        9 => b"\x1b[20~".to_vec(),
        10 => b"\x1b[21~".to_vec(),
        11 => b"\x1b[23~".to_vec(),
        12 => b"\x1b[24~".to_vec(),
        _ => Vec::new(),
    }
}

/// The type of the channel the session opens, kept so the split halves can be
/// named in tests without guessing at russh's internals.
pub type _ChannelStream = ChannelStream;

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> Vec<u8> {
        key_bytes(KeyEvent::new(code, modifiers))
    }

    #[test]
    fn typing_is_forwarded_verbatim() {
        assert_eq!(press(KeyCode::Char('l'), KeyModifiers::NONE), b"l");
        assert_eq!(press(KeyCode::Char('s'), KeyModifiers::NONE), b"s");
        assert_eq!(press(KeyCode::Enter, KeyModifiers::NONE), b"\r");
        assert_eq!(press(KeyCode::Tab, KeyModifiers::NONE), b"\t");
        assert_eq!(press(KeyCode::Backspace, KeyModifiers::NONE), b"\x7f");
    }

    #[test]
    fn control_and_arrows_match_a_terminal() {
        assert_eq!(press(KeyCode::Char('c'), KeyModifiers::CONTROL), b"\x03");
        assert_eq!(press(KeyCode::Char('d'), KeyModifiers::CONTROL), b"\x04");
        assert_eq!(press(KeyCode::Char('l'), KeyModifiers::CONTROL), b"\x0c");
        assert_eq!(press(KeyCode::Up, KeyModifiers::NONE), b"\x1b[A");
        assert_eq!(press(KeyCode::End, KeyModifiers::NONE), b"\x1b[F");
        assert_eq!(press(KeyCode::F(5), KeyModifiers::NONE), b"\x1b[15~");
    }

    #[test]
    fn alt_prefixes_escape() {
        assert_eq!(press(KeyCode::Char('b'), KeyModifiers::ALT), b"\x1bb");
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use russh::server::{Auth, Msg as ServerMsg, Server as _, Session as ServerSession};
    use std::sync::mpsc::RecvTimeoutError;

    /// A tiny SSH server: accepts any key, allocates a "terminal", greets the
    /// client and echoes every line back with a prefix.
    struct EchoServer;

    impl russh::server::Server for EchoServer {
        type Handler = EchoHandler;

        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> EchoHandler {
            EchoHandler
        }
    }

    struct EchoHandler;

    impl russh::server::Handler for EchoHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<ServerMsg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(
            &mut self,
            channel: russh::ChannelId,
            _term: &str,
            _cols: u32,
            _rows: u32,
            _pix_w: u32,
            _pix_h: u32,
            _modes: &[(russh::Pty, u32)],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: russh::ChannelId,
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, "welcome\r\n")?;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut ServerSession,
        ) -> Result<(), Self::Error> {
            let reply = format!("echo:{}", String::from_utf8_lossy(data));
            session.data(channel, reply)?;
            Ok(())
        }
    }

    /// Wait for the next data frame, ignoring the host-key notice.
    fn expect_data(events: &Receiver<Event>, needle: &str) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = String::new();
        while std::time::Instant::now() < deadline {
            match events.recv_timeout(Duration::from_millis(200)) {
                Ok(Event::Data(bytes)) => {
                    seen.push_str(&String::from_utf8_lossy(&bytes));
                    if seen.contains(needle) {
                        return seen;
                    }
                }
                Ok(Event::Opened) => {}
                Ok(Event::Closed(reason)) => {
                    panic!("session closed early: {reason}\nafter: {seen}")
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => panic!("session thread ended: {seen}"),
            }
        }
        panic!("never saw {needle:?}; got {seen:?}");
    }

    #[test]
    fn a_session_connects_logs_in_and_forwards_keys() {
        let dir = std::env::temp_dir().join(format!("msm-session-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");

        // The server's host key and listening socket.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();

        // Reuse the console's own key format for the server's host key, so the
        // test needs no second key generator.
        let host = crate::sshkey::SshKey::generate().expect("host key");
        let server_key =
            russh::keys::PrivateKey::from_openssh(&host.private_pem).expect("host key parses");
        let config = Arc::new(russh::server::Config {
            keys: vec![server_key],
            ..Default::default()
        });

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                let mut server = EchoServer;
                let _ = server.run_on_socket(config, &listener).await;
            });
        });

        // The console's own key, exactly as pairing leaves it.
        let key = crate::sshkey::SshKey::generate().expect("key");
        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, &key.private_pem).expect("write key");

        let session = start(Start {
            host: "127.0.0.1".into(),
            port,
            user: "tester".into(),
            key: key_path,
            known_hosts: dir.join("known_hosts"),
            cols: 80,
            rows: 24,
            label: "test".into(),
        });

        expect_data(&session.events, "welcome");
        session
            .input
            .send(Input::Data(b"hi\n".to_vec()))
            .expect("send");
        expect_data(&session.events, "echo:hi");

        // The first connection records the host key, so a second one verifies.
        assert!(dir.join("known_hosts").exists());
        session.input.send(Input::Close).expect("close");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
