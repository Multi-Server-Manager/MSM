//! Conformance tests for `PROTOCOL.md` §10.
//!
//! The test names match the matrix in the protocol document and the Go node's
//! suite, so a missing requirement is visible on either side.

use msm_protocol::code::{ALPHABET, CODE_LEN, generate_code, normalize_code};
use msm_protocol::commands::{
    self, Command, LogsResult, MAX_PACKAGE_NAME_LEN, MAX_REQUEST_ID_LEN, MAX_UNIT_LEN,
    MetricsResult, PackageResult, valid_package_name, valid_request_id, valid_unit,
};
use msm_protocol::derive::{Transcript, client_proof, mac_eq, node_proof, pair_keys};
use msm_protocol::frame::{MAX_FRAME_LEN, read_frame, write_frame};
use msm_protocol::messages;
use msm_protocol::messages::Setup;
use msm_protocol::tls::{Identity, SPKI_LEN, spki_from_cert_der};
use msm_protocol::{Message, ProtocolError};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd hex string");
    (0..value.len() / 2)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

fn hexed(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn frame_roundtrip() {
    let payload = br#"{"t":"info","v":1}"#;
    let mut buffer = Vec::new();
    write_frame(&mut buffer, payload).expect("write");
    assert_eq!(read_frame(&mut buffer.as_slice()).expect("read"), payload);

    // A frame of exactly the cap is legal.
    let exact = vec![b'a'; MAX_FRAME_LEN];
    buffer.clear();
    write_frame(&mut buffer, &exact).expect("write at cap");
    assert_eq!(read_frame(&mut buffer.as_slice()).expect("read at cap").len(), MAX_FRAME_LEN);
}

#[test]
fn frame_zero_length() {
    let header = [0u8; 4];
    let err = read_frame(&mut header.as_slice()).unwrap_err();
    assert_eq!(err.code(), "bad_frame");

    let mut buffer = Vec::new();
    assert!(write_frame(&mut buffer, &[]).is_err());
}

#[test]
fn frame_cap() {
    let mut header = [0u8; 4];
    header.copy_from_slice(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes());

    // Rejection must happen from the header alone; no payload follows.
    let err = read_frame(&mut header.as_slice()).unwrap_err();
    assert_eq!(err.code(), "bad_frame");
    assert!(matches!(err, ProtocolError::BadFrame(_)));
}

#[test]
fn frame_unknown_type() {
    let err = messages::decode(br#"{"t":"pair.renegotiate","v":1}"#).unwrap_err();
    assert_eq!(err.code(), "unknown_type");
}

#[test]
fn frame_bad_version() {
    for payload in [
        br#"{"t":"info","v":2}"#.as_slice(),
        br#"{"t":"info","v":0}"#.as_slice(),
        br#"{"t":"info"}"#.as_slice(),
        br#"{"t":"info","v":"1"}"#.as_slice(),
    ] {
        let err = messages::decode(payload).unwrap_err();
        assert_eq!(err.code(), "bad_version", "payload {:?}", payload);
    }
}

#[test]
fn frame_malformed() {
    for payload in [
        b"[1,2,3]".as_slice(),
        b"\"pair.hello\"".as_slice(),
        b"{\"t\":\"info\",\"v\":".as_slice(),
        b"".as_slice(),
        b"{\"v\":1}".as_slice(),
        b"{\"t\":5,\"v\":1}".as_slice(),
    ] {
        let err = messages::decode(payload).unwrap_err();
        assert_eq!(err.code(), "bad_frame", "payload {:?}", payload);
    }

    // Unknown members are ignored.
    let message = messages::decode(br#"{"t":"info","v":1,"extra":"ignored"}"#).expect("decode");
    assert_eq!(message.kind(), "info");
}

#[test]
fn code_generate() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let code = generate_code(&mut rng);
        assert_eq!(code.len(), CODE_LEN);
        for byte in code.bytes() {
            assert!(ALPHABET.contains(&byte), "out-of-alphabet byte {byte}");
        }
        seen.insert(code);
    }
    assert_eq!(seen.len(), 200);

    // All-zero bytes encode to the first character, all-ones to the last: this
    // pins the bit order.
    assert_eq!(generate_code(&mut ZeroRng), "00000000");
    assert_eq!(generate_code(&mut OnesRng), "ZZZZZZZZ");
}

struct ZeroRng;

struct OnesRng;

impl rand::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill(0);
        Ok(())
    }
}

impl rand::RngCore for OnesRng {
    fn next_u32(&mut self) -> u32 {
        u32::MAX
    }
    fn next_u64(&mut self) -> u64 {
        u64::MAX
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0xff);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill(0xff);
        Ok(())
    }
}

#[test]
fn code_normalise() {
    let accepted = [
        ("7K3M9QXA", "7K3M9QXA"),
        ("7k3m9qxa", "7K3M9QXA"),
        ("7K3M-9QXA", "7K3M9QXA"),
        (" 7k3m 9qxa ", "7K3M9QXA"),
        ("7K3M9QXI", "7K3M9QX1"),
        ("7K3M9QXL", "7K3M9QX1"),
        ("7K3M9QXO", "7K3M9QX0"),
        ("0000-0000", "00000000"),
        ("zzzzzzzz", "ZZZZZZZZ"),
    ];
    for (input, want) in accepted {
        assert_eq!(normalize_code(input).expect("accepted"), want, "input {input:?}");
    }

    for input in ["", "7K3M9QX", "7K3M9QXAA", "7K3M9QXA!", "U7K3M9QX"] {
        assert!(normalize_code(input).is_err(), "input {input:?} was accepted");
    }
}

#[test]
fn hkdf_rfc5869() {
    let ikm = vec![0x0b; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let prk = msm_protocol::hkdf::extract(&salt, &ikm);
    assert_eq!(
        hexed(&prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );

    let okm = msm_protocol::hkdf::expand(&prk, &info, 42).expect("expand");
    assert_eq!(
        hexed(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    assert!(msm_protocol::hkdf::expand(&prk, &info, 0).is_err());
    assert!(msm_protocol::hkdf::expand(&prk, &info, 255 * 32 + 1).is_err());
}

#[test]
fn derive_vectors() {
    let node_spki = [hex("302a300506032b6570032100"), vec![0x77; 32]].concat();
    let client_spki = [hex("302a300506032b6570032100"), vec![0x88; 32]].concat();

    let transcript = Transcript {
        client_eph: &[0x11; 32],
        node_eph: &[0x22; 32],
        client_nonce: &[0x33; 16],
        node_nonce: &[0x44; 16],
        node_id: &[0x55; 16],
        node_spki: &node_spki,
        client_id: &[0x66; 16],
        client_spki: &client_spki,
    };
    let th = transcript.hash();
    assert_eq!(
        hexed(&th),
        "bd32dac41b5f3c00a69923cb5dd91234aa846136283eed72fd84223e811ccf7a"
    );

    let shared: Vec<u8> = (0u8..32).collect();
    let (client_key, node_key) = pair_keys("7K3M9QXA", &shared).expect("pair keys");
    assert_eq!(
        hexed(&client_key),
        "0cbf791edfaddf0d68a5f054890406e4036be9f1736b788ba1d6c276231d67f0"
    );
    assert_eq!(
        hexed(&node_key),
        "8380e037d87ff7081d4185b6be150dcd07e5fcb4dbf44d3ec1b2fe137581bc64"
    );

    assert_eq!(
        hexed(&client_proof(&client_key, &th)),
        "dd2ec1d589496749a721d62584f9d7b115c65d35d4005028192cb74a9858bc5c"
    );
    assert_eq!(
        hexed(&node_proof(&node_key, &th)),
        "bda7348ebf2ae7b6276f5502a664519b74bf2567d92afa3bdd69ddc44106ec66"
    );

    // One wrong character in the code changes the client proof.
    let (wrong_key, _) = pair_keys("7K3M9QXB", &shared).expect("pair keys");
    assert_eq!(
        hexed(&client_proof(&wrong_key, &th)),
        "7a449a29cbb7b56047aef45f42d617e3af40e7884760cf7e9107dbe678e6b4f3"
    );
    assert!(!mac_eq(
        &client_proof(&wrong_key, &th),
        &client_proof(&client_key, &th)
    ));

    // Field order and every field matter.
    let swapped = Transcript {
        client_eph: &[0x22; 32],
        node_eph: &[0x11; 32],
        ..transcript
    };
    assert_ne!(swapped.hash(), th);
}

#[test]
fn spki_ed25519() {
    let identity = Identity::generate("msm-node").expect("generate");
    assert_eq!(identity.spki().len(), SPKI_LEN);
    assert_eq!(identity.id().len(), 16);

    let from_cert = spki_from_cert_der(identity.certificate()).expect("pin from cert");
    assert_eq!(from_cert, identity.spki());

    // A certificate that does not carry an Ed25519 SPKI is rejected.
    assert!(spki_from_cert_der(&[0u8; 8]).is_err());
    assert!(spki_from_cert_der(&[0u8; 200]).is_err());

    // A stored identity keeps the same pin.
    let restored =
        Identity::from_stored(&identity.id_b64(), &identity.key_b64(), "msm-node").expect("restore");
    assert_eq!(restored.spki(), identity.spki());
    assert_eq!(restored.id(), identity.id());
}

#[test]
fn message_roundtrip() {
    let message = Message::PairChallenge {
        v: 1,
        eph: msm_protocol::b64::encode(&[1u8; 32]),
        nonce: msm_protocol::b64::encode(&[2u8; 16]),
        node_id: msm_protocol::b64::encode(&[3u8; 16]),
        node_spki: msm_protocol::b64::encode(&[4u8; 44]),
        op_port: 7333,
        ttl_left: 300,
        trials_left: 3,
    };
    let payload = messages::encode(&message).expect("encode");
    assert_eq!(messages::decode(&payload).expect("decode"), message);
}

#[test]
fn command_roundtrip() {
    // The expected strings are the same literals the Go suite asserts, so a
    // field-order or spelling drift between the two shows up here.
    let cases: Vec<(Message, &str)> = vec![
        (
            Message::PkgUpdate {
                v: 1,
                id: "a1".into(),
            },
            r#"{"t":"pkg.update","v":1,"id":"a1"}"#,
        ),
        (
            Message::PkgInstall {
                v: 1,
                id: "a1".into(),
                name: "ripgrep".into(),
            },
            r#"{"t":"pkg.install","v":1,"id":"a1","name":"ripgrep"}"#,
        ),
        (
            Message::SvcRestart {
                v: 1,
                id: "a1".into(),
                unit: "sshd.service".into(),
            },
            r#"{"t":"svc.restart","v":1,"id":"a1","unit":"sshd.service"}"#,
        ),
        (
            Message::HostReboot {
                v: 1,
                id: "a1".into(),
                confirm: "reboot".into(),
            },
            r#"{"t":"host.reboot","v":1,"id":"a1","confirm":"reboot"}"#,
        ),
        (
            Message::MetricsSample {
                v: 1,
                id: "a1".into(),
            },
            r#"{"t":"metrics.sample","v":1,"id":"a1"}"#,
        ),
        (
            Message::LogsTail {
                v: 1,
                id: "a1".into(),
                lines: 20,
            },
            r#"{"t":"logs.tail","v":1,"id":"a1","lines":20}"#,
        ),
        (
            Message::SshAuthorize {
                v: 1,
                id: "a1".into(),
                key: "ssh-ed25519 AAAA msm-console".into(),
                user: String::new(),
            },
            r#"{"t":"ssh.authorize","v":1,"id":"a1","key":"ssh-ed25519 AAAA msm-console"}"#,
        ),
        (
            Message::SshAuthorize {
                v: 1,
                id: "a1".into(),
                key: "ssh-ed25519 AAAA msm-console".into(),
                user: "admin".into(),
            },
            r#"{"t":"ssh.authorize","v":1,"id":"a1","key":"ssh-ed25519 AAAA msm-console","user":"admin"}"#,
        ),
        (
            Message::NodeSetup {
                v: 1,
                id: "a1".into(),
                run_as: "root".into(),
                ssh_user: "admin".into(),
                ssh_port: 2200,
            },
            r#"{"t":"node.setup","v":1,"id":"a1","run_as":"root","ssh_user":"admin","ssh_port":2200}"#,
        ),
    ];

    for (message, want) in cases {
        let encoded = String::from_utf8(messages::encode(&message).expect("encode")).expect("utf8");
        assert_eq!(encoded, want, "{} encoding", message.kind());
        assert_eq!(
            messages::decode(want.as_bytes()).expect("decode"),
            message,
            "{} roundtrip",
            message.kind()
        );
    }
}

#[test]
fn command_builders() {
    assert_eq!(
        Command::PkgInstall("aero".into()).into_message("i1"),
        Message::PkgInstall {
            v: 1,
            id: "i1".into(),
            name: "aero".into(),
        }
    );
    assert_eq!(
        Command::MetricsSample.into_message("i2"),
        Message::MetricsSample {
            v: 1,
            id: "i2".into(),
        }
    );
    assert_eq!(Command::LogsTail(5).describe(), "logs.tail 5");
    assert_eq!(Command::SvcRestart(String::new()).describe(), "svc.restart self");
    assert_eq!(Command::HostReboot("reboot".into()).describe(), "host.reboot");
    assert_eq!(
        Command::NodeSetup(Setup {
            run_as: "root".into(),
            ssh_user: "admin".into(),
            ssh_port: 22,
        })
        .describe(),
        "node.setup run_as=root ssh_user=admin ssh_port=22"
    );
}

#[test]
fn setup_travels_only_when_answered() {
    // A console that pairs without answering keeps the old wire shape, so an
    // older node sees exactly the message it always saw.
    let proof = Message::PairProof {
        v: 1,
        mac: "m".into(),
        client_id: "c".into(),
        client_spki: "s".into(),
        setup: None,
    };
    let encoded = String::from_utf8(messages::encode(&proof).expect("encode")).expect("utf8");
    assert!(!encoded.contains("setup"), "{encoded}");

    let answered = Message::PairProof {
        v: 1,
        mac: "m".into(),
        client_id: "c".into(),
        client_spki: "s".into(),
        setup: Some(Setup {
            run_as: "root".into(),
            ssh_user: "admin".into(),
            ssh_port: 2222,
        }),
    };
    let encoded = String::from_utf8(messages::encode(&answered).expect("encode")).expect("utf8");
    assert!(encoded.contains(r#""setup":{"run_as":"root","ssh_user":"admin","ssh_port":2222}"#));

    // A node that predates the exchange sends neither the key nor the answers.
    let older: Message = messages::decode(
        br#"{"t":"pair.ok","v":1,"mac":"m","node_id":"n","node_spki":"s","op_port":7333}"#,
    )
    .expect("decode an older pair.ok");
    match older {
        Message::PairOk {
            ssh_key, setup, ..
        } => {
            assert!(ssh_key.is_empty());
            assert!(setup.is_none());
        }
        other => panic!("decoded {}", other.kind()),
    }
}

#[test]
fn command_result_envelope() {
    // A refusal as the Go node writes it: absent members are absent, not null.
    let refused = br#"{"t":"result","v":1,"id":"req-1","ok":false,"code":"bad_argument","detail":"nope"}"#;
    match messages::decode(refused).expect("decode refusal") {
        Message::Result {
            id,
            ok,
            code,
            detail,
            data,
            ..
        } => {
            assert_eq!(id, "req-1");
            assert!(!ok);
            assert_eq!(code.as_deref(), Some("bad_argument"));
            assert_eq!(detail.as_deref(), Some("nope"));
            assert!(data.is_none());
        }
        other => panic!("decoded {}", other.kind()),
    }

    let success = commands::success(
        "req-1",
        serde_json::to_value(LogsResult {
            lines: vec!["a".into(), "b".into()],
            dropped: 3,
        })
        .expect("payload"),
    );
    let encoded = String::from_utf8(messages::encode(&success).expect("encode")).expect("utf8");
    assert_eq!(
        encoded,
        r#"{"t":"result","v":1,"id":"req-1","ok":true,"data":{"lines":["a","b"],"dropped":3}}"#
    );

    let failure = commands::failure("req-2", "busy", "another command is running", None);
    let encoded = String::from_utf8(messages::encode(&failure).expect("encode")).expect("utf8");
    assert_eq!(
        encoded,
        r#"{"t":"result","v":1,"id":"req-2","ok":false,"code":"busy","detail":"another command is running"}"#
    );
}

#[test]
fn package_name_charset() {
    for name in ["aero", "ripgrep-14", "libstdc++", "python3.11:amd64", "node_18", "a"] {
        assert!(valid_package_name(name), "{name} should be accepted");
    }

    let too_long = "a".repeat(MAX_PACKAGE_NAME_LEN + 1);
    for name in [
        "",
        "-y",
        "--force",
        ".",
        "..",
        "a b",
        "a;rm -rf /",
        "$(id)",
        "a|b",
        "a&b",
        "a/b",
        "../etc",
        "a\nb",
        "`id`",
        &too_long,
    ] {
        assert!(!valid_package_name(name), "{name:?} should be refused");
    }
}

#[test]
fn unit_charset() {
    for unit in ["sshd", "sshd.service", "getty@tty1.service", "msm-node"] {
        assert!(valid_unit(unit), "{unit} should be accepted");
    }

    let too_long = "a".repeat(MAX_UNIT_LEN + 1);
    for unit in ["", "a b", "--now", "-1", "a/b", "a;b", "a$b", &too_long] {
        assert!(!valid_unit(unit), "{unit:?} should be refused");
    }
}

#[test]
fn request_id_charset() {
    for id in ["a", "req-1", "A_b-9"] {
        assert!(valid_request_id(id), "{id} should be accepted");
    }
    for id in ["", "a b", "a\"b", "a\tb"] {
        assert!(!valid_request_id(id), "{id:?} should be refused");
    }

    let longest = "z".repeat(MAX_REQUEST_ID_LEN);
    assert!(valid_request_id(&longest));
    assert!(!valid_request_id(&format!("{longest}z")));
}

#[test]
fn command_payloads() {
    // A package result as the Go node writes it, including a negative exit code.
    let payload = br#"{"manager":"dnf","commands":[["dnf","-y","install","dpkg"]],"exit_code":-1,"output":"error: unable to find a match"}"#;
    let parsed: PackageResult = serde_json::from_slice(payload).expect("package payload");
    assert_eq!(parsed.manager, "dnf");
    assert_eq!(parsed.commands, vec![vec!["dnf", "-y", "install", "dpkg"]]);
    assert_eq!(parsed.exit_code, -1);

    let payload = br#"{"load1":0.5,"load5":0.25,"load15":0.1,"cpu_count":2,"mem_total_kb":1024,"mem_available_kb":512,"uptime_s":9,"disk_total_kb":2048,"disk_available_kb":1024}"#;
    let metrics: MetricsResult = serde_json::from_slice(payload).expect("metrics payload");
    assert_eq!(metrics.cpu_count, 2);
    assert_eq!(metrics.mem_available_kb, 512);

    let payload = br#"{"lines":["one"],"dropped":7}"#;
    let logs: LogsResult = serde_json::from_slice(payload).expect("logs payload");
    assert_eq!(logs.lines, vec!["one".to_string()]);
    assert_eq!(logs.dropped, 7);
}
