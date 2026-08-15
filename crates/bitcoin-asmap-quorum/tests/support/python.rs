//! Locating, launching and talking to the Python oracle.
//!
//! Included with `#[path]` by `differential_python.rs` rather than compiled as
//! its own test target (`tests/support/` is not auto-discovered by Cargo).
//!
//! A missing or too-old interpreter is a **hard failure**, never a silent skip:
//! the whole point of the feature gate is that turning it on means the oracle
//! ran. A differential test that quietly skips is worse than no test.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

/// Repository root, derived from the manifest directory rather than the working
/// directory, so the tests are runnable from anywhere.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

/// The vendored reference implementation's directory.
pub fn vendored_asmap_dir() -> PathBuf {
    let dir = repo_root().join("contrib/asmap");
    assert!(
        dir.join("asmap.py").is_file(),
        "vendored contrib/asmap/asmap.py is missing at {}",
        dir.display()
    );
    dir
}

/// `$ASMAP_PYTHON` if set, else `python3` from `PATH`.
pub fn interpreter() -> String {
    std::env::var("ASMAP_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

/// A fresh scratch directory under `target/`, used as the cwd for every child
/// process so nothing is written next to the sources.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = repo_root()
        .join("target/tmp/differential")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Builds a `Command` with a cleared environment.
///
/// Only `PATH` survives (so `python3` resolves), plus `PYTHONHASHSEED=0` and
/// `LC_ALL=C` for determinism. `-B` suppresses `__pycache__` writes.
fn python_command(cwd: &Path) -> Command {
    let mut cmd = Command::new(interpreter());
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("PYTHONHASHSEED", "0");
    cmd.env("LC_ALL", "C");
    cmd.current_dir(cwd);
    cmd
}

/// Runs `contrib/asmap/asmap-tool.py` with the given arguments.
///
/// Uses `-s -B` rather than `-I`: `-I` also stops the script's own directory
/// being prepended to `sys.path`, which would make `asmap-tool.py`'s
/// `import asmap` fail. With the environment cleared there is no `PYTHONPATH`
/// to isolate from, and `-s` still keeps user site-packages out, so the
/// vendored copy is the only importable one either way.
pub fn run_asmap_tool(cwd: &Path, args: &[&str]) -> Output {
    let tool = vendored_asmap_dir().join("asmap-tool.py");
    let mut cmd = python_command(cwd);
    cmd.arg("-s").arg("-B").arg(&tool).args(args);
    cmd.output().unwrap_or_else(|e| {
        panic!(
            "failed to run {} {}: {e}\n\
             The `python-differential` feature requires a working python3.",
            interpreter(),
            tool.display()
        )
    })
}

/// Facts the preflight established, printed once so a re-vendoring of
/// `asmap.py` is visible in a CI log rather than silently changing the oracle.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub version: (u64, u64, u64),
    pub executable: String,
    pub asmap_path: String,
    pub asmap_sha256: String,
}

/// A live oracle process.
pub struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pub cwd: PathBuf,
    pub preflight: Preflight,
    pub calls: u64,
}

impl Oracle {
    /// Starts the worker and runs the preflight. Panics with an actionable
    /// message if python is missing, too old, or the vendored copy is absent.
    pub fn start(scratch_name: &str) -> Self {
        let cwd = scratch_dir(scratch_name);
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/asmap_ref.py");
        assert!(script.is_file(), "missing worker at {}", script.display());

        let mut cmd = python_command(&cwd);
        cmd.arg("-I")
            .arg("-B")
            .arg(&script)
            .arg(vendored_asmap_dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().unwrap_or_else(|e| {
            panic!(
                "could not start the python oracle ({} {}): {e}\n\
                 The `python-differential` feature requires python3 >= 3.9 on PATH \
                 (or $ASMAP_PYTHON). It is off by default precisely so that a clone \
                 without python still passes `cargo test`.",
                interpreter(),
                script.display()
            )
        });

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut oracle = Self {
            child,
            stdin,
            stdout,
            cwd,
            preflight: Preflight {
                version: (0, 0, 0),
                executable: String::new(),
                asmap_path: String::new(),
                asmap_sha256: String::new(),
            },
            calls: 0,
        };

        let resp = oracle.call(&json_obj(&[("cmd", Json::Str("preflight".into()))]));
        let version = resp.array("version");
        let preflight = Preflight {
            version: (
                version[0].as_u64(),
                version[1].as_u64(),
                version[2].as_u64(),
            ),
            executable: resp.string("executable"),
            asmap_path: resp.string("asmap_path"),
            asmap_sha256: resp.string("asmap_sha256"),
        };
        assert!(
            preflight.version >= (3, 9, 0),
            "python {:?} is too old; asmap.py evaluates PEP 585 generics at def time \
             and needs >= 3.9",
            preflight.version
        );
        println!(
            "oracle: {} ({}.{}.{})\noracle: {} sha256={}",
            preflight.executable,
            preflight.version.0,
            preflight.version.1,
            preflight.version.2,
            preflight.asmap_path,
            preflight.asmap_sha256,
        );
        oracle.preflight = preflight;
        oracle
    }

    /// Sends one request and reads one response.
    pub fn call(&mut self, request: &str) -> Json {
        self.calls += 1;
        writeln!(self.stdin, "{request}").expect("write to the oracle");
        self.stdin.flush().expect("flush the oracle");
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .expect("read from the oracle");
        assert!(
            read > 0,
            "the python oracle exited early; request was: {request}"
        );
        let value = Json::parse(&line);
        if let Json::Obj(fields) = &value
            && let Some(err) = fields.get("error")
        {
            panic!("python oracle error: {}\nrequest: {request}", err.as_str());
        }
        value
    }

    /// Generates a random map in the oracle and returns its rendering.
    pub fn generate(&mut self, seed: u64, leaves: u32, max_asn: u32, unassigned: f64) -> Json {
        self.call(&json_obj(&[
            ("cmd", Json::Str("gen".into())),
            ("seed", Json::Num(seed as f64)),
            ("leaves", Json::Num(leaves as f64)),
            ("max_asn", Json::Num(max_asn as f64)),
            ("unassigned", Json::Num(unassigned)),
        ]))
    }

    /// Asks the oracle to decode a binary payload.
    pub fn decode_binary(&mut self, hex: &str) -> Json {
        self.call(&json_obj(&[
            ("cmd", Json::Str("from_binary".into())),
            ("hex", Json::Str(hex.into())),
        ]))
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "{{\"cmd\":\"quit\"}}");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// A 150-line JSON reader/writer.
//
// The protocol is fixed and machine-generated, so a full serde dependency in
// the workspace's dev-dependencies would buy nothing. Only what the protocol
// actually uses is implemented.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn parse(text: &str) -> Json {
        let chars: Vec<char> = text.chars().collect();
        let mut pos = 0usize;
        parse_value(&chars, &mut pos)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("expected a JSON string, got {other:?}"),
        }
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Json::Num(n) => *n as u64,
            other => panic!("expected a JSON number, got {other:?}"),
        }
    }

    pub fn as_bool(&self) -> bool {
        match self {
            Json::Bool(b) => *b,
            other => panic!("expected a JSON bool, got {other:?}"),
        }
    }

    pub fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(fields) => fields
                .get(key)
                .unwrap_or_else(|| panic!("missing key {key:?} in {self:?}")),
            other => panic!("expected a JSON object, got {other:?}"),
        }
    }

    pub fn opt(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.get(key),
            _ => None,
        }
    }

    pub fn string(&self, key: &str) -> String {
        self.get(key).as_str().to_string()
    }

    pub fn array(&self, key: &str) -> &[Json] {
        match self.get(key) {
            Json::Arr(items) => items,
            other => panic!("expected a JSON array at {key:?}, got {other:?}"),
        }
    }

    /// An array of strings, the shape every entry list uses.
    pub fn strings(&self, key: &str) -> Vec<String> {
        self.array(key)
            .iter()
            .map(|v| v.as_str().to_string())
            .collect()
    }
}

fn skip_ws(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn parse_value(chars: &[char], pos: &mut usize) -> Json {
    skip_ws(chars, pos);
    match chars.get(*pos) {
        Some('{') => {
            *pos += 1;
            let mut fields = BTreeMap::new();
            skip_ws(chars, pos);
            if chars.get(*pos) == Some(&'}') {
                *pos += 1;
                return Json::Obj(fields);
            }
            loop {
                skip_ws(chars, pos);
                let key = match parse_value(chars, pos) {
                    Json::Str(s) => s,
                    other => panic!("object key must be a string, got {other:?}"),
                };
                skip_ws(chars, pos);
                assert_eq!(chars.get(*pos), Some(&':'), "expected ':' after object key");
                *pos += 1;
                fields.insert(key, parse_value(chars, pos));
                skip_ws(chars, pos);
                match chars.get(*pos) {
                    Some(',') => *pos += 1,
                    Some('}') => {
                        *pos += 1;
                        return Json::Obj(fields);
                    }
                    other => panic!("expected ',' or '}}' in object, got {other:?}"),
                }
            }
        }
        Some('[') => {
            *pos += 1;
            let mut items = Vec::new();
            skip_ws(chars, pos);
            if chars.get(*pos) == Some(&']') {
                *pos += 1;
                return Json::Arr(items);
            }
            loop {
                items.push(parse_value(chars, pos));
                skip_ws(chars, pos);
                match chars.get(*pos) {
                    Some(',') => *pos += 1,
                    Some(']') => {
                        *pos += 1;
                        return Json::Arr(items);
                    }
                    other => panic!("expected ',' or ']' in array, got {other:?}"),
                }
            }
        }
        Some('"') => {
            *pos += 1;
            let mut out = String::new();
            loop {
                let ch = *chars.get(*pos).expect("unterminated string");
                *pos += 1;
                match ch {
                    '"' => return Json::Str(out),
                    '\\' => {
                        let esc = *chars.get(*pos).expect("dangling escape");
                        *pos += 1;
                        out.push(match esc {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            'b' => '\u{8}',
                            'f' => '\u{c}',
                            'u' => {
                                let hex: String = chars[*pos..*pos + 4].iter().collect();
                                *pos += 4;
                                let code = u32::from_str_radix(&hex, 16).expect("\\u escape");
                                char::from_u32(code).expect("valid code point")
                            }
                            other => other,
                        });
                    }
                    other => out.push(other),
                }
            }
        }
        Some('t') => {
            *pos += 4;
            Json::Bool(true)
        }
        Some('f') => {
            *pos += 5;
            Json::Bool(false)
        }
        Some('n') => {
            *pos += 4;
            Json::Null
        }
        Some(_) => {
            let start = *pos;
            while *pos < chars.len()
                && (chars[*pos].is_ascii_digit() || "+-.eE".contains(chars[*pos]))
            {
                *pos += 1;
            }
            let text: String = chars[start..*pos].iter().collect();
            Json::Num(
                text.parse()
                    .unwrap_or_else(|_| panic!("bad number {text:?}")),
            )
        }
        None => panic!("unexpected end of JSON input"),
    }
}

/// Serialises a flat object. Sufficient for every request the protocol sends.
pub fn json_obj(fields: &[(&str, Json)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("{}:{}", json_str(key), json_write(value)))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn json_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_write(value: &Json) -> String {
    match value {
        Json::Null => "null".into(),
        Json::Bool(true) => "true".into(),
        Json::Bool(false) => "false".into(),
        // The protocol carries only exact-integer counts and the three
        // probabilities, so a plain `{}` rendering is lossless here.
        Json::Num(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
        Json::Str(s) => json_str(s),
        Json::Arr(items) => format!(
            "[{}]",
            items.iter().map(json_write).collect::<Vec<_>>().join(",")
        ),
        Json::Obj(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(k, v)| format!("{}:{}", json_str(k), json_write(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// Lowercase hex, matching python's `bytes.hex()`.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of [`to_hex`].
pub fn from_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex: {text:?}");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}
