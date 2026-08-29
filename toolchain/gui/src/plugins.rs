//! GUI host for out-of-process RESQ plugins.
//!
//! Discovery: scans `plugins/` directories (next to the exe, then cwd) for
//! `resq-plugin.toml` manifests; the plugin executable is expected next to
//! the manifest, named `<manifest.name><EXE_SUFFIX>`.
//!
//! Protocol: the host speaks the MCP method surface (`initialize`,
//! `notifications/initialized`, `tools/list`, `tools/call`) so MCP servers
//! like resq-mcp work as-is; plain RESQ plugins can answer the same
//! methods. stdout lines come back through a reader thread -> mpsc and are
//! drained non-blockingly from the UI loop via [`PluginHost::poll`].

use resq_plugin_sdk::Manifest;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};

/// Cap on the per-plugin protocol log shown in the Plugins window.
const LOG_CAP: usize = 500;
/// Client identity reported in `initialize.clientInfo`.
pub const CLIENT_INFO: (&str, &str) = ("resq-gui", env!("CARGO_PKG_VERSION"));

/// A discovered (not necessarily running) plugin.
#[derive(Debug, Clone)]
pub struct PluginEntry {
    pub manifest: Manifest,
    pub exe: PathBuf,
}

/// One event drained from a running plugin.
#[derive(Debug)]
pub enum Ev {
    /// Protocol/transport log line (already formatted).
    Log(usize, String),
    /// `tools/list` answered; count of tools now cached.
    Tools(usize, usize),
    /// Tool call finished; payload is the text content or error message.
    ToolDone(usize, String),
    /// The plugin process closed stdout.
    Exited(usize),
}

struct Pending {
    tool: Option<String>,
}

/// One running plugin process.
pub struct Running {
    pub name: String,
    pub version: String,
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Option<String>>,
    next_id: u64,
    pending: HashMap<u64, Pending>,
    /// Request id of the outstanding MCP `initialize` (if any); the
    /// initialized notification and `tools/list` wait for its response.
    init_id: Option<u64>,
    /// Cached `tools/list` result (name, description).
    pub tools: Vec<(String, String)>,
    /// Protocol log (request/response lines, capped).
    pub log: VecDeque<String>,
    pub requests: usize,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    /// Send one request; returns its id. Non-blocking (pipes are buffered).
    fn request(&mut self, method: &str, params: &Value, tool: Option<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let msg = serde_json::json!({ "id": id, "method": method, "params": params });
        self.send_line(&msg.to_string());
        self.pending.insert(id, Pending { tool });
        id
    }

    /// Send one notification (no id, no reply expected).
    fn notify(&mut self, method: &str, params: &Value) {
        let msg = serde_json::json!({ "method": method, "params": params });
        self.send_line(&msg.to_string());
    }

    fn send_line(&mut self, line: &str) {
        self.log.push_back(format!(">> {line}"));
        if self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
        if writeln!(self.stdin, "{line}")
            .and_then(|()| self.stdin.flush())
            .is_err()
        {
            // Broken pipe: the reader thread will observe EOF and report exit.
        }
    }

    /// Drain stdout lines and resolve pending requests. Returns events for
    /// the UI.
    fn poll(&mut self, idx: usize) -> Vec<Ev> {
        let mut evs = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(Some(line)) => {
                    self.log.push_back(format!("<< {line}"));
                    if self.log.len() > LOG_CAP {
                        self.log.pop_front();
                    }
                    if let Some(ev) = self.on_line(idx, &line) {
                        evs.push(ev);
                    }
                }
                Ok(None) => {
                    evs.push(Ev::Exited(idx));
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    evs.push(Ev::Exited(idx));
                    break;
                }
            }
        }
        evs
    }

    fn on_line(&mut self, idx: usize, line: &str) -> Option<Ev> {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return Some(Ev::Log(idx, format!("unparseable: {line}")));
        };
        let id = v.get("id").and_then(Value::as_u64)?;
        let kind = self.pending.remove(&id)?;
        if let Some(err) = v.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Some(match kind.tool {
                Some(_) => Ev::ToolDone(idx, format!("error: {msg}")),
                None => Ev::Log(idx, msg.to_string()),
            });
        }
        let result = v.get("result").cloned().unwrap_or(Value::Null);
        match kind.tool {
            Some(tool) => {
                let is_err = result.get("isError").and_then(Value::as_bool) == Some(true);
                let text = content_text(&result).unwrap_or_else(|| result.to_string());
                Some(Ev::ToolDone(
                    idx,
                    if is_err {
                        format!("{tool} failed: {text}")
                    } else {
                        text
                    },
                ))
            }
            None => {
                if self.init_id == Some(id) {
                    self.init_id = None;
                    // MCP sequencing: notifications/initialized and further
                    // requests may go out only after the initialize response.
                    self.notify("notifications/initialized", &Value::Null);
                    self.request("tools/list", &Value::Null, None);
                }
                if let Some(tools) = result.get("tools").and_then(Value::as_array) {
                    self.tools = tools
                        .iter()
                        .filter_map(|t| {
                            let name = t.get("name")?.as_str()?.to_string();
                            let desc = t
                                .get("description")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            Some((name, desc))
                        })
                        .collect();
                    return Some(Ev::Tools(idx, self.tools.len()));
                }
                None
            }
        }
    }
}

/// Extract `content[0].text` from an MCP tool result, if shaped that way.
fn content_text(result: &Value) -> Option<String> {
    let c = result.get("content")?.as_array()?.first()?;
    c.get("text")?.as_str().map(str::to_string)
}

/// Plugin host state owned by the App.
pub struct PluginHost {
    /// Discovered plugins (refreshed by [`PluginHost::rescan`]).
    pub found: Vec<PluginEntry>,
    /// Spawned plugin sessions, in start order.
    pub running: Vec<Running>,
    /// Scan directories used last rescan (shown in the UI).
    pub dirs: Vec<PathBuf>,
}

impl Default for PluginHost {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginHost {
    pub fn new() -> PluginHost {
        let mut host = PluginHost {
            found: Vec::new(),
            running: Vec::new(),
            dirs: Vec::new(),
        };
        host.rescan();
        host
    }

    /// Plugin dirs: `plugins/` next to the exe, then cwd `plugins/`.
    pub fn plugin_dirs() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(d) = exe.parent() {
                dirs.push(d.join("plugins"));
            }
        }
        dirs.push(PathBuf::from("plugins"));
        dirs
    }

    /// Dev-mode fallback: plugin repos checked out next to this repo with a
    /// root `resq-plugin.toml` and a built binary in `target/{release,debug}`.
    /// Keeps the edit-build-run loop free of manual copy steps; in packaged
    /// builds nothing matches and `plugins/` is the only source.
    fn dev_candidates() -> Vec<PluginEntry> {
        let mut bases: Vec<PathBuf> = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            // Depth 4 reaches the sibling layout
            // GitHub/{RESQ-kit/toolchain/gui, resq-mcp}.
            for a in cwd.ancestors().take(4) {
                bases.push(a.to_path_buf());
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(d) = exe.parent() {
                for a in d.ancestors().take(4) {
                    bases.push(a.to_path_buf());
                }
            }
        }
        let mut out = Vec::new();
        for base in bases {
            let Ok(rd) = std::fs::read_dir(&base) else {
                continue;
            };
            let mut folders: Vec<_> = rd.flatten().collect();
            folders.sort_by_key(|p| p.path());
            for f in folders {
                let path = f.path();
                if !path.is_dir() || !path.join("resq-plugin.toml").is_file() {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(path.join("resq-plugin.toml")) else {
                    continue;
                };
                let Ok(manifest) = Manifest::parse(&text) else {
                    continue;
                };
                for profile in ["release", "debug"] {
                    let exe = path.join("target").join(profile).join(format!(
                        "{}{}",
                        manifest.name,
                        std::env::consts::EXE_SUFFIX
                    ));
                    if exe.is_file() {
                        out.push(PluginEntry { manifest, exe });
                        break;
                    }
                }
            }
        }
        out
    }

    /// Rescan all sources: `plugins/` dirs first (they win), then dev
    /// sibling checkouts not already covered.
    pub fn rescan(&mut self) {
        self.dirs = Self::plugin_dirs();
        self.found = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for dir in &self.dirs {
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut folders: Vec<_> = rd.flatten().collect();
            folders.sort_by_key(|p| p.path());
            for f in folders {
                let path = f.path();
                if !path.is_dir() {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(path.join("resq-plugin.toml")) else {
                    continue;
                };
                let Ok(manifest) = Manifest::parse(&text) else {
                    eprintln!("plugins: bad manifest in {}", path.display());
                    continue;
                };
                let exe = path.join(format!("{}{}", manifest.name, std::env::consts::EXE_SUFFIX));
                if !exe.is_file() {
                    eprintln!(
                        "plugins: {} missing executable {}",
                        manifest.name,
                        exe.display()
                    );
                    continue;
                }
                if seen.insert(manifest.name.clone()) {
                    self.found.push(PluginEntry { manifest, exe });
                }
            }
        }
        for e in Self::dev_candidates() {
            if seen.insert(e.manifest.name.clone()) {
                self.found.push(e);
            }
        }
    }

    /// Spawn plugin `found[i]`, run the MCP handshake and ask for tools.
    pub fn start(&mut self, i: usize) -> Result<usize, String> {
        let entry = self
            .found
            .get(i)
            .ok_or_else(|| "bad plugin index".to_string())?;
        let mut child = Command::new(&entry.exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", entry.exe.display()))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel::<Option<String>>();
        if let Err(e) = std::thread::Builder::new()
            .name(format!("resq-plugin-{}", entry.manifest.name))
            .spawn(move || {
                let rd = BufReader::new(stdout);
                for line in rd.lines() {
                    if tx.send(Some(line.unwrap_or_default())).is_err() {
                        break;
                    }
                }
                let _ = tx.send(None);
            })
        {
            // Reader thread failed to start: do not leak the child process.
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("spawn reader: {e}"));
        }

        let mut r = Running {
            name: entry.manifest.name.clone(),
            version: entry.manifest.version.clone(),
            child,
            stdin,
            rx,
            next_id: 0,
            pending: HashMap::new(),
            init_id: None,
            tools: Vec::new(),
            log: VecDeque::new(),
            requests: 0,
        };
        // MCP handshake: send `initialize` only. The initialized notification
        // and `tools/list` go out once its response arrives (MCP sequencing),
        // see `Running::on_line`.
        let init = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": CLIENT_INFO.0, "version": CLIENT_INFO.1 },
        });
        let init_id = r.request("initialize", &init, None);
        r.init_id = Some(init_id);
        self.running.push(r);
        Ok(self.running.len() - 1)
    }

    /// Call a tool on running plugin `i`.
    pub fn call_tool(&mut self, i: usize, tool: &str, args: Value) -> Result<(), String> {
        let r = self.running.get_mut(i).ok_or("plugin not running")?;
        r.request(
            "tools/call",
            &serde_json::json!({ "name": tool, "arguments": args }),
            Some(tool.to_string()),
        );
        r.requests += 1;
        Ok(())
    }

    /// Drain events from every running plugin.
    pub fn poll(&mut self) -> Vec<Ev> {
        let mut out = Vec::new();
        for i in 0..self.running.len() {
            out.extend(self.running[i].poll(i));
        }
        out
    }

    /// Stop running plugin `i` (kill; Drop reaps).
    pub fn stop(&mut self, i: usize) {
        if i < self.running.len() {
            let mut r = self.running.remove(i);
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }

    pub fn stop_all(&mut self) {
        while !self.running.is_empty() {
            self.stop(self.running.len() - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `current_dir` is process-wide; tests that chdir serialize on this.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn rescan_finds_manifest_and_exe() {
        let dir = std::env::temp_dir().join(format!("resq_host_scan_{}", std::process::id()));
        let pdir = dir.join("plugins").join("resq-stub");
        std::fs::create_dir_all(&pdir).expect("mkdir");
        std::fs::write(
            pdir.join("resq-plugin.toml"),
            "name = \"resq-stub\"\nversion = \"0.3.0\"\nprotocol = 1\n",
        )
        .expect("manifest");
        let exe = pdir.join(format!("resq-stub{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"not really an exe").expect("exe placeholder");

        // Point discovery at our temp layout.
        let _g = CWD_LOCK.lock().unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).expect("chdir");
        let host = PluginHost::new();
        std::env::set_current_dir(&saved).expect("restore");

        assert_eq!(host.found.len(), 1, "{:?}", host.found);
        assert_eq!(host.found[0].manifest.name, "resq-stub");
        assert_eq!(host.found[0].manifest.version, "0.3.0");
        // Discovery joins cwd-relative dirs; compare the tail.
        assert!(host.found[0].exe.ends_with(exe.strip_prefix(&dir).unwrap()));

        // A folder without an executable is skipped.
        let empty = dir.join("plugins").join("resq-noexe");
        std::fs::create_dir_all(&empty).expect("mkdir2");
        std::fs::write(
            empty.join("resq-plugin.toml"),
            "name = \"resq-noexe\"\nversion = \"1.0\"\n",
        )
        .expect("manifest2");
        std::env::set_current_dir(&dir).expect("chdir2");
        let host2 = PluginHost::new();
        std::env::set_current_dir(&saved).expect("restore2");
        assert!(host2.found.iter().all(|f| f.manifest.name != "resq-noexe"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dev_discovery_finds_sibling_checkout() {
        // Layout: <root>/resq-stub/{resq-plugin.toml,target/release/<exe>},
        // cwd below <root> so ancestors() reaches it.
        let dir = std::env::temp_dir().join(format!("resq_host_dev_{}", std::process::id()));
        let pdir = dir.join("resq-stub");
        std::fs::create_dir_all(pdir.join("target").join("release")).expect("mkdir");
        std::fs::write(
            pdir.join("resq-plugin.toml"),
            "name = \"resq-stub\"\nversion = \"9.9\"\n",
        )
        .expect("manifest");
        let exe = pdir
            .join("target")
            .join("release")
            .join(format!("resq-stub{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"stub").expect("exe");

        let _g = CWD_LOCK.lock().unwrap();
        let saved = std::env::current_dir().unwrap();
        let deep = dir.join("deep");
        std::fs::create_dir_all(&deep).expect("mkdir deep");
        std::env::set_current_dir(&deep).expect("chdir");
        let cands = PluginHost::dev_candidates();
        std::env::set_current_dir(&saved).expect("restore");

        let hit = cands.iter().find(|c| c.manifest.name == "resq-stub");
        assert!(hit.is_some(), "no dev candidate in {cands:?}");
        assert_eq!(hit.unwrap().manifest.version, "9.9");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn content_text_extracts_mcp_shape() {
        let v = serde_json::json!({
            "content": [ { "type": "text", "text": "{\"functions\":1310}" } ],
            "structuredContent": { "functions": 1310 }
        });
        assert_eq!(content_text(&v).unwrap(), "{\"functions\":1310}");
        assert_eq!(content_text(&serde_json::json!({ "x": 1 })), None);
    }
}
