//! Headless host<->plugin probe: discovers a plugin in a given layout,
//! runs the MCP handshake, lists tools, drives open_qvm / session_info /
//! decompile_function against a real QVM. Not part of `cargo test`
//! (needs a built resq-mcp next to a manifest).
//!
//! Layout (create before running):
//!   <plugins_dir>/resq-mcp/resq-plugin.toml
//!   <plugins_dir>/resq-mcp/resq-mcp.exe
//!
//! Usage:
//!   cargo run --example host_probe -- <plugins_dir> <qvm_path>

use resq_gui::plugins::{Ev, PluginHost};
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: host_probe <plugins_dir> <qvm_path>");
        std::process::exit(2);
    }
    let (plugins_dir, qvm) = (&args[0], &args[1]);

    // The host scans `<cwd>/plugins`; the argument names that folder.
    let root = std::path::Path::new(plugins_dir)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    std::env::set_current_dir(&root).expect("chdir plugins root");
    let mut host = PluginHost::new();
    println!(
        "discovered {} plugin(s): {:?}",
        host.found.len(),
        host.found
            .iter()
            .map(|f| f.manifest.name.clone())
            .collect::<Vec<_>>()
    );
    let idx = match host
        .found
        .iter()
        .position(|f| f.manifest.name == "resq-mcp")
    {
        Some(i) => i,
        None => {
            eprintln!("resq-mcp not discovered");
            std::process::exit(1);
        }
    };

    host.start(idx).expect("start resq-mcp");
    let ri = host.running.len() - 1;

    // Wait for the tools/list answer (initialize precedes it).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while host.running[ri].tools.is_empty() {
        if std::time::Instant::now() > deadline {
            eprintln!("timeout waiting for tools/list");
            std::process::exit(1);
        }
        for ev in host.poll() {
            if let Ev::Tools(i, n) = ev {
                println!("[plugin {i}] tools/list -> {n} tools");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let tools: Vec<String> = host.running[ri]
        .tools
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    println!("tools: {tools:?}");

    // open_qvm
    host.call_tool(ri, "open_qvm", json!({ "path": qvm }))
        .expect("call open_qvm");
    let text = wait_tool_done(&mut host, ri, "open_qvm");
    println!("open_qvm -> {text}");

    // session_info
    host.call_tool(ri, "session_info", json!({}))
        .expect("call session_info");
    let text = wait_tool_done(&mut host, ri, "session_info");
    println!("session_info -> {text}");

    // decompile_function fn_0
    host.call_tool(ri, "decompile_function", json!({ "fn": "fn_0" }))
        .expect("call decompile_function");
    let text = wait_tool_done(&mut host, ri, "decompile_function");
    let head: String = text.chars().take(220).collect();
    println!("decompile_function fn_0 -> {head}...");

    // A failing call must come back as tool feedback, not a hang.
    host.call_tool(ri, "decompile_function", json!({ "fn": "no_such_fn" }))
        .expect("call bad fn");
    let text = wait_tool_done(&mut host, ri, "decompile_function");
    println!("decompile_function no_such_fn -> {text}");

    host.stop_all();
    println!("OK");
}

fn wait_tool_done(host: &mut PluginHost, ri: usize, tool: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for {tool}");
        }
        for ev in host.poll() {
            if let Ev::ToolDone(i, text) = ev {
                if i == ri {
                    return text;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
}
