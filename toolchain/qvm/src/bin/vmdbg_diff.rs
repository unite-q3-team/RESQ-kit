// External driver + differ for the q3e-fork QVM live debugger (vm_debug.c).
//
// Two different compilations of the same source (original qagame vs our
// decompiled+rebuilt qagame) do NOT share an instruction layout, so raw PC
// lockstep is meaningless across them. The invariant that MUST hold is the
// ordered syscall/effect stream: with a deterministic scenario (fixedtime, no
// user input) both modules must issue the same syscalls with the same args in
// the same order until the first real behavioural divergence.
//
// This tool:
//   * `drive <host:port> <outfile> <ms> [events|full]`
//       connect to a running engine, start a trace, wait, stop, detach.
//   * `diff <orig.trace> <rbld.trace>`
//       align the SYS records of both traces and report the first mismatch,
//       naming the enclosing function via the most recent ENTER record
//       (rebuilt side carries real symbol names from vm/qagame.map).
//
// Typical use (q3dm17 fall-through), with two engines launched on ports
// 8998 (original fs_game) and 8999 (rebuilt fs_game):
//   vmdbg_diff drive 127.0.0.1:8998 orig.trace 3000 events
//   vmdbg_diff drive 127.0.0.1:8999 rbld.trace 3000 events
//   vmdbg_diff diff orig.trace rbld.trace

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn drive(addr: &str, outfile: &str, ms: u64, mode: &str) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true).ok();

    let cmd = match mode {
        "full" => format!("trace start {}\n", outfile),
        _ => format!("trace events {}\n", outfile),
    };
    stream.write_all(cmd.as_bytes())?;
    read_until_end(&mut stream)?;

    println!("[drive] tracing {addr} -> {outfile} for {ms} ms ({mode})");
    thread::sleep(Duration::from_millis(ms));

    stream.write_all(b"trace stop\n")?;
    read_until_end(&mut stream)?;
    stream.write_all(b"detach\n")?;
    // best effort; the engine drops us
    thread::sleep(Duration::from_millis(100));
    println!("[drive] done");
    Ok(())
}

// Read from the socket until a line "END" is seen (or the peer closes).
fn read_until_end(stream: &mut TcpStream) -> std::io::Result<Vec<String>> {
    stream.set_read_timeout(Some(Duration::from_millis(4000))).ok();
    let mut out = Vec::new();
    let mut buf = [0u8; 1];
    let mut line = String::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                if buf[0] == b'\n' {
                    let t = line.trim_end_matches('\r').to_string();
                    if t == "END" {
                        break;
                    }
                    out.push(t);
                    line.clear();
                } else {
                    line.push(buf[0] as char);
                }
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

#[derive(Clone)]
struct Sys {
    call_pc: i32, // instruction index of the OP_CALL that issued this syscall
    num: i32,
    args: [i32; 6],
    // most recent ENTER pc/name before this syscall (best-effort, not popped on return)
    ctx_pc: i32,
    ctx_name: String,
}

fn load_sys(path: &str, only: &Option<Vec<i32>>) -> std::io::Result<Vec<Sys>> {
    let f = fs::File::open(path)?;
    let r = BufReader::new(f);
    let mut out = Vec::new();
    let mut ctx_pc = -1;
    let mut ctx_name = String::from("?");
    for line in r.lines() {
        let line = line?;
        if let Some(rest) = line.strip_prefix("ENTER\t") {
            let mut it = rest.split('\t');
            ctx_pc = it.next().and_then(|s| s.parse().ok()).unwrap_or(-1);
            ctx_name = it.next().unwrap_or("?").to_string();
        } else if let Some(rest) = line.strip_prefix("SYS\t") {
            let v: Vec<i32> = rest.split('\t').filter_map(|s| s.parse().ok()).collect();
            // format: call_pc num a0 a1 a2 a3 a4 a5
            if v.len() >= 8 {
                let num = v[1];
                if let Some(set) = only {
                    if !set.contains(&num) {
                        continue;
                    }
                }
                out.push(Sys {
                    call_pc: v[0],
                    num,
                    args: [v[2], v[3], v[4], v[5], v[6], v[7]],
                    ctx_pc,
                    ctx_name: ctx_name.clone(),
                });
            }
        }
    }
    Ok(out)
}

fn diff(orig: &str, rbld: &str, only: &Option<Vec<i32>>) -> std::io::Result<()> {
    let a = load_sys(orig, only)?;
    let b = load_sys(rbld, only)?;
    if let Some(set) = only {
        println!("[diff] filtering to syscalls {set:?}");
    }
    println!("[diff] {} syscalls (orig)  vs  {} syscalls (rbld)", a.len(), b.len());

    // Compare the syscall NUMBER stream only. Argument values that are VM
    // pointers legitimately differ between two compilations (different data
    // segment layouts), so only the ordered set of syscall numbers is a valid
    // cross-binary invariant. A divergence here means the two modules took a
    // different control-flow path -- exactly the behavioural bug we hunt.
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i].num != b[i].num {
            println!("\nFIRST DIVERGENCE at syscall #{i} (number stream)");
            println!(
                "  orig: num={} call_pc={} args={:?}  (enclosing ~{})",
                a[i].num, a[i].call_pc, a[i].args, a[i].ctx_name
            );
            println!(
                "  rbld: num={} call_pc={} args={:?}  (enclosing ~{})",
                b[i].num, b[i].call_pc, b[i].args, b[i].ctx_name
            );
            let lo = i.saturating_sub(8);
            println!("\n  preceding syscalls (orig | rbld):");
            for j in lo..i {
                println!(
                    "    #{j}  orig num={:<4} call_pc={:<7}  rbld num={:<4} call_pc={}",
                    a[j].num, a[j].call_pc, b[j].num, b[j].call_pc
                );
            }
            return Ok(());
        }
    }

    if a.len() != b.len() {
        println!(
            "\nStreams identical for the first {n} syscalls; lengths differ (orig={}, rbld={}).",
            a.len(),
            b.len()
        );
        let (longer, label) = if a.len() > b.len() { (&a, "orig") } else { (&b, "rbld") };
        if n < longer.len() {
            let s = &longer[n];
            println!(
                "  next only-in-{label} syscall #{n}: num={} args={:?} in {}",
                s.num, s.args, s.ctx_name
            );
        }
    } else {
        println!("\nNo divergence: syscall streams are identical.");
    }
    Ok(())
}

// Resolve instruction-index PCs to "symbol+offset" using a q3asm .map file
// (lines: "0 <hex-instruction> <name>"; negative hex values are syscalls).
fn symbolize(mapfile: &str, pcs: &[i32]) -> std::io::Result<()> {
    let text = fs::read_to_string(mapfile)?;
    let mut syms: Vec<(i32, String)> = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let seg = it.next();
        let val = it.next();
        let name = it.next();
        if let (Some("0"), Some(v), Some(n)) = (seg, val, name) {
            if let Ok(iv) = i64::from_str_radix(v, 16) {
                let iv = iv as i32;
                if iv >= 0 {
                    syms.push((iv, n.to_string()));
                }
            }
        }
    }
    syms.sort_by_key(|(v, _)| *v);
    for &pc in pcs {
        // largest symbol value <= pc
        let idx = syms.partition_point(|(v, _)| *v <= pc);
        if idx == 0 {
            println!("{pc}\t<before first symbol>");
        } else {
            let (v, n) = &syms[idx - 1];
            println!("{pc}\t{n}+{}", pc - v);
        }
    }
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  vmdbg_diff drive <host:port> <outfile> <ms> [events|full]\n  vmdbg_diff diff <orig.trace> <rbld.trace> [only=24,25]\n  vmdbg_diff sym <module.map> <pc> [pc...]"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let res = match args[1].as_str() {
        "drive" if args.len() >= 5 => {
            let ms: u64 = args[4].parse().unwrap_or(3000);
            let mode = args.get(5).map(|s| s.as_str()).unwrap_or("events");
            drive(&args[2], &args[3], ms, mode)
        }
        "diff" if args.len() >= 4 => {
            let only = args.get(4).and_then(|s| s.strip_prefix("only=")).map(|s| {
                s.split(',').filter_map(|x| x.parse::<i32>().ok()).collect::<Vec<_>>()
            });
            diff(&args[2], &args[3], &only)
        }
        "sym" if args.len() >= 4 => {
            let pcs: Vec<i32> = args[3..].iter().filter_map(|s| s.parse().ok()).collect();
            symbolize(&args[2], &pcs)
        }
        _ => usage(),
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
