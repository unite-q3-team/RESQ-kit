//! Probe: run one GAME_INIT command on a single module with the differential
//! harness handler, tracing every instruction (CALL/ENTER/traps stand out),
//! capped at N steps.
//!
//! Usage: probe_ginit <path.qvm> [max_steps]

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{make_handler_ctrl, TrapLog};
use qvm::{build_functions, disassemble, load, Opcode};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let path = &a[0];
    let max_steps: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(400_000);
    let q = Box::leak(Box::new(load(path).expect("load qvm")));
    let d = Box::leak(Box::new(disassemble(q).expect("disasm")));
    let (start, _end) = build_functions(d)[0];

    let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let hc = make_handler_ctrl(q.module, 0, logs.clone());

    let dump_spawns = std::env::var("QVM_DUMP_SPAWNS").is_ok();
    let mut emu = qvm::Emu::new(&d.insns, q)
        .with_syscall(hc.syscall)
        .with_watch_label("rebld");
    emu.trace = !dump_spawns;
    emu.set_max_steps(max_steps);
    hc.entity_tokens.borrow_mut().reset();

    let r = emu.call(start, &[0, 0, 0, 0]);
    println!("RESULT: {r:?} steps={}", emu.stats.steps);
    println!("trap count: {}", logs.borrow().len());

    if dump_spawns {
        dump_player_spawns(&emu.mem);
        simulate_player_on_pads(&mut emu, d);
    }
}

fn dump_player_spawns(mem: &qvm::Memory) {
    let load4 = |addr: i32| mem.load4(addr);
    let f32_at = |addr: i32| f32::from_bits(load4(addr) as u32);
    let cstr = |addr: i32| -> String {
        if addr == 0 {
            return "(null)".into();
        }
        let a = mem.masked(addr);
        let rest = &mem.data[a..];
        let n = rest
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(rest.len().min(64));
        String::from_utf8_lossy(&rest[..n]).into_owned()
    };
    let num = load4(1064020);
    println!("num_entities@1064020 = {num}");
    println!("maxclients@1064028? = {}", load4(1064028));
    let mut n_dm = 0;
    for i in 0..num.max(0) {
        let ent = 220232 + i * 824;
        let inuse = load4(ent + 520);
        if inuse == 0 {
            continue;
        }
        let cls = cstr(load4(ent + 524));
        if !cls.contains("player") {
            continue;
        }
        n_dm += 1;
        let flags = load4(ent + 536);
        println!(
            "ent[{i}] @{ent} class={cls:?} origin=({:.1},{:.1},{:.1}) flags={flags} nobots={} nohumans={}",
            f32_at(ent + 92),
            f32_at(ent + 96),
            f32_at(ent + 100),
            flags & 8192 != 0,
            flags & 16384 != 0
        );
    }
    println!("player-class entities: {n_dm}");
    println!(
        "num_clients@1064080={} sortedClients0@1064092={} clients@1064004={} gametype@219968={} gentity0.client={}",
        load4(1064080),
        load4(1064092),
        load4(1064004),
        load4(219968),
        load4(220232 + 516)
    );
}

fn f32_at(mem: &qvm::Memory, addr: i32) -> f32 {
    f32::from_bits(mem.load4(addr) as u32)
}

fn store_f32(mem: &mut qvm::Memory, addr: i32, v: f32) {
    mem.store4(addr, v.to_bits() as i32);
}

fn find_enter(insns: &[qvm::Insn], pcs: &[usize]) -> Option<usize> {
    pcs.iter().copied().find(|&pc| {
        insns
            .get(pc)
            .map(|i| i.op == Opcode::Enter)
            .unwrap_or(false)
    })
}

/// Plant client 0 at each deathmatch pad and ask both SpotWouldTelefrag and
/// SelectRandomFurthest what they see. Orig vs rebuilt at the same origin
/// tells us whether the hang is spawn-select or pmove.
fn simulate_player_on_pads(emu: &mut qvm::Emu, d: &qvm::Disassembly) {
    let telefrag_fn = find_enter(&d.insns, &[118302, 155521]);
    let select_fn = find_enter(&d.insns, &[118719, 156004]);
    println!("telefrag_fn={telefrag_fn:?} select_fn={select_fn:?}");
    let Some(telefrag_fn) = telefrag_fn else {
        println!("no SpotWouldTelefrag entry");
        return;
    };
    let Some(select_fn) = select_fn else {
        println!("no SelectRandomFurthest entry");
        return;
    };

    let pads: Vec<(i32, i32, f32, f32, f32, i32)> = {
        let mem = &emu.mem;
        let num = mem.load4(1064020);
        let mut v = Vec::new();
        for i in 0..num.max(0) {
            let ent = 220232 + i * 824;
            if mem.load4(ent + 520) == 0 {
                continue;
            }
            let cls_p = mem.load4(ent + 524);
            if cls_p == 0 {
                continue;
            }
            let a = mem.masked(cls_p);
            let rest = &mem.data[a..];
            let n = rest.iter().position(|&b| b == 0).unwrap_or(0);
            let cls = String::from_utf8_lossy(&rest[..n]);
            if cls != "info_player_deathmatch" {
                continue;
            }
            v.push((
                i,
                ent,
                f32_at(mem, ent + 92),
                f32_at(mem, ent + 96),
                f32_at(mem, ent + 100),
                mem.load4(ent + 536),
            ));
        }
        v
    };

    // 1064004 is often still 0 after a truncated GAME_INIT; entity 0's
    // .client (offset 516) is linked in G_Init to the clients array.
    let clients = {
        let c = emu.mem.load4(1064004);
        if c != 0 {
            c
        } else {
            emu.mem.load4(220232 + 516)
        }
    };
    if clients == 0 {
        println!("no level.clients pointer");
        return;
    }
    println!("using clients array @{clients}");
    let scratch = (emu.mem.data_mask as i32 + 1) - 65536 - 128;

    for (pi, _pent, px, py, pz, pflags) in &pads {
        // client 0 occupies this pad
        emu.mem.store4(220232 + 516, clients);
        emu.mem.store4(220232 + 520, 1);
        emu.mem.store4(clients + 944, 0); // not spectator
        store_f32(&mut emu.mem, clients + 20, *px);
        store_f32(&mut emu.mem, clients + 24, *py);
        store_f32(&mut emu.mem, clients + 28, *pz);
        store_f32(&mut emu.mem, 220232 + 24, *px);
        store_f32(&mut emu.mem, 220232 + 28, *py);
        store_f32(&mut emu.mem, 220232 + 32, *pz);
        emu.mem.store4(1064080, 1);
        emu.mem.store4(1064092, 0); // sortedClients[0] = entity 0

        println!("--- player on pad ent[{pi}] ({px:.0},{py:.0},{pz:.0}) flags={pflags} ---");
        for (si, sent, sx, sy, sz, sflags) in &pads {
            emu.stats.steps = 0;
            emu.set_max_steps(50_000);
            match emu.call(telefrag_fn, &[*sent]) {
                Ok(v) => {
                    println!("  telefrag ent[{si}] ({sx:.0},{sy:.0},{sz:.0}) flags={sflags} -> {v}")
                }
                Err(e) => println!("  telefrag ent[{si}] ERR {e:?}"),
            }
        }

        store_f32(&mut emu.mem, scratch, *px);
        store_f32(&mut emu.mem, scratch + 4, *py);
        store_f32(&mut emu.mem, scratch + 8, *pz);
        let mut picks = Vec::new();
        for trial in 0..16 {
            emu.stats.steps = 0;
            emu.set_max_steps(200_000);
            match emu.call(select_fn, &[scratch, scratch + 16, scratch + 32]) {
                Ok(spot) => {
                    let flags = if spot != 0 {
                        emu.mem.load4(spot + 536)
                    } else {
                        0
                    };
                    picks.push((trial, spot, flags & 8192 != 0));
                }
                Err(e) => {
                    println!("  SelectRandomFurthest[{trial}] ERR {e:?}");
                    break;
                }
            }
        }
        let n_nobots = picks.iter().filter(|p| p.2).count();
        let n_ok = picks.len() - n_nobots;
        println!(
            "  SelectRandomFurthest x{}: bot-ok={n_ok} nobots={n_nobots} first={:?}",
            picks.len(),
            picks.first().map(|p| (p.1, p.2))
        );
        if n_ok == 0 {
            println!(
                "  ALL PICKS NOBOTS: {}",
                picks
                    .iter()
                    .map(|p| p.1.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        } else {
            let seq: String = picks.iter().map(|p| if p.2 { 'N' } else { 'o' }).collect();
            println!("  pick seq: {seq}");
        }
    }

    // Live +forward hang: human in q3dm0 south corridor, start pad free.
    println!("=== corridor plant (-1148,-1308.9,24.1) ncli=1 ===");
    emu.mem.store4(220232 + 516, clients);
    emu.mem.store4(220232 + 520, 1);
    emu.mem.store4(clients + 944, 0);
    store_f32(&mut emu.mem, clients + 20, -1148.0);
    store_f32(&mut emu.mem, clients + 24, -1308.9);
    store_f32(&mut emu.mem, clients + 28, 24.1);
    store_f32(&mut emu.mem, 220232 + 24, -1148.0);
    store_f32(&mut emu.mem, 220232 + 28, -1308.9);
    store_f32(&mut emu.mem, 220232 + 32, 24.1);
    emu.mem.store4(1064080, 1);
    emu.mem.store4(1064092, 0);
    for (si, sent, sx, sy, sz, sflags) in &pads {
        emu.stats.steps = 0;
        emu.set_max_steps(50_000);
        match emu.call(telefrag_fn, &[*sent]) {
            Ok(v) => {
                println!("  telefrag ent[{si}] ({sx:.0},{sy:.0},{sz:.0}) flags={sflags} -> {v}")
            }
            Err(e) => println!("  telefrag ent[{si}] ERR {e:?}"),
        }
    }
    store_f32(&mut emu.mem, scratch, 0.0);
    store_f32(&mut emu.mem, scratch + 4, 0.0);
    store_f32(&mut emu.mem, scratch + 8, 0.0);
    let mut picks = Vec::new();
    for trial in 0..16 {
        emu.stats.steps = 0;
        emu.set_max_steps(200_000);
        match emu.call(select_fn, &[scratch, scratch + 16, scratch + 32]) {
            Ok(spot) => {
                let flags = if spot != 0 {
                    emu.mem.load4(spot + 536)
                } else {
                    0
                };
                let ox = if spot != 0 {
                    f32_at(&emu.mem, spot + 92)
                } else {
                    0.0
                };
                let oy = if spot != 0 {
                    f32_at(&emu.mem, spot + 96)
                } else {
                    0.0
                };
                picks.push((trial, spot, flags & 8192 != 0, ox, oy));
            }
            Err(e) => {
                println!("  SelectRandomFurthest[{trial}] ERR {e:?}");
                break;
            }
        }
    }
    let seq: String = picks.iter().map(|p| if p.2 { 'N' } else { 'o' }).collect();
    println!(
        "  avoid(0,0,0) x{} seq={seq} first=({:.0},{:.0}) nobots={}",
        picks.len(),
        picks.first().map(|p| p.3).unwrap_or(0.0),
        picks.first().map(|p| p.4).unwrap_or(0.0),
        picks.first().map(|p| p.2).unwrap_or(false)
    );

    println!("=== corridor + bot@0,0,0 ncli=2 sc=1,0 ===");
    let c1 = clients + 1448;
    emu.mem.store4(220232 + 824 + 516, c1);
    emu.mem.store4(220232 + 824 + 520, 1);
    emu.mem.store4(c1 + 944, 0);
    store_f32(&mut emu.mem, c1 + 20, -1148.0);
    store_f32(&mut emu.mem, c1 + 24, -1308.9);
    store_f32(&mut emu.mem, c1 + 28, 24.1);
    emu.mem.store4(clients + 944, 0);
    store_f32(&mut emu.mem, clients + 20, 0.0);
    store_f32(&mut emu.mem, clients + 24, 0.0);
    store_f32(&mut emu.mem, clients + 28, 0.0);
    emu.mem.store4(1064080, 2);
    emu.mem.store4(1064092, 1);
    emu.mem.store4(1064096, 0);
    for (si, sent, sx, sy, sz, sflags) in &pads {
        emu.stats.steps = 0;
        emu.set_max_steps(50_000);
        match emu.call(telefrag_fn, &[*sent]) {
            Ok(v) => {
                println!("  telefrag2 ent[{si}] ({sx:.0},{sy:.0},{sz:.0}) flags={sflags} -> {v}")
            }
            Err(e) => println!("  telefrag2 ent[{si}] ERR {e:?}"),
        }
    }
}
