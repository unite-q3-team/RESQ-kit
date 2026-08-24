//! Smoke test for the GUI state layer: build a tiny QVM on disk, open it
//! through `Loaded`, rename a function, save + reload the `.map`.

use std::path::PathBuf;

use resq_gui::state::Loaded;

// Minimal v1 QVM: one ENTER/LEAVE function, no data/lit.
fn fixture_bytes() -> Vec<u8> {
    let mut code = vec![3u8]; // ENTER opcode
    code.extend_from_slice(&16i32.to_le_bytes()); // ENTER 16
    code.push(4); // LEAVE
    code.extend_from_slice(&16i32.to_le_bytes());

    let mut out = Vec::new();
    let header: [i32; 8] = [
        qvm::loader::VM_MAGIC as i32,
        2,  // instructionCount
        32, // codeOffset
        code.len() as i32,
        (32 + code.len()) as i32, // dataOffset
        0,
        0,
        64, // data/lit/bss lengths
    ];
    for v in header {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&code);
    out
}

fn write_fixture(dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir");
    let path = dir.join("smoke.qvm");
    std::fs::write(&path, fixture_bytes()).expect("write");
    path
}

#[test]
fn open_rename_save_reload() {
    let dir = std::env::temp_dir().join(format!("resq_gui_{}", std::process::id()));
    let path = write_fixture(&dir);

    // fresh load: one function, unnamed
    let mut l = Loaded::open(&path).expect("open");
    assert_eq!(l.fns.len(), 1);
    assert_eq!(l.lines.len(), 2);
    assert!(l.fns[0].name.is_none());

    // decompile works on the trivial function
    let c = l.decompile(0).expect("decompile");
    assert!(!c.0.is_empty());

    // rename -> save map -> reload picks the name up
    l.rename(0, "Smoke_Main");
    let map_path = l.save_map().expect("save map");
    assert!(map_path.is_file());

    let l2 = Loaded::open(&path).expect("reopen with map");
    assert_eq!(l2.fns[0].name.as_deref(), Some("Smoke_Main"));
    assert_eq!(
        l2.decompile(0).expect("re-decompile"),
        l.decompile(0).expect("orig decompile")
    );

    // clearing a name removes it from the next save
    let mut l3 = l2;
    l3.rename(0, "");
    l3.save_map().expect("resave");
    let text = std::fs::read_to_string(&map_path).unwrap();
    assert_eq!(text.lines().count(), 1, "only the comment line remains");

    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&map_path).ok();
    std::fs::remove_dir(&dir).ok();
}
