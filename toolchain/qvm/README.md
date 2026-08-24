# `qvm` crate (RESQ probes)

Copy of the live decompiler. Build from this directory:

```powershell
cargo build --release --bin probe_emit --bin probe_dump_all --bin probe_sigs
```

Untyped emit is the default. Pass `--typed` only for the known overlay in `src/types.rs`. Do not enable it on a foreign QVM.

Do not copy `target/` into a zip. Standing orders: `../../AGENT.md`.
