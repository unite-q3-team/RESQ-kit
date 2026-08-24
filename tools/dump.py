#!/usr/bin/env python3
"""QVM dump oracle — strings (±4 NUL), identity fn/insn/callers, slots.

Overlay names lie. Identity `L<insn>:` is the bytecode. CONST comments are often
4 bytes into the real C string or 4 bytes before it — this prints walk-back, at,
and +4.

  python tools/dump.py --qvm work/qagame.qvm hdr
  python tools/dump.py --qvm work/qagame.qvm str 45487 40650
  python tools/dump.py --qvm work/qagame.qvm find FREEFLOAT
  python tools/dump.py --qvm work/qagame.qvm --c work/qagame/qagame.c insn 107760
  python tools/dump.py --qvm work/qagame.qvm --c work/qagame/qagame.c xref FREEFLOAT
  python tools/dump.py --qvm work/qagame.qvm --c work/qagame/qagame.c cvar amf_debug
  python tools/dump.py --qvm work/qagame.qvm --c work/qagame/qagame.c cvars
  python tools/dump.py --qvm work/qagame.qvm --c work/qagame/qagame.c calls G_InitGame
  python tools/dump.py --qvm work/qagame.qvm --c work/qagame/qagame.c slot 668

IEEE-754 / TFL / CONTENTS calculator (no .qvm) — do not paste i32 float bits into C:

  python tools/qvmbits.py --fbits -1002487808 1134329856 1103101952
  python tools/qvmbits.py --float -765 313 24
  python tools/qvmbits.py --tfl 1836958
  python tools/qvmbits.py --mask 100663297
  python tools/dump.py --qvm work/ui.qvm color 5148
"""
from __future__ import print_function

import argparse
import bisect
import math
import os
import re
import struct
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Filled by main() from --qvm / --c / --struct / --names (siblings of the QVM if omitted).
QVM_PATH = None
IDENT_PATH = None
STRUCT_PATH = None
NAMES_PATH = None
SIGS_PATH = None
MOD_LABEL = "qvm"


_out_lines = None


def out(s=""):
    if _out_lines is not None:
        _out_lines.append(s)
        return
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.stdout.write(s + "\n")


def captured(fn, *args, **kwargs):
    """Run a cmd_* function and return its printed text (CLI and optional wrappers)."""
    global _out_lines
    _out_lines = []
    try:
        fn(*args, **kwargs)
        return "\n".join(_out_lines)
    finally:
        _out_lines = None


def data_mask(dl, ll, bl):
    total = dl + ll + bl
    mask = 1
    while total > mask:
        mask <<= 1
    return mask - 1


def cmd_hdr(mod):
    path, data, hdr = load_qvm(mod)
    magic, ic, co, clen, doff, dl, ll, bl = hdr
    total = dl + ll + bl
    mask = data_mask(dl, ll, bl)
    out("== %s QVM header ==" % MOD_LABEL)
    out("  path          %s" % path)
    out("  magic         0x%08X" % magic)
    out("  instructions  %d" % ic)
    out("  codeLength    %d" % clen)
    out("  dataLength    %d  initialized .data (cvars, pointer tables)" % dl)
    out("  litLength     %d  read-only strings (after data in the file)" % ll)
    out("  bssLength     %d  zero-filled; NOT stored in the .qvm file" % bl)
    out("  data+lit+bss  %d" % total)
    out("  dataMask+1    %d  VM data segment (next power of two)" % (mask + 1))
    out("  qvm_mem_words %d  emit blob words = (4+data+lit+bss+3)/4" % ((4 + total + 3) // 4))
    out("  file data+lit %d  (dump.py string/table offsets live here)" % len(data))
    out("  BSS VM range  %d .. %d  (qvm_mem + N-4 for CONST N)" % (dl + ll, total))


_qvm_blob_cache = {}


def load_qvm_blob():
    path = QVM_PATH
    if not path or not os.path.isfile(path):
        raise SystemExit("need --qvm PATH (readable .qvm)")
    mtime = os.path.getmtime(path)
    hit = _qvm_blob_cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    blob = open(path, "rb").read()
    hdr = struct.unpack_from("<8I", blob)
    rec = (path, blob, hdr)
    _qvm_blob_cache[path] = (mtime, rec)
    return rec


def load_qvm(mod=None):
    path, blob, hdr = load_qvm_blob()
    doff = hdr[4]
    data = blob[doff:]
    return path, data, hdr


# QVM opcode numbers (ioq3 vm_local.h). Lengths: +i32, ARG +1 byte, else 1.
OP_ENTER, OP_LEAVE, OP_CALL = 3, 4, 5
OP_PUSH, OP_POP = 6, 7
OP_CONST, OP_LOCAL, OP_JUMP = 8, 9, 10
OP_EQ, OP_GEF = 11, 26
OP_LOAD1, OP_LOAD2, OP_LOAD4 = 27, 28, 29
OP_STORE1, OP_STORE2, OP_STORE4 = 30, 31, 32
OP_ARG, OP_BLOCK_COPY = 33, 34
OP_ADD, OP_SUB = 38, 39
OP_I32 = set([3, 4, 8, 9, 34]) | set(range(OP_EQ, OP_GEF + 1))
OP_BRANCH = set(range(OP_EQ, OP_GEF + 1))


def decode_qvm_insns(blob, hdr):
    """List of (op, operand_or_None) indexed by insn. operand is signed i32 or ARG byte."""
    _magic, ic, co, clen, _doff, _dl, _ll, _bl = hdr
    code = blob[co : co + clen]
    insns = []
    p = 0
    n = len(code)
    for _ in range(ic):
        if p >= n:
            break
        op = code[p]
        p += 1
        operand = None
        if op in OP_I32:
            if p + 4 > n:
                break
            (operand,) = struct.unpack_from("<i", code, p)
            p += 4
        elif op == OP_ARG:
            if p >= n:
                break
            operand = code[p]
            p += 1
        insns.append((op, operand))
    return insns


def vm_kind_from_path(path):
    stem = os.path.splitext(os.path.basename(path or ""))[0].lower()
    if stem.startswith("cgame"):
        return "cgame"
    if stem.startswith("ui"):
        return "ui"
    return "game"


def trap_cvar_consts(kind):
    """CONST immediates for trap_Cvar_Register / Update.

    ioq3: CONST -N; CALL maps to syscall index -1-(-N)=N-1. Register is
    game/cgame trap 3 → CONST -4; Update trap 4 → CONST -5. UI traps 50/51
    → CONST -51/-52.
    """
    if kind == "ui":
        return -51, -52
    return -4, -5


def c_str(data, off):
    if off < 0 or off >= len(data):
        return None
    end = data.find(bytes([0]), off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("latin1", "replace")


def walk_back(data, off):
    if off < 0 or off >= len(data):
        return None, None
    prev = data.rfind(bytes([0]), 0, off)
    start = prev + 1
    return start, c_str(data, start)


def show_str(data, off):
    wb_off, wb = walk_back(data, off)
    at = c_str(data, off)
    p4_off, p4 = walk_back(data, off + 4) if off + 4 < len(data) else (None, None)
    out("CONST %d" % off)
    if wb is not None:
        out("  walk-back @%d %r" % (wb_off, wb))
    if at is not None and (wb_off != off):
        out("  at        @%d %r" % (off, at))
    if p4 is not None and p4_off not in (wb_off, off):
        out("  +4        @%d %r" % (p4_off, p4))
    elif p4 is not None and at != p4 and p4_off == off + 4:
        out("  +4        @%d %r" % (off + 4, c_str(data, off + 4)))


def find_strings(data, needle):
    raw = needle.encode("latin1", "replace")
    hits = []
    i = 0
    while True:
        j = data.find(raw, i)
        if j < 0:
            break
        start, s = walk_back(data, j)
        hits.append((start, s, j - start))
        i = j + 1
    # unique by start
    seen = set()
    uniq = []
    for h in hits:
        if h[0] in seen:
            continue
        seen.add(h[0])
        uniq.append(h)
    return uniq


def dump_files(mod=None):
    return IDENT_PATH, STRUCT_PATH, NAMES_PATH, SIGS_PATH


def read_text(path):
    if not os.path.isfile(path):
        return None
    return open(path, "r", encoding="latin1", errors="replace").read()


def parse_names(path):
    rows = []
    text = read_text(path)
    if not text:
        return rows
    for line in text.splitlines():
        m = re.match(r"fn\[(\d+)\]\s+(\S+)", line)
        if m:
            rows.append((int(m.group(1)), m.group(2)))
    return rows


def parse_struct_fns(text):
    rows = []
    if not text:
        return rows
    for m in re.finditer(
        r"fn\[(\d+)\] insns (\d+)\.\.(\d+) frame (\d+) = ([^\s=]+)",
        text,
    ):
        rows.append(
            {
                "n": int(m.group(1)),
                "lo": int(m.group(2)),
                "hi": int(m.group(3)),
                "frame": int(m.group(4)),
                "name": m.group(5),
                "pos": m.start(),
            }
        )
    return rows


_text_cache = {}


def _cached_text(text):
    key = id(text)
    c = _text_cache.get(key)
    if c is not None:
        return c
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)
    fns = []
    for m in re.finditer(r"^int ([A-Za-z_][A-Za-z0-9_]*)\(", text, re.M):
        fns.append((m.start(), m.group(1)))
    c = (line_starts, fns)
    _text_cache[key] = c
    return c


def ident_defs(text, name):
    """Column-0 `int Name(` definitions with first L-insn after them."""
    hits = []
    pat = re.compile(r"^int %s\(" % re.escape(name), re.M)
    for m in pat.finditer(text):
        line = line_of(text, m.start())
        rest = text[m.start() : m.start() + 8000]
        lm = re.search(r"^L(\d+):", rest, re.M)
        insn = int(lm.group(1)) if lm else None
        hits.append((line, insn))
    return hits


def line_of(text, pos):
    line_starts, _ = _cached_text(text)
    return bisect.bisect_right(line_starts, pos)


def nearest_insn(text, pos):
    chunk = text[max(0, pos - 2500) : pos]
    labels = re.findall(r"^L(\d+):", chunk, re.M)
    return int(labels[-1]) if labels else None


def enclosing_ident_fn(text, pos):
    _, fns = _cached_text(text)
    lo, hi = 0, len(fns)
    while lo < hi:
        mid = (lo + hi) // 2
        if fns[mid][0] <= pos:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None, None
    p, name = fns[lo - 1]
    return name, line_of(text, p)


def cmd_str(mod, offs):
    path, data, hdr = load_qvm(mod)
    out("%s data=%d lit=%d  %s" % (MOD_LABEL, hdr[5], hdr[6], path))
    for off in offs:
        show_str(data, off)
        out()


def cmd_find(mod, needle):
    path, data, hdr = load_qvm(mod)
    hits = find_strings(data, needle)
    out("%s find %r  (%d strings)  %s" % (MOD_LABEL, needle, len(hits), path))
    for start, s, rel in hits[:80]:
        mark = "  +%d" % rel if rel else ""
        out("  @%d%s %r" % (start, mark, s))
    if len(hits) > 80:
        out("  ... %d more" % (len(hits) - 80))


def cmd_xref(mod, needle, limit=20):
    ident_p = dump_files(mod)[0]
    ident = read_text(ident_p)
    _, data, hdr = load_qvm(mod)
    hits = find_strings(data, needle)
    out("== QVM strings matching %r ==" % needle)
    if not hits:
        out("  (none)")
        return
    if not ident:
        out("  missing identity dump")
        return
    n = 0
    for start, s, rel in hits[:15]:
        out("  @%d %r" % (start, s))
        offs = set([start])
        for delta in range(-4, 5):
            offs.add(start + delta)
        for off in sorted(offs):
            if off < 0:
                continue
            pat = re.compile(r"qvm_mem \+ %d\)" % off)
            for m in pat.finditer(ident):
                ln = line_of(ident, m.start())
                insn = nearest_insn(ident, m.start())
                enc, _ = enclosing_ident_fn(ident, m.start())
                line_start = ident.rfind("\n", 0, m.start()) + 1
                line = ident[line_start : ident.find("\n", m.start())]
                out("    CONST %d  %s.c:%d  L%s  in %s" % (off, mod, ln, insn or "?", enc))
                out("      %s" % line.strip()[:150])
                n += 1
                if n >= limit:
                    out("  ... truncated")
                    return
    if n == 0:
        out("  (no qvm_mem + <offset> hits in identity; try nearby CONST ±4)")


def cmd_fn(mod, name):
    ident_p, struct_p, names_p, sigs_p = dump_files(mod)
    ident = read_text(ident_p)
    structc = read_text(struct_p)
    names = parse_names(names_p)
    out("== overlay .names (often a lie) ==")
    nmatch = [r for r in names if name.lower() in r[1].lower()]
    if not nmatch:
        out("  (none)")
    for n, nm in nmatch[:20]:
        out("  fn[%d] %s" % (n, nm))
    out("== struct.c insn ranges (overlay title) ==")
    sfns = parse_struct_fns(structc or "")
    sm = [r for r in sfns if name.lower() in r["name"].lower()]
    if not sm:
        out("  (none)")
    for r in sm[:20]:
        out(
            "  fn[%d] insns %d..%d frame %d = %s"
            % (r["n"], r["lo"], r["hi"], r["frame"], r["name"])
        )
        if ident:
            m = re.search(r"^L%d:" % r["lo"], ident, re.M)
            if m:
                enc, fline = enclosing_ident_fn(ident, m.start())
                out("    identity at L%d: int %s(  %s.c:%s" % (r["lo"], enc, mod, fline))
    out("== identity dump definitions (bytecode) ==")
    if not ident:
        out("  missing %s" % ident_p)
        return
    defs = ident_defs(ident, name)
    if not defs:
        # substring: list int Foo( whose name contains
        loose = []
        for m in re.finditer(r"^int ([A-Za-z_][A-Za-z0-9_]*)\(", ident, re.M):
            if name.lower() in m.group(1).lower():
                line = line_of(ident, m.start())
                rest = ident[m.start() : m.start() + 4000]
                lm = re.search(r"^L(\d+):", rest, re.M)
                insn = int(lm.group(1)) if lm else None
                loose.append((m.group(1), line, insn))
        if not loose:
            out("  (none)")
        for nm, line, insn in loose[:30]:
            out("  %s.c:%d  L%s  int %s(" % (mod, line, insn if insn else "?", nm))
    else:
        for line, insn in defs:
            out("  %s.c:%d  L%s  int %s(" % (mod, line, insn if insn else "?", name))
            if insn is not None:
                for r in sfns:
                    if r["lo"] <= insn < r["hi"]:
                        out(
                            "    struct overlay for this insn: fn[%d] %s (%d..%d)"
                            % (r["n"], r["name"], r["lo"], r["hi"])
                        )
    out("identity wins when overlay title disagrees.")


def slice_ident(ident, pos, before=25, after=55):
    line = line_of(ident, pos)
    lines = ident.splitlines()
    lo = max(0, line - 1 - before)
    hi = min(len(lines), line - 1 + after)
    for i in range(lo, hi):
        out("%6d %s" % (i + 1, lines[i]))


def cmd_insn(mod, insn, context=40):
    ident_p, struct_p, names_p, sigs_p = dump_files(mod)
    ident = read_text(ident_p)
    structc = read_text(struct_p)
    out("== struct.c function covering insn %d ==" % insn)
    sfns = parse_struct_fns(structc or "")
    hit = [r for r in sfns if r["lo"] <= insn < r["hi"]]
    if not hit:
        out("  (none)")
    for r in hit:
        out(
            "  fn[%d] insns %d..%d frame %d = %s"
            % (r["n"], r["lo"], r["hi"], r["frame"], r["name"])
        )
    out("== identity %s.c L%d ==" % (mod, insn))
    if not ident:
        out("  missing")
        return
    m = re.search(r"^L%d:" % insn, ident, re.M)
    if not m:
        # nearest label
        labels = [int(x) for x in re.findall(r"^L(\d+):", ident, re.M)]
        below = [x for x in labels if x <= insn]
        above = [x for x in labels if x >= insn]
        near = (below[-1] if below else None, above[0] if above else None)
        out("  no L%d:  nearest %s" % (insn, near))
        if below:
            m = re.search(r"^L%d:" % below[-1], ident, re.M)
    if not m:
        return
    name, fline = enclosing_ident_fn(ident, m.start())
    out("  in int %s(  @ line %s" % (name, fline))
    slice_ident(ident, m.start(), before=8, after=context)


def cmd_calls(mod, name, limit=25):
    ident_p = dump_files(mod)[0]
    ident = read_text(ident_p)
    if not ident:
        out("missing %s" % ident_p)
        return
    pat = re.compile(r"\b%s\s*\(" % re.escape(name))
    n = 0
    out("== identity calls %s( ==" % name)
    for m in pat.finditer(ident):
        line_start = ident.rfind("\n", 0, m.start()) + 1
        line = ident[line_start : ident.find("\n", m.start())]
        if line.startswith("int %s(" % name):
            continue
        if line.startswith("int %s(" % name):
            continue
        ln = line_of(ident, m.start())
        insn = nearest_insn(ident, m.start())
        enc, _ = enclosing_ident_fn(ident, m.start())
        out("  %s.c:%d  L%s  in %s  %s" % (mod, ln, insn or "?", enc, line.strip()[:140]))
        n += 1
        if n >= limit:
            out("  ... truncated at %d" % limit)
            break
    if n == 0:
        out("  (none)")


def cmd_slot(mod, off, limit=30):
    ident_p = dump_files(mod)[0]
    ident = read_text(ident_p)
    if not ident:
        out("missing")
        return
    pats = [
        r"\+ %d\)" % off,
        r"\+%d\)" % off,
        r"\+ %d," % off,
        r"\+%d," % off,
        r"\+ %d\]" % off,
        r"\+%d\]" % off,
    ]
    rx = re.compile("|".join(pats))
    out("== identity %s +%d ==" % (mod, off))
    n = 0
    seen = set()
    for m in rx.finditer(ident):
        ln = line_of(ident, m.start())
        if ln in seen:
            continue
        seen.add(ln)
        line_start = ident.rfind("\n", 0, m.start()) + 1
        line = ident[line_start : ident.find("\n", m.start())]
        insn = nearest_insn(ident, m.start())
        enc, _ = enclosing_ident_fn(ident, m.start())
        out("  %s.c:%d  L%s  in %s" % (mod, ln, insn or "?", enc))
        out("    %s" % line.strip()[:160])
        n += 1
        if n >= limit:
            out("  ... truncated at %d" % limit)
            break
    if n == 0:
        out("  (none)")


def cmd_addcmd(mod):
    ident_p = dump_files(mod)[0]
    ident = read_text(ident_p)
    _, data, _ = load_qvm(mod)
    if not ident:
        out("missing")
        return
    out("== trap_AddCommand in %s.c (resolved via QVM ±4) ==" % mod)
    n = 0
    for m in re.finditer(
        r"trap_AddCommand\((?:\(int\))?\(qvm_mem \+ (\d+)\)\)|trap_AddCommand\(\*\(int\*\)\(\(v\d+ << 3\) \+ (\d+)\)\)",
        ident,
    ):
        off = m.group(1) or m.group(2)
        ln = line_of(ident, m.start())
        if m.group(1):
            o = int(m.group(1))
            start, s = walk_back(data, o)
            out("  %s.c:%d  CONST %d -> @%d %r" % (mod, ln, o, start, s))
        else:
            out("  %s.c:%d  table %s (8-byte name,fn)" % (mod, ln, m.group(2)))
        n += 1
        if n >= 200:
            out("  ... truncated")
            break
    if n == 0:
        out("  (none parsed)")


def cmd_ptrs(mod, target, limit=40):
    _, data, hdr = load_qvm(mod)
    out("== %s dwords pointing at %d (and ±4, +256) ==" % (MOD_LABEL, target))
    want = set([target, target - 4, target + 4, target + 256, target + 252, target + 260])
    n = 0
    for i in range(0, (len(data) // 4) * 4, 4):
        (v,) = struct.unpack_from("<I", data, i)
        if v not in want:
            continue
        start, s = walk_back(data, v)
        out("  table@%d -> %d (%+d) %r" % (i, v, v - target, s))
        n += 1
        if n >= limit:
            out("  ... truncated")
            return
    if n == 0:
        out("  (none)")


def read_f32(data, off):
    if off < 0 or off + 4 > len(data):
        return None
    (v,) = struct.unpack_from("<f", data, off)
    return v


def fmt_f(v):
    if v is None or (isinstance(v, float) and not math.isfinite(v)):
        return "nan"
    if abs(v) >= 1e6 or (abs(v) > 0 and abs(v) < 1e-4):
        return "%.4g" % v
    s = "%.4f" % v
    return s.rstrip("0").rstrip(".") if "." in s else s


def read_vec4(data, off):
    if off < 0 or off + 16 > len(data):
        return None
    return tuple(read_f32(data, off + i * 4) for i in range(4))


def looks_like_color(rgba):
    if not rgba or any(c is None or not math.isfinite(c) for c in rgba):
        return False
    return all(-0.05 <= c <= 1.05 for c in rgba)


# Stock q3_ui / q_shared literals. Do not snap vec4 pointers to 16 bytes.
_COLOR_NAMES = (
    ("black", (0.0, 0.0, 0.0, 1.0)),
    ("white", (1.0, 1.0, 1.0, 1.0)),
    ("yellow", (1.0, 1.0, 0.0, 1.0)),
    ("blue", (0.0, 0.0, 1.0, 1.0)),
    ("lightOrange", (1.0, 0.68, 0.0, 1.0)),
    ("orange", (1.0, 0.43, 0.0, 1.0)),
    ("red", (1.0, 0.0, 0.0, 1.0)),
    ("dim", (0.0, 0.0, 0.0, 0.25)),
    ("colorDim75", (0.0, 0.0, 0.0, 0.75)),
)


def guess_color_name(rgba, eps=0.02):
    if not looks_like_color(rgba):
        return None
    best = None
    best_d = eps
    for name, ref in _COLOR_NAMES:
        d = max(abs(rgba[i] - ref[i]) for i in range(4))
        if d <= best_d:
            best_d = d
            best = name
    return best


def fmt_rgba(rgba):
    if not rgba:
        return "(unreadable)"
    return "(%s, %s, %s, %s)" % tuple(fmt_f(c) for c in rgba)


def cmd_color(mod, offs):
    """vec4 windows at CONST-4 / CONST / CONST+4. Color pointers are often mid-vector."""
    _, data, _ = load_qvm(mod)
    out("%s color windows  (vec4 pointer: do not snap to 16-byte; CONST often +/-4)" % MOD_LABEL)
    for off in offs:
        out("CONST %d  %%4=%d  %%16=%d%s" % (
            off,
            off % 4,
            off % 16,
            "  UNALIGNED — lcc does not put vec4 on 16 bytes" if (off % 16) else "",
        ))
        windows = ((-4, off - 4), (0, off), (4, off + 4))
        scored = []
        for delta, addr in windows:
            rgba = read_vec4(data, addr)
            name = guess_color_name(rgba)
            ok = looks_like_color(rgba)
            alpha_bad = ok and rgba[3] < 0.05
            tag = []
            if name:
                tag.append("~%s" % name)
            elif ok:
                tag.append("color-like")
            else:
                tag.append("not-a-color")
            if alpha_bad:
                tag.append("alpha~0 (invisible / mid-vector)")
            out("  %s @%d  rgba %s  %s" % (
                "%+d" % delta if delta else " 0",
                addr,
                fmt_rgba(rgba),
                ", ".join(tag),
            ))
            score = 0
            if ok:
                score += 2
            if name:
                score += 3
            if alpha_bad:
                score -= 4
            # Identity comments are CONST-4; on a tie prefer the +4 window.
            if delta == 4:
                score += 1
            scored.append((score, delta, addr, name))
        best = max(scored, key=lambda t: t[0])
        if best[0] >= 2 and best[1] != 0:
            out("  likely pointer is %+d -> @%d%s" % (
                best[1],
                best[2],
                (" ~%s" % best[3]) if best[3] else "",
            ))
        lo = max(0, (off - 64) & ~3)
        hi = min(len(data) - 16, off + 48)
        shown = 0
        out("  nearby color-like vec4s:")
        for addr in range(lo, hi + 1, 4):
            rgba = read_vec4(data, addr)
            name = guess_color_name(rgba)
            if not looks_like_color(rgba):
                continue
            if not name:
                continue
            mark = "  <-- CONST" if addr == off else ""
            out("    @%d  %s  %s%s" % (
                addr,
                fmt_rgba(rgba),
                ("~%s" % name) if name else "color-like",
                mark,
            ))
            shown += 1
            if shown >= 12:
                break
        if shown == 0:
            out("    (none)")
        out()


def cmd_table(mod, off, count, width):
    _, data, _ = load_qvm(mod)
    out("== %s table @%d count=%d width=%d ==" % (MOD_LABEL, off, count, width))
    if width == 4:
        for i in range(count):
            p = off + i * 4
            if p + 4 > len(data):
                break
            (v,) = struct.unpack_from("<I", data, p)
            start, s = walk_back(data, v) if v < len(data) else (None, None)
            fv = read_f32(data, p)
            if s is not None and 0 < v < len(data) and data[v : v + 1] != b"\x00":
                out("  [%d] @%d u32=%d  str@%d %r" % (i, p, v, start, s))
            else:
                (sv,) = struct.unpack_from("<i", data, p)
                extra = ""
                rgba = read_vec4(data, p)
                name = guess_color_name(rgba) if rgba and rgba[3] >= 0.2 else None
                if name:
                    extra = "  vec4~%s" % name
                out("  [%d] @%d u32=%d i32=%d f=%s%s" % (i, p, v, sv, fmt_f(fv), extra))
    else:
        chunk = data[off : off + count * width]
        out(chunk.hex())


# vmCvar_t gameplay fields. Compact QVMs test +8 (.value bits as int != 0) / +12.
# ioq3 layout is string[256] at +0, so .value/.integer sit at +260/+264.
# vmCvar_t is 272 bytes; +280 is the *next* cvar's +8, not this .integer.
VMCVAR_LOAD_OFFS = (4, 8, 12, 256, 260, 264)
VMCVAR_SIZE = 272
CVAR_STRIDES = (16, 20, 24, 28, 32)
CVAR_FLAG_NAMES = (
    (1, "ARCHIVE"),
    (2, "USERINFO"),
    (4, "SERVERINFO"),
    (8, "SYSTEMINFO"),
    (16, "INIT"),
    (32, "LATCH"),
    (64, "ROM"),
    (128, "USER_CREATED"),
    (256, "TEMP"),
    (512, "CHEAT"),
    (1024, "NORESTART"),
)


def u32_at(data, off):
    (v,) = struct.unpack_from("<I", data, off)
    return v


def i32_at(data, off):
    (v,) = struct.unpack_from("<i", data, off)
    return v


def is_cvarish_name(s):
    if not s or len(s) < 2 or len(s) > 64:
        return False
    return re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s) is not None


def _string_at_start(data, cand):
    if cand < 0 or cand >= len(data):
        return None
    if cand > 0 and data[cand - 1] != 0:
        return None
    return c_str(data, cand)


def resolve_name_ptr(data, v):
    """Table name dword -> C string. Some mods store the plain find offset, others find+0x100."""
    for cand in (v, v - 4, v + 4, v - 256, v - 252, v - 260):
        s = _string_at_start(data, cand)
        if s and is_cvarish_name(s):
            return cand, s
    return None, None


def resolve_default_ptr(data, v):
    for cand in (v, v - 4, v + 4, v - 256, v - 252, v - 260):
        s = _string_at_start(data, cand)
        if s is not None and len(s) < 128:
            return cand, s
    return None, None


def format_cvar_flags(flags):
    parts = []
    rest = flags
    for bit, name in CVAR_FLAG_NAMES:
        if flags & bit:
            parts.append(name)
            rest &= ~bit
    if rest:
        parts.append("0x%X" % rest)
    return "|".join(parts) if parts else "0"


def valid_cvar_row(data, off):
    if off < 0 or off + 16 > len(data):
        return False
    _, name = resolve_name_ptr(data, u32_at(data, off + 4))
    if not name:
        return False
    flags = i32_at(data, off + 12)
    if flags < 0 or flags > 0x7FFFF:
        return False
    return True


def parse_cvar_row(data, off, stride):
    vm = u32_at(data, off)
    np = u32_at(data, off + 4)
    dp = u32_at(data, off + 8)
    flags = i32_at(data, off + 12)
    ns, name = resolve_name_ptr(data, np)
    ds, default = resolve_default_ptr(data, dp)
    return {
        "off": off,
        "stride": stride,
        "vm": vm,
        "name": name,
        "name_off": ns,
        "name_dword": np,
        "default": default if default is not None else "",
        "default_off": ds,
        "flags": flags,
    }


def expand_cvar_table(data, name_field_off):
    """Walk backward/forward from a name-pointer dword. Return (rows, stride)."""
    best = []
    best_stride = 28
    for stride in CVAR_STRIDES:
        start = name_field_off - 4
        if not valid_cvar_row(data, start):
            continue
        while start - stride >= 0 and valid_cvar_row(data, start - stride):
            start -= stride
        rows = []
        off = start
        while valid_cvar_row(data, off):
            rows.append(parse_cvar_row(data, off, stride))
            off += stride
            if off + 16 > len(data):
                break
        if len(rows) > len(best):
            best = rows
            best_stride = stride
    return best, best_stride


def ptr_want_set(off):
    want = set()
    for base in (off, off + 256):
        for d in range(-4, 5):
            want.add(base + d)
    return want


def find_name_dwords(data, str_off):
    want = ptr_want_set(str_off)
    hits = []
    for i in range(0, (len(data) // 4) * 4, 4):
        if u32_at(data, i) in want:
            hits.append(i)
    return hits


def find_cvar_tables(data, needle=None):
    """Discover cvarTable runs. If needle is set, only tables containing that name."""
    str_offs = []
    if needle:
        hits = find_strings(data, needle)
        exact = [h for h in hits if h[1] == needle]
        for start, s, _rel in exact or hits:
            str_offs.append(start)
    else:
        str_offs = None

    seen = set()
    tables = []
    scan_fields = []
    if str_offs is not None:
        for so in str_offs:
            scan_fields.extend(find_name_dwords(data, so))
    else:
        for i in range(0, (len(data) // 4) * 4, 4):
            _, name = resolve_name_ptr(data, u32_at(data, i))
            if name:
                scan_fields.append(i)

    for nf in scan_fields:
        rows, stride = expand_cvar_table(data, nf)
        if not rows:
            if valid_cvar_row(data, nf - 4):
                rows = [parse_cvar_row(data, nf - 4, 28)]
                stride = 28
            else:
                continue
        start = rows[0]["off"]
        key = (start, stride, len(rows))
        if key in seen:
            continue
        if needle:
            names = [r["name"].lower() for r in rows if r.get("name")]
            if needle.lower() not in names:
                continue
        seen.add(key)
        tables.append((start, stride, rows))
    tables.sort(key=lambda t: (-len(t[2]), t[0]))
    return tables


def merge_ranges(rs):
    if not rs:
        return []
    rs = sorted(rs)
    out = [[rs[0][0], rs[0][1]]]
    for a, b in rs[1:]:
        if a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def in_ranges(insn, ranges):
    if insn is None or not ranges:
        return False
    i = bisect.bisect_right(ranges, (insn, 10 ** 9)) - 1
    if i < 0:
        return False
    lo, hi = ranges[i]
    return lo <= insn <= hi


def func_enter_ranges(insns):
    starts = [i for i, (op, _) in enumerate(insns) if op == OP_ENTER]
    out = []
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(insns)
        out.append((s, e))
    return out


def admin_cvar_ranges(insns, trap_reg, trap_upd):
    """Insn ranges of table-walk loops that CALL trap_Cvar_Register|Update.

    Identity overlay names like RegisterCvars are *not* used. A load after the
    loop in the same function still counts. A loop that merely *contains* one
    Update (BotCheckConsoleMessages) is not a table walk — require loc += stride.
    """
    traps = set()
    for i, (op, _) in enumerate(insns):
        if op != OP_CALL or i == 0:
            continue
        pop, pimm = insns[i - 1]
        if pop == OP_CONST and pimm in (trap_reg, trap_upd):
            traps.add(i)
            traps.add(i - 1)
    if not traps:
        return []
    strides = set(CVAR_STRIDES)

    def has_stride_add(lo, hi):
        for i in range(lo, hi + 1):
            op, _imm = insns[i]
            if op != OP_ADD or i == 0:
                continue
            prev = insns[i - 1]
            if prev[0] == OP_CONST and prev[1] in strides:
                return True
        return False

    ranges = []
    for lo, hi in func_enter_ranges(insns):
        here = [t for t in traps if lo <= t < hi]
        if not here:
            continue
        for i in range(lo, hi):
            op, arg = insns[i]
            if op not in OP_BRANCH or arg is None:
                continue
            t = arg
            if lo <= t <= i and any(t <= x <= i for x in here) and has_stride_add(t, i):
                ranges.append((t, i))
        # Unrolled / one-shot Register/Update: ARG window before the CALL only.
        for t in here:
            ranges.append((max(lo, t - 16), t))
    return merge_ranges(ranges)


def classify_ident_line(text, addr):
    s = text or ""
    if re.search(
        r"\*\(\s*(?:int|float|unsigned\s+int|blob_\d+)\s*\*\s*\)\s*"
        r"\(\s*(?:(?:int)\s*\(\s*)?(?:qvm_mem\s*\+\s*)?%d\s*\)\s*=" % addr,
        s,
    ):
        return "write"
    if re.search(
        r"\*\(\s*(?:int|float|unsigned\s+int|blob_\d+)\s*\*\s*\)\s*"
        r"\(\s*(?:(?:int)\s*\(\s*)?(?:qvm_mem\s*\+\s*)?%d\b" % addr,
        s,
    ):
        return "read"
    return "address-only"


def ident_code_hits(ident, addr, index=None, admin_ranges=None):
    """qvm_mem / *(int*)(addr) hits that look like code, not the data blob.

    Does not skip a whole function because overlay called it Register*.
    Trap lines and Register/Update *insn ranges* are filtered.
    """
    if index is not None:
        hits = list(index.get(addr, []))
    elif not ident or addr is None:
        hits = []
    else:
        pats = [
            r"qvm_mem\s*\+\s*%d\b" % addr,
            r"\*\(\s*(?:int|float|unsigned\s+int)\s*\*\s*\)\s*\(\s*%d\s*\)" % addr,
        ]
        rx = re.compile("|".join(pats))
        hits = []
        seen = set()
        for m in rx.finditer(ident):
            ln = line_of(ident, m.start())
            if ln in seen:
                continue
            line_start = ident.rfind("\n", 0, m.start()) + 1
            line = ident[line_start : ident.find("\n", m.start())]
            if "(void*)0x" in line or "(void *)0x" in line:
                continue
            if re.search(r"trap_Cvar_(Register|Update)\s*\(", line):
                continue
            seen.add(ln)
            hits.append(
                {
                    "line": ln,
                    "insn": nearest_insn(ident, m.start()),
                    "enc": enclosing_ident_fn(ident, m.start())[0],
                    "text": line.strip(),
                    "kind": classify_ident_line(line, addr),
                    "how": "identity CONST",
                }
            )
    out_hits = []
    for h in hits:
        if admin_ranges and in_ranges(h.get("insn"), admin_ranges):
            continue
        if "kind" not in h:
            h = dict(h)
            h["kind"] = classify_ident_line(h.get("text") or "", addr)
            h.setdefault("how", "identity CONST")
        out_hits.append(h)
    return out_hits


def build_ident_load_index(ident):
    """addr -> hits, one pass. Used by `cvars` so we do not re-scan the dump."""
    index = {}
    if not ident:
        return index
    rx = re.compile(
        r"qvm_mem\s*\+\s*(\d+)\b"
        r"|\*\(\s*(?:int|float|unsigned\s+int)\s*\*\s*\)\s*\(\s*(\d+)\s*\)"
    )
    fn_rx = re.compile(r"^int ([A-Za-z_][A-Za-z0-9_]*)\(")
    lab_rx = re.compile(r"^L(\d+):")
    enc = None
    last_insn = None
    seen = set()
    for ln, line in enumerate(ident.splitlines(), 1):
        fm = fn_rx.match(line)
        if fm:
            enc = fm.group(1)
            last_insn = None
        lm = lab_rx.match(line)
        if lm:
            last_insn = int(lm.group(1))
        if "(void*)0x" in line or "(void *)0x" in line:
            continue
        if re.search(r"trap_Cvar_(Register|Update)\s*\(", line):
            continue
        for m in rx.finditer(line):
            addr = int(m.group(1) or m.group(2))
            key = (addr, ln)
            if key in seen:
                continue
            seen.add(key)
            index.setdefault(addr, []).append(
                {
                    "line": ln,
                    "insn": last_insn,
                    "enc": enc,
                    "text": line.strip(),
                }
            )
    return index


_ident_label_cache = {}


def ident_labels(ident):
    key = id(ident)
    hit = _ident_label_cache.get(key)
    if hit is not None:
        return hit
    labs = [(int(m.group(1)), m.start()) for m in re.finditer(r"^L(\d+):", ident, re.M)]
    _ident_label_cache[key] = labs
    return labs


def ident_site_for_insn(ident, insn):
    if not ident or insn is None:
        return None, None, ""
    labs = ident_labels(ident)
    if not labs:
        return None, None, ""
    i = bisect.bisect_right(labs, (insn, 10 ** 9)) - 1
    if i < 0:
        return None, None, ""
    lab, pos = labs[i]
    enc, _ = enclosing_ident_fn(ident, pos)
    ln = line_of(ident, pos)
    line_end = ident.find("\n", pos)
    nxt = ident.find("\n", line_end + 1) if line_end >= 0 else -1
    text = ""
    if line_end >= 0 and nxt >= 0:
        text = ident[line_end + 1 : nxt].strip()
    return ln, enc, text


_cvar_taint_cache = {}


def _cvar_range_lookup(vm_bases, n):
    """(row, off) if n is in [vm, vm+271] of some row, else None. Not +272/+280."""
    if n is None or n < 0 or not vm_bases:
        return None
    i = bisect.bisect_right(vm_bases, (n, 10 ** 9)) - 1
    if i < 0:
        return None
    vm, row = vm_bases[i]
    off = n - vm
    if 0 <= off < VMCVAR_SIZE:
        return row, off
    return None


def taint_cvar_events(insns, rows, table, stride, mask, trap_reg, trap_upd, admin):
    """CONST/LOAD/ADD/LOCAL taint into LOAD1/2/4. Seeds: vmCvar bases and table slots.

    Tags:
      ('I', n) immediate
      ('A', row, off) address of vmCvar[row]+off (row None = table-walk unknown row)
      ('T', row, field) address of cvarTable[row]+field
      ('W', field) address of some table row + field
      ('L', local_off) address of a local
    """
    n_rows = len(rows)
    vm_bases = sorted((r["vm"], i) for i, r in enumerate(rows) if r.get("vm"))
    table_map = {}
    if table is not None and stride:
        for i in range(n_rows):
            base = table + i * stride
            for f in range(0, stride, 4):
                table_map[base + f] = (i, f)

    field_imm = set((0, 4, 8, 12, 16, 256, 260, 264))

    def cvar_at(n):
        return _cvar_range_lookup(vm_bases, n)

    def as_addr(tag):
        if not tag:
            return tag
        if tag[0] == "I" and tag[1] is not None and tag[1] >= 0:
            n = tag[1] & mask
            hit = cvar_at(n)
            # Immediates: only known vmCvar fields / base. Do not tag 65537 etc.
            # just because they fall inside some [vm, vm+271]. ADD from a tagged
            # base may still form any off < 272.
            if hit and hit[1] in field_imm:
                return ("A", hit[0], hit[1])
            tf = table_map.get(n)
            if tf:
                return ("T",) + tf
        return tag

    def add_tags(a, b):
        if a and a[0] == "I" and b and b[0] != "I":
            a, b = b, a
        if a and a[0] == "I" and b and b[0] == "I":
            return ("I", a[1] + b[1])
        if not a or not b or b[0] != "I":
            return None
        k = b[1]
        if a[0] == "A":
            no = a[2] + k
            if 0 <= no < VMCVAR_SIZE:
                return ("A", a[1], no)
            return None
        if a[0] == "T":
            row, f = a[1], a[2]
            if stride and k % stride == 0 and k != 0:
                nr = row + k // stride
                if 0 <= nr < n_rows:
                    return ("T", nr, f)
                return ("W", f)
            nf = f + k
            if 0 <= nf < stride:
                return ("T", row, nf)
            return None
        if a[0] == "W":
            if stride and (k == stride or k % stride == 0):
                return ("W", a[1])
            nf = a[1] + k
            if 0 <= nf < stride:
                return ("W", nf)
            return None
        return None

    events = []
    call_args = {}
    recording = [False]

    def record(kind, insn, row, off, how):
        if not recording[0]:
            return
        if in_ranges(insn, admin):
            return
        events.append(
            {"kind": kind, "insn": insn, "row": row, "off": off, "how": how}
        )

    def run_pass(incoming):
        stack = []
        locals_ = {}
        pending = []
        frame = 0

        def push(t):
            stack.append(t)

        def pop():
            return stack.pop() if stack else None

        for i, (op, imm) in enumerate(insns):
            if op == OP_ENTER:
                stack = []
                locals_ = {}
                pending = []
                frame = imm or 0
                inc = incoming.get(i) or {}
                for k, tag in inc.items():
                    locals_[frame + 8 + 4 * k] = tag
                continue
            if op == OP_LEAVE:
                stack = []
                locals_ = {}
                pending = []
                continue
            if op == OP_CONST:
                push(("I", imm))
                continue
            if op == OP_LOCAL:
                push(("L", imm))
                continue
            if op == OP_PUSH:
                push(None)
                continue
            if op == OP_POP:
                pop()
                continue
            if op == OP_JUMP:
                pop()
                stack = []
                continue
            if op in OP_BRANCH:
                pop()
                pop()
                continue
            if op in (OP_LOAD1, OP_LOAD2, OP_LOAD4):
                addr = as_addr(pop())
                if addr and addr[0] == "L":
                    push(locals_.get(addr[1]))
                    continue
                if addr and addr[0] == "T":
                    row, f = addr[1], addr[2]
                    if f == 0:
                        push(("A", row, 0))
                        record("tbl-load", i, row, 0, "table-ptr LOAD *(table+row*stride)")
                    else:
                        push(None)
                    continue
                if addr and addr[0] == "W":
                    if addr[1] == 0:
                        push(("A", None, 0))
                        record("tbl-load", i, None, 0, "table-walk LOAD *(p)")
                    else:
                        push(None)
                    continue
                if addr and addr[0] == "A":
                    record("read", i, addr[1], addr[2], "LOAD of [vm,vm+271]")
                    push(None)
                    continue
                push(None)
                continue
            if op in (OP_STORE1, OP_STORE2, OP_STORE4):
                val = pop()
                addr = as_addr(pop())
                if addr and addr[0] == "L":
                    locals_[addr[1]] = val
                    continue
                if addr and addr[0] == "A":
                    record("write", i, addr[1], addr[2], "STORE of [vm,vm+271]")
                    continue
                continue
            if op == OP_ARG:
                tag = pop()
                pending.append((i, as_addr(tag) if tag and tag[0] == "I" else tag))
                continue
            if op == OP_BLOCK_COPY:
                src = as_addr(pop())
                dest = as_addr(pop())
                if src and src[0] == "A":
                    record("read", i, src[1], src[2], "BLOCK_COPY src in [vm,vm+271]")
                if dest and dest[0] == "A":
                    record("write", i, dest[1], dest[2], "BLOCK_COPY dest (not a read)")
                continue
            if op == OP_CALL:
                target_tag = pop()
                target = target_tag[1] if target_tag and target_tag[0] == "I" else None
                if target in (trap_reg, trap_upd):
                    pending = []
                    continue
                args = []
                for ai, (ainsn, atag) in enumerate(pending):
                    atag = as_addr(atag)
                    args.append(atag)
                    if atag and atag[0] == "A":
                        record(
                            "address-only",
                            ainsn,
                            atag[1],
                            atag[2],
                            "call arg &vmCvar[+off]",
                        )
                if target is not None and target >= 0 and 0 <= target < len(insns):
                    if not in_ranges(i, admin):
                        slot = call_args.setdefault(target, {})
                        for k, atag in enumerate(args):
                            if atag and atag[0] == "A":
                                slot[k] = atag
                pending = []
                push(None)
                continue
            if op == OP_ADD:
                b = pop()
                a = pop()
                push(add_tags(a, b))
                continue
            if op == OP_SUB:
                b = pop()
                a = pop()
                if b and b[0] == "I":
                    push(add_tags(a, ("I", -b[1])))
                else:
                    push(None)
                continue
            # default: drop a value for unknown ops that typically pop/push
            if op in (35, 36, 37, 49, 53, 58, 59):
                continue
            if 39 <= op <= 57:
                pop()
                pop()
                push(None)

        return

    incoming = {}
    for rnd in range(3):
        recording[0] = rnd == 2
        incoming = call_args
        run_pass(incoming)
    return events


def analyze_cvar_module(ident, data, hdr, start, stride, rows):
    path, blob, _ = load_qvm_blob()
    mask = data_mask(hdr[5], hdr[6], hdr[7])
    kind = vm_kind_from_path(path)
    trap_reg, trap_upd = trap_cvar_consts(kind)
    cache_key = (path, os.path.getmtime(path), start, stride, len(rows), ident and len(ident))
    hit = _cvar_taint_cache.get(cache_key)
    if hit:
        return hit
    insns = decode_qvm_insns(blob, hdr)
    admin = admin_cvar_ranges(insns, trap_reg, trap_upd)
    events = taint_cvar_events(
        insns, rows, start, stride, mask, trap_reg, trap_upd, admin
    )
    index = build_ident_load_index(ident) if ident else {}
    rec = {
        "admin": admin,
        "events": events,
        "index": index,
        "insns": insns,
        "mask": mask,
    }
    _cvar_taint_cache[cache_key] = rec
    return rec


def filter_taint_for_row(events, row):
    out = []
    for e in events:
        if e["row"] is None or e["row"] == row:
            out.append(e)
        elif e["kind"] == "tbl-load" and e["row"] == row:
            out.append(e)
    return out


def _emit_load_hit(mod, ident, h, how=None):
    how = how or h.get("how") or "identity CONST"
    insn = h.get("insn")
    enc = h.get("enc")
    line = h.get("line")
    text = h.get("text") or ""
    if (enc is None or not text) and ident and insn is not None:
        ln, e2, t2 = ident_site_for_insn(ident, insn)
        if line is None:
            line = ln
        if enc is None:
            enc = e2
        if not text:
            text = t2
    kind = h.get("kind") or ""
    extra = ("  %s" % kind) if kind else ""
    out(
        "    %s.c:%s  L%s  in %s%s"
        % (
            mod,
            line if line is not None else "?",
            insn if insn is not None else "?",
            enc or "?",
            extra,
        )
    )
    if text:
        out("      %s" % text[:160])
    out("      how: %s" % how)


def cmd_cvar(mod, needle, limit=20):
    ident_p = dump_files(mod)[0]
    ident = read_text(ident_p)
    _, data, hdr = load_qvm(mod)
    out("== cvar %r ==" % needle)
    out("xref of the name string is not a load. Gameplay CONSTs vmCvar+8 (or +12 / ioq3 +260).")
    out("Skip Register/Update by insn range (table walk + trap), not overlay fn names.")
    hits = find_strings(data, needle)
    if not hits:
        out("  (no C string %r in data+lit)" % needle)
        return
    for start, s, rel in hits[:8]:
        mark = "  +%d" % rel if rel else ""
        out("  string @%d%s %r" % (start, mark, s))
    tables = find_cvar_tables(data, needle)
    if not tables:
        out("  (no cvar table row; leftover vs lost still needs a vmCvar cell)")
        if ident:
            out("  try: dump.py ptrs <string-off>  (includes +256)")
        return
    start, stride, rows = tables[0]
    match = [r for r in rows if r.get("name") and r["name"].lower() == needle.lower()]
    if not match:
        match = [r for r in rows if r.get("name") and needle.lower() in r["name"].lower()]
    row = match[0]
    idx = rows.index(row)
    delta = row["name_dword"] - (row["name_off"] or 0)
    out(
        "  table @%d  stride=%d  rows=%d  row %d"
        % (start, stride, len(rows), idx)
    )
    if delta:
        out("  name dword %d = find @%d %+d" % (row["name_dword"], row["name_off"], delta))
    out("  vmCvar  %d" % row["vm"])
    out("  default %r" % row["default"])
    out("  flags   %d (%s)" % (row["flags"], format_cvar_flags(row["flags"])))
    out(
        "  fields  compact +4/+8/+12; ioq3 string[256] then +260 value / +264 integer"
    )
    out(
        "  size    vmCvar_t %d bytes; +%d is next cvar +8, not this .integer"
        % (VMCVAR_SIZE, VMCVAR_SIZE + 8)
    )
    ana = analyze_cvar_module(ident, data, hdr, start, stride, rows)
    admin = ana["admin"]
    if admin:
        bits = ", ".join("L%d-L%d" % (a, b) for a, b in admin[:6])
        more = " ..." if len(admin) > 6 else ""
        out("  admin   Register/Update insn ranges %s%s" % (bits, more))
    if not ident:
        out("  (no identity .c — CONST grep skipped; opcode taint still runs)")
    field_label = {
        0: "+0 base/string",
        4: "+4",
        8: "+8 value/test",
        12: "+12 integer",
        256: "+256 ioq3 modCount",
        260: "+260 ioq3 value",
        264: "+264 ioq3 integer",
    }
    out("== loads (skip Register/Update insn ranges) ==")
    nprint = 0
    any_hit = False
    shown_insns = set()

    def budget():
        return nprint >= limit

    # (1) identity CONSTs in [vm, vm+271]
    vm = row["vm"]
    if ident and vm:
        range_hits = []
        seen_line = set()
        for off in range(0, VMCVAR_SIZE):
            addr = vm + off
            for h in ident_code_hits(ident, addr, index=ana["index"], admin_ranges=admin):
                key = (h["line"], addr)
                if key in seen_line:
                    continue
                seen_line.add(key)
                hh = dict(h)
                hh["off"] = off
                hh["addr"] = addr
                range_hits.append(hh)
        range_hits.sort(key=lambda h: (h["off"], h["line"] or 0))
        # Prefer listing known fields first, then leftovers.
        by_off = {}
        for h in range_hits:
            by_off.setdefault(h["off"], []).append(h)
        prefer = list(VMCVAR_LOAD_OFFS) + [0]
        ordered_offs = []
        for o in prefer:
            if o in by_off and o not in ordered_offs:
                ordered_offs.append(o)
        for o in sorted(by_off):
            if o not in ordered_offs:
                ordered_offs.append(o)
        for off in ordered_offs:
            loads = by_off[off]
            addr = vm + off
            label = field_label.get(off, "+%d" % off)
            any_hit = True
            out(
                "  %s  qvm_mem+%d  (%d hits, identity CONST)"
                % (label, addr, len(loads))
            )
            for h in loads:
                if budget():
                    out("  ... truncated")
                    return
                _emit_load_hit(mod, ident, h)
                shown_insns.add(h.get("insn"))
                nprint += 1

    # (2)(3)(4) opcode taint: table-ptr field LOAD, pointer escape, memcpy src
    tev = filter_taint_for_row(ana["events"], idx)
    ident_addrs = set()
    if ident and vm:
        for off in range(0, VMCVAR_SIZE):
            if ident_code_hits(ident, vm + off, index=ana["index"], admin_ranges=admin):
                ident_addrs.add(vm + off)
    taint_shown = False
    for e in tev:
        if e["kind"] == "tbl-load":
            continue
        if e["kind"] == "write" and e["how"].startswith("BLOCK_COPY dest"):
            continue
        if e["insn"] in shown_insns and e["kind"] in ("read", "write"):
            continue
        off = e.get("off")
        if off is not None and vm:
            addr = vm + off
            if addr in ident_addrs or (addr - 4) in ident_addrs:
                continue
        if budget():
            out("  ... truncated")
            return
        if not taint_shown:
            out("  -- opcode taint / table-pointer (identity may omit computed BSS) --")
            taint_shown = True
        row_s = "row %s" % (e["row"] if e["row"] is not None else "walk")
        label = field_label.get(off, "+%d" % off if off is not None else "")
        out(
            "  %s  %s  %s  insn L%s"
            % (e["kind"], row_s, label, e["insn"] if e["insn"] is not None else "?")
        )
        dummy = {"insn": e["insn"], "kind": e["kind"], "how": e["how"]}
        _emit_load_hit(mod, ident, dummy, how=e["how"])
        shown_insns.add(e["insn"])
        nprint += 1
        any_hit = True

    if not any_hit:
        out(
            "  no CONST, no table-pointer LOAD, no [vm,vm+271] hit "
            "outside Register/Update ranges"
        )


def cmd_cvars(mod, limit=8):
    ident_p = dump_files(mod)[0]
    ident = read_text(ident_p)
    _, data, hdr = load_qvm(mod)
    tables = find_cvar_tables(data)
    if not tables:
        out("== cvars == (no table found)")
        return
    start, stride, rows = tables[0]
    ana = analyze_cvar_module(ident, data, hdr, start, stride, rows)
    admin = ana["admin"]
    index = ana["index"]
    events = ana["events"]
    by_row = {}
    walk_all = 0
    for e in events:
        if e["kind"] not in ("read", "address-only"):
            continue
        if e["row"] is None:
            walk_all += 1
            continue
        by_row.setdefault(e["row"], []).append(e)
    out(
        "== cvars  table @%d  stride=%d  rows=%d  %s =="
        % (start, stride, len(rows), MOD_LABEL)
    )
    out(
        "  #  %-24s %10s %8s %6s %5s %s"
        % ("name", "vmCvar", "flags", "+8", "obj", "tbl")
    )
    for i, row in enumerate(rows):
        plus8 = 0
        obj = 0
        tbl = 0
        vm = row["vm"]
        if index is not None and vm:
            plus8 = len(
                ident_code_hits(ident, vm + 8, index=index, admin_ranges=admin)
            )
            seen = set()
            ident_offs = set()
            for off in range(0, VMCVAR_SIZE):
                hs = ident_code_hits(
                    ident, vm + off, index=index, admin_ranges=admin
                )
                if not hs:
                    continue
                ident_offs.add(off)
                if off == 8:
                    continue
                for h in hs:
                    key = (h["line"], off)
                    if key in seen:
                        continue
                    seen.add(key)
                    obj += 1
        else:
            ident_offs = set()
        for e in by_row.get(i, []):
            if e["kind"] not in ("read", "address-only"):
                continue
            off = e.get("off")
            if off is not None and (off in ident_offs or (off - 4) in ident_offs):
                continue
            tbl += 1
        mark8 = str(plus8) if ident else "?"
        marko = str(obj) if ident else str(obj)
        out(
            "  %-3d %-24s %10d %8d %6s %5s %s"
            % (i, row["name"] or "?", vm, row["flags"], mark8, marko, tbl)
        )
    if ident:
        out("  +8 = compact .value identity CONSTs (skip Register/Update insn ranges).")
        out("  obj = other [vm,vm+271] identity hits (+0/+4/+12/...); tbl = table-pointer / taint LOAD identity missed.")
        out("  Empty xref NAME does not mean unused. Detail: dump.py cvar <name>")
    else:
        out("  (no identity .c — +8 is ?; obj/tbl still from opcode taint; pass --c)")
    if walk_all:
        out(
            "  footnote: %d table-walk LOAD(s) with unknown row (not assigned to one cvar)"
            % walk_all
        )
    if len(tables) > 1:
        out("  (%d more table-like run(s); showing the longest)" % (len(tables) - 1))


def configure_paths(qvm, ident, structc, names, sigs, label):
    global QVM_PATH, IDENT_PATH, STRUCT_PATH, NAMES_PATH, SIGS_PATH, MOD_LABEL
    QVM_PATH = os.path.abspath(qvm)
    stem = os.path.splitext(QVM_PATH)[0]
    base = os.path.basename(stem)
    MOD_LABEL = label or base
    ddir = os.path.dirname(QVM_PATH)

    def pick(explicit, *cands):
        if explicit:
            return os.path.abspath(explicit)
        for c in cands:
            if c and os.path.isfile(c):
                return os.path.abspath(c)
        return cands[0] if cands else None

    IDENT_PATH = pick(
        ident,
        stem + ".c",
        os.path.join(ddir, base, base + ".c"),
        os.path.join(ddir, base + ".c"),
    )
    STRUCT_PATH = pick(
        structc,
        stem + ".struct.c",
        os.path.join(ddir, base, base + ".struct.c"),
    )
    NAMES_PATH = pick(names, stem + ".names", os.path.join(ddir, base + ".names"))
    SIGS_PATH = pick(sigs, stem + ".sigs", os.path.join(ddir, base + ".sigs"))


def main():
    ap = argparse.ArgumentParser(
        description="QVM dump oracle -- strings (+/-4 NUL), identity fn/insn/callers, slots."
    )
    ap.add_argument("--qvm", required=True, help="path to the .qvm")
    ap.add_argument("--c", dest="ident", help="identity dump .c (probe_emit --no-typed)")
    ap.add_argument("--struct", dest="structc", help="structured dump .struct.c")
    ap.add_argument("--names", help=".names file")
    ap.add_argument("--sigs", help=".sigs file")
    ap.add_argument("-m", "--mod", default="", help="label in output (default: QVM stem)")
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True

    p = sub.add_parser("str", help="QVM C string at CONST offset(s), with +/-4")
    p.add_argument("offs", nargs="+", type=lambda x: int(x, 0))

    p = sub.add_parser("find", help="find C strings containing text")
    p.add_argument("needle")

    p = sub.add_parser("fn", help="overlay vs identity definition for a name")
    p.add_argument("name")

    p = sub.add_parser("insn", help="identity dump around L<insn>")
    p.add_argument("insn", type=lambda x: int(x, 0))
    p.add_argument("-n", type=int, default=50, help="lines after label")

    p = sub.add_parser("calls", help="identity call sites")
    p.add_argument("name")
    p.add_argument("-n", type=int, default=25)

    p = sub.add_parser("slot", help="identity accesses of +OFF")
    p.add_argument("off", type=lambda x: int(x, 0))
    p.add_argument("-n", type=int, default=30)

    p = sub.add_parser("addcmd", help="trap_AddCommand CONST -> strings")

    p = sub.add_parser("table", help="dump data table")
    p.add_argument("off", type=lambda x: int(x, 0))
    p.add_argument("-c", "--count", type=int, default=8)
    p.add_argument("-w", "--width", type=int, default=4)

    p = sub.add_parser(
        "color",
        help="vec4 RGBA windows at CONST-4 / CONST / CONST+4 (color pointers are often mid-vector)",
    )
    p.add_argument("offs", nargs="+", type=lambda x: int(x, 0))

    p = sub.add_parser("xref", help="QVM string -> identity qvm_mem uses")
    p.add_argument("needle")
    p.add_argument("-n", type=int, default=20)

    p = sub.add_parser(
        "cvar",
        aliases=["cvarxref"],
        help="cvar table row + [vm,vm+271] loads / table-pointer chase (not the name string)",
    )
    p.add_argument("name")
    p.add_argument("-n", type=int, default=20)

    p = sub.add_parser(
        "cvars",
        help="all cvar table rows; +8 / obj / tbl load counts if identity .c is present",
    )

    p = sub.add_parser("ptrs", help="find data-section pointers to a CONST")
    p.add_argument("off", type=lambda x: int(x, 0))
    p.add_argument("-n", type=int, default=40)

    p = sub.add_parser("hdr", help="QVM header: data / lit / bss sizes")

    args = ap.parse_args()
    configure_paths(args.qvm, args.ident, args.structc, args.names, args.sigs, args.mod)
    mod = MOD_LABEL
    if args.cmd == "str":
        cmd_str(mod, args.offs)
    elif args.cmd == "find":
        cmd_find(mod, args.needle)
    elif args.cmd == "fn":
        cmd_fn(mod, args.name)
    elif args.cmd == "insn":
        cmd_insn(mod, args.insn, context=args.n)
    elif args.cmd == "calls":
        cmd_calls(mod, args.name, limit=args.n)
    elif args.cmd == "slot":
        cmd_slot(mod, args.off, limit=args.n)
    elif args.cmd == "addcmd":
        cmd_addcmd(mod)
    elif args.cmd == "table":
        cmd_table(mod, args.off, args.count, args.width)
    elif args.cmd == "color":
        cmd_color(mod, args.offs)
    elif args.cmd == "xref":
        cmd_xref(mod, args.needle, limit=args.n)
    elif args.cmd == "cvar" or args.cmd == "cvarxref":
        cmd_cvar(mod, args.name, limit=args.n)
    elif args.cmd == "cvars":
        cmd_cvars(mod)
    elif args.cmd == "ptrs":
        cmd_ptrs(mod, args.off, limit=args.n)
    elif args.cmd == "hdr":
        cmd_hdr(mod)


if __name__ == "__main__":
    main()
