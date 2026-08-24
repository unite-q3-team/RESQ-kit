//! Control-flow graph construction.
//!
//! Function model:
//!   - A function starts at an ENTER instruction.
//!   - Frame size v = ENTER operand. Locals are LOCAL offsets < v.
//!     Arguments are at LOCAL (v + 8 + 4*k) (k=0,1,...) relative to programStack.
//!   - LEAVE v pops the saved program counter (return address).
//!
//! JUMP is indirect (target popped from opstack), so its destination is
//! resolved by a lightweight abstract interpretation. The typical
//! switch-dispatch pattern is:
//!     <expr> CONST base ADD  (or x<<2)  LOAD4  JUMP
//! where LOAD4 reads the jump table from the data segment. Full stack
//! tracking is deferred to `decompile`; here we look backward from each JUMP
//! for a pushed constant (pattern A) or a LOAD4 over a constant address
//! (pattern B). Unresolved JUMPs get no static edge.

use std::collections::{HashMap, HashSet};

use crate::disasm::{Disassembly, Insn};
use crate::loader::Qvm;
use crate::opcodes::Opcode;

/// A basic block: contiguous run of instructions [start, end).
#[derive(Debug, Clone)]
pub struct Block {
    /// First instruction index (inclusive).
    pub start: usize,
    /// One past the last instruction index (exclusive).
    pub end: usize,
    /// Block indices of successors.
    pub succ: Vec<usize>,
    /// Block indices of predecessors.
    pub pred: Vec<usize>,
}

impl Block {
    /// The block's terminating instruction.
    pub fn last<'a>(&self, d: &'a Disassembly) -> &'a Insn {
        &d.insns[self.end - 1]
    }

    /// The block's instructions.
    pub fn insns<'a>(&'a self, d: &'a Disassembly) -> &'a [Insn] {
        &d.insns[self.start..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

/// Control-flow graph of one function.
#[derive(Debug, Clone)]
pub struct CFG {
    pub blocks: Vec<Block>,
    /// Index of the entry block (always 0).
    pub entry: usize,
    /// Function instruction range.
    pub start: usize,
    pub end: usize,
}

impl CFG {
    pub fn block(&self, idx: usize) -> &Block {
        &self.blocks[idx]
    }
}

/// Instructions that terminate a block (they change control flow).
pub fn is_terminator(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        op,
        Enter
            | Leave
            | Jump
            | Eq
            | Ne
            | Lti
            | Lei
            | Gti
            | Gei
            | Ltu
            | Leu
            | Gtu
            | Geu
            | Eqf
            | Nef
            | Ltf
            | Lef
            | Gtf
            | Gef
    )
}

/// Resolve indirect JUMP destinations inside a linear run.
///
/// Pattern A: `... CONST c ... JUMP` -> target = c.
/// Pattern B: `... CONST base LOAD4 ... JUMP` -> target = data32[base].
/// Pattern C: indexed jump-table dispatch (switch):
///   `... CONST 2 LSH CONST base ADD LOAD4 JUMP` with preceding bounds
///   checks `CONST lo; LTI dflt` / `CONST hi; GTI dflt`; every valid
///   `data32[base/4 + k]` (k in lo..=hi) is a destination.
///
/// Pattern C returns ALL table targets so the CFG splits basic blocks at
/// every case target. Without that, `case k: goto L<t>` in the emitter
/// references a label that is mid-block and never printed (q3lcc:
/// `undefined label`). The dispatch JUMP gets no static edge (pattern C
/// targets are recorded for leader splitting only), so `decompile`'s
/// `resolve_switch` still runs and builds the real Switch terminator.
///
/// Returns `{jump_insn_idx: target_insn_idx}` (A/B) — see
/// `switch_table_targets` for C.
pub fn simulate_jump_targets(
    insns: &[Insn],
    start: usize,
    end: usize,
    data: &[i32],
) -> HashMap<usize, usize> {
    let mut targets = HashMap::new();

    // LOAD4 whose address is a constant pushed immediately before.
    let mut load4_addr: HashMap<usize, i32> = HashMap::new();
    for i in start..end {
        let ins = &insns[i];
        if ins.op == Opcode::Load4 && i > start {
            if let Some(prev) = insns.get(i - 1) {
                if prev.op == Opcode::Const {
                    if let Some(operand) = prev.operand {
                        load4_addr.insert(i, operand);
                    }
                }
            }
        }
    }

    for i in start..end {
        let ins = &insns[i];
        if ins.op != Opcode::Jump {
            continue;
        }
        // Pattern A: JUMP pops the value pushed by the immediate predecessor.
        if i > start && insns[i - 1].op == Opcode::Const {
            if let Some(operand) = insns[i - 1].operand {
                targets.insert(i, operand as usize);
            }
            continue;
        }
        // Pattern B: ... LOAD4 ... JUMP with only no-ops in between.
        let mut j = i as isize - 1;
        while j >= start as isize
            && matches!(
                insns[j as usize].op,
                Opcode::Pop | Opcode::Ignore | Opcode::Break
            )
        {
            j -= 1;
        }
        if j >= start as isize {
            let jj = j as usize;
            if insns[jj].op == Opcode::Load4 {
                if let Some(&base) = load4_addr.get(&jj) {
                    if base >= 0 && (base as usize) < data.len() {
                        targets.insert(i, data[base as usize] as usize);
                    }
                }
            }
        }
    }
    targets
}

/// Pattern C: indexed jump-table switch dispatch.
///
/// Detects `... CONST 2 LSH CONST base ADD LOAD4 JUMP` (lcc layout) inside
/// `[start, end)`, finds the preceding range bounds checks
/// `CONST lo; LTI dflt` / `CONST hi; GTI dflt` (dflt must match), and
/// returns every `data32[base/4 + k]` (k in lo..=hi) that is a valid
/// instruction index inside the function range.
///
/// These are the switch case targets. The CFG must split basic blocks at
/// each of them so the emitter can print `L<t>:` labels — a case target
/// that lands mid-block would otherwise emit `goto L<t>` with no label
/// (q3lcc: `undefined label`). See `simulate_jump_targets` for details.
pub fn switch_table_targets(insns: &[Insn], start: usize, end: usize, data: &[i32]) -> Vec<usize> {
    use Opcode::{Add, Const, Gti, Jump, Load4, Lsh, Lti};
    let mut out = Vec::new();
    for i in start..end {
        if insns[i].op != Jump {
            continue;
        }
        if i < start + 4 {
            continue;
        }
        // Before JUMP (allowing no-ops): LOAD4, ADD, CONST base, LSH, CONST 2.
        let mut k = i as isize - 1;
        while k >= start as isize
            && matches!(
                insns[k as usize].op,
                Opcode::Pop | Opcode::Ignore | Opcode::Break
            )
        {
            k -= 1;
        }
        if k < start as isize + 4 {
            continue;
        }
        let k = k as usize;
        let (l4, add, bse, lsh, sh) = (k, k - 1, k - 2, k - 3, k - 4);
        if insns[l4].op != Load4 || insns[add].op != Add || insns[bse].op != Const {
            continue;
        }
        if insns[lsh].op != Lsh || insns[sh].op != Const || insns[sh].operand != Some(2) {
            continue;
        }
        let base = insns[bse].operand.unwrap_or(0);
        if base < 0 || !(base as usize).is_multiple_of(4) {
            continue;
        }
        let tbl = base as usize / 4;
        if tbl >= data.len() {
            continue;
        }
        // Bounds checks: nearest `CONST c; LTI dflt` and `CONST c; GTI dflt`
        // scanning backward (they sit in the blocks before the dispatch).
        let mut lo: Option<(i32, usize)> = None;
        let mut hi: Option<(i32, usize)> = None;
        let mut cur = i as isize - 5;
        let mut steps = 0;
        while cur >= start as isize && steps < 64 {
            let c = cur as usize;
            if c + 1 < end && c > start && insns[c].op == Const {
                let n = &insns[c + 1];
                let v = insns[c].operand.unwrap_or(0);
                let t = n.target;
                match n.op {
                    Lti if lo.is_none() && t.is_some() => lo = Some((v, t.unwrap())),
                    Gti if hi.is_none() && t.is_some() => hi = Some((v, t.unwrap())),
                    _ => {}
                }
            }
            cur -= 1;
            steps += 1;
        }
        let (Some((l, dlo)), Some((h, dhi))) = (lo, hi) else {
            continue;
        };
        if dlo != dhi || l > h {
            continue;
        }
        for kk in l..=h {
            let di = tbl as isize + kk as isize;
            if di < 0 || di as usize >= data.len() {
                continue;
            }
            let t = data[di as usize] as usize;
            if t >= start && t < end && !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out
}

/// Split instructions into functions at ENTER boundaries.
///
/// Each function range is `[start_of_ENTER, next_ENTER)`.
pub fn build_functions(d: &Disassembly) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let starts: Vec<usize> = d
        .insns
        .iter()
        .filter(|i| i.op == Opcode::Enter)
        .map(|i| i.idx)
        .collect();
    for k in 0..starts.len() {
        let s = starts[k];
        let e = starts.get(k + 1).copied().unwrap_or(d.insns.len());
        ranges.push((s, e));
    }
    ranges
}

/// Build the CFG for one function range. Returns `None` for degenerate ranges.
pub fn build_cfg(d: &Disassembly, fn_range: (usize, usize), data: &[i32]) -> Option<CFG> {
    let (start_idx, end_idx) = fn_range;
    if start_idx >= end_idx {
        return None;
    }
    let insns = &d.insns;

    // ---- basic block split ----
    // Leaders: function entry, instructions after block-terminators, and
    // branch targets.
    let mut leaders = vec![start_idx];
    let mut leader_set: HashSet<usize> = HashSet::from([start_idx]);

    for i in start_idx..end_idx {
        let ins = &insns[i];
        if is_terminator(ins.op) {
            if i + 1 < end_idx && leader_set.insert(i + 1) {
                leaders.push(i + 1);
            }
            if let Some(t) = ins.target {
                if t >= start_idx && t < end_idx && leader_set.insert(t) {
                    leaders.push(t);
                }
            }
        }
    }

    // Resolve indirect jump targets; their destinations are leaders too.
    let jmp_targets = simulate_jump_targets(insns, start_idx, end_idx, data);
    for (&_jidx, &t) in &jmp_targets {
        if t >= start_idx && t < end_idx && leader_set.insert(t) {
            leaders.push(t);
        }
    }

    // Pattern C: jump-table switch dispatches — every case target is a
    // basic-block entry so the emitter's `case v: goto L<t>` labels exist
    // (a mid-block target would otherwise print an undefined label).
    for t in switch_table_targets(insns, start_idx, end_idx, data) {
        if leader_set.insert(t) {
            leaders.push(t);
        }
    }

    leaders.sort_unstable();
    let mut blocks: Vec<Block> = Vec::with_capacity(leaders.len());
    for k in 0..leaders.len() {
        let l = leaders[k];
        let e = leaders.get(k + 1).copied().unwrap_or(end_idx);
        blocks.push(Block {
            start: l,
            end: e,
            succ: Vec::new(),
            pred: Vec::new(),
        });
    }
    if blocks.is_empty() {
        return None;
    }

    let mut block_of: HashMap<usize, usize> = HashMap::with_capacity(blocks.len());
    let by_start: HashMap<usize, usize> = blocks
        .iter()
        .enumerate()
        .map(|(bi, b)| (b.start, bi))
        .collect();
    for (bi, b) in blocks.iter().enumerate() {
        for i in b.start..b.end {
            block_of.insert(i, bi);
        }
    }

    // ---- edges ----
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for bi in 0..blocks.len() {
        let b = &blocks[bi];
        let last = &insns[b.end - 1];
        match last.op {
            Opcode::Leave => {} // function return
            Opcode::Jump => {
                if let Some(&t) = jmp_targets.get(&last.idx) {
                    if t >= start_idx && t < end_idx {
                        if let Some(&dst) = by_start.get(&t) {
                            edges.push((bi, dst));
                        }
                    }
                }
                // unhandled indirect jump -> no static edge
            }
            op if op.is_branch_idx() => {
                if let Some(t) = last.target {
                    if t >= start_idx && t < end_idx {
                        if let Some(&dst) = by_start.get(&t) {
                            edges.push((bi, dst));
                        }
                    }
                }
                if let Some(&nb) = block_of.get(&(last.idx + 1)) {
                    edges.push((bi, nb));
                }
            }
            _ => {
                if let Some(&nb) = block_of.get(&(last.idx + 1)) {
                    edges.push((bi, nb));
                }
            }
        }
    }

    // dedupe edges, fill preds
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for &(a, b) in &edges {
        if seen.insert((a, b)) {
            blocks[a].succ.push(b);
            blocks[b].pred.push(a);
        }
    }

    Some(CFG {
        blocks,
        entry: 0,
        start: start_idx,
        end: end_idx,
    })
}

/// Convenience: functions + their CFGs for a whole QVM.
pub fn build_all(d: &Disassembly, qvm: &Qvm) -> Vec<CFG> {
    let data = qvm.data_int32();
    build_functions(d)
        .into_iter()
        .filter_map(|r| build_cfg(d, r, &data))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::disassemble;
    use crate::loader::parse;

    fn qvm_from_parts(code: &[u8], data: &[u8], instr_count: i32) -> crate::loader::Qvm {
        let mut f = Vec::new();
        for v in [
            0x12721444u32,
            instr_count as u32,
            32u32,
            code.len() as u32,
            32 + code.len() as u32,
            data.len() as u32,
            0u32,
            0u32,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(code);
        f.extend_from_slice(data);
        parse(&f).unwrap()
    }

    fn one_fn_code(insns: &[u8], count: i32) -> (Disassembly, crate::loader::Qvm) {
        let q = qvm_from_parts(insns, &[], count);
        let d = disassemble(&q).unwrap();
        (d, q)
    }

    #[test]
    fn function_split_at_enter() {
        // 2 functions: ENTER..ENTER and ENTER..end
        let code = [
            0x03, 4, 0, 0, 0, // f0: ENTER 4
            0x04, 4, 0, 0, 0, //     LEAVE 4
            0x03, 8, 0, 0, 0, // f1: ENTER 8
            0x04, 8, 0, 0, 0, //     LEAVE 8
        ];
        let (d, _) = one_fn_code(&code, 4);
        let ranges = build_functions(&d);
        assert_eq!(ranges, vec![(0, 2), (2, 4)]);
    }

    #[test]
    fn jump_const_pattern_a() {
        // #0 ENTER 0; #1 CONST 3; #2 JUMP; #3 LEAVE 0
        let code = [0x03, 0, 0, 0, 0, 0x08, 3, 0, 0, 0, 0x0a, 0x04, 0, 0, 0, 0];
        let (d, q) = one_fn_code(&code, 4);
        let data = q.data_int32();
        let cfg = build_cfg(&d, (0, 4), &data).unwrap();
        assert_eq!(cfg.blocks.len(), 3);
        // blocks: [0,1) [1,3) [3,4)
        assert_eq!(cfg.blocks[0].succ, vec![1]);
        assert_eq!(cfg.blocks[1].succ, vec![2]);
        assert_eq!(cfg.blocks[2].succ, vec![] as Vec<usize>);
        assert_eq!(cfg.blocks[2].pred, vec![1]);
    }

    #[test]
    fn jump_table_pattern_b() {
        // data word[0] = 7 (big-endian on disk)
        // #0 ENTER 0; #1 CONST 0; #2 CONST 0; #3 LOAD4; #4 JUMP;
        // #5 IGNORE; #6 IGNORE; #7 LEAVE 0 (target); #8 IGNORE
        let code = [
            0x03, 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0x08, 0, 0, 0, 0, 0x1d, 0x0a, 0x01, 0x01, 0x04, 0,
            0, 0, 0, 0x01,
        ];
        let data = [0x07, 0x00, 0x00, 0x00]; // little-endian 7
        let q = qvm_from_parts(&code, &data, 9);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 9), &data_words).unwrap();
        // leaders: 0, 1, 5, 7, 8 -> blocks [0,1) [1,5) [5,7) [7,8) [8,9)
        assert_eq!(cfg.blocks.len(), 5);
        // block [1,5) ends with JUMP -> target 7 => block idx 3
        assert_eq!(cfg.blocks[1].succ, vec![3]);
        // fallthrough chain 0->1, 2->3
        assert_eq!(cfg.blocks[0].succ, vec![1]);
        assert_eq!(cfg.blocks[2].succ, vec![3]);
    }

    #[test]
    fn jump_table_switch_pattern_c() {
        // switch(sel) with table dispatch:
        //   #0  ENTER 0          #9  LOCAL 4
        //   #1  LOCAL 4          #10 LOAD4
        //   #2  LOAD4            #11 CONST 2
        //   #3  CONST -1         #12 LSH
        //   #4  LTI 20 (dflt)    #13 CONST 8  (base, tbl word = 8/4 = 2)
        //   #5  LOCAL 4          #14 ADD
        //   #6  LOAD4            #15 LOAD4
        //   #7  CONST 2          #16 JUMP
        //   #8  GTI 20 (dflt)    #17..#20 case/default bodies, #21 IGNORE
        // data words: [0]=0, [1]=17 (case -1), [2]=20 (case 0), [3]=18 (case 1),
        //              [4]=19 (case 2)
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 4, 0, 0, 0, 0x1d, 0x08, 0xff, 0xff, 0xff, 0xff, 0x0d, 20, 0, 0,
            0, 0x09, 4, 0, 0, 0, 0x1d, 0x08, 2, 0, 0, 0, 0x0f, 20, 0, 0, 0, 0x09, 4, 0, 0, 0, 0x1d,
            0x08, 2, 0, 0, 0, 0x32, 0x08, 8, 0, 0, 0, 0x26, 0x1d, 0x0a, 0x01, 0x04, 0, 0, 0, 0,
            0x04, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0x01,
        ];
        let data = [
            0x00, 0x00, 0x00, 0x00, // word0 = 0
            0x11, 0x00, 0x00, 0x00, // word1 = 17 (case -1)
            0x14, 0x00, 0x00, 0x00, // word2 = 20 (case 0)
            0x12, 0x00, 0x00, 0x00, // word3 = 18 (case 1)
            0x13, 0x00, 0x00, 0x00, // word4 = 19 (case 2)
        ];
        let q = qvm_from_parts(&code, &data, 22);
        let d = disassemble(&q).unwrap();
        let words = q.data_int32();
        let mut targets = switch_table_targets(&d.insns, 0, 22, &words);
        targets.sort_unstable();
        assert_eq!(targets, vec![17, 18, 19, 20]);
        let cfg = build_cfg(&d, (0, 22), &words).unwrap();
        let starts: Vec<usize> = cfg.blocks.iter().map(|b| b.start).collect();
        assert_eq!(starts, vec![0, 1, 5, 9, 17, 18, 19, 20, 21]);
    }

    #[test]
    fn comparison_edge_both_ways() {
        // #0 ENTER 0; #1 CONST 1; #2 CONST 2; #3 GTI 5; #4 LEAVE 0; #5 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x08, 1, 0, 0, 0, 0x08, 2, 0, 0, 0, 0x0f, 5, 0, 0,
            0, // GTI -> #5
            0x04, 0, 0, 0, 0, // #4 LEAVE (fallthrough)
            0x04, 0, 0, 0, 0, // #5 LEAVE (target)
        ];
        let (d, q) = one_fn_code(&code, 6);
        let data = q.data_int32();
        let cfg = build_cfg(&d, (0, 6), &data).unwrap();
        // leaders: 0,1,4,5 -> blocks [0,1) [1,4) [4,5) [5,6)
        assert_eq!(cfg.blocks.len(), 4);
        // block [1,4) ends with GTI: succ = {target 5 => block 3, fallthrough 4 => block 2}
        let mut s = cfg.blocks[1].succ.clone();
        s.sort_unstable();
        assert_eq!(s, vec![2, 3]);
        assert_eq!(cfg.blocks[2].succ, vec![] as Vec<usize>);
    }
}
