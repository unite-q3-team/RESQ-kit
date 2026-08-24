#!/usr/bin/env python3
"""QVM CONST bit calculator — identity dumps store IEEE-754 floats as i32.

No QVM file needed. Use this before pasting a CONST into C.

  python tools/qvmbits.py --fbits -1002487808 1134329856 1103101952
  python tools/qvmbits.py --fbits 0xC3C80000
  python tools/qvmbits.py --float -568 -768 450
  python tools/qvmbits.py --tfl 1836958 1841054 18616254
  python tools/qvmbits.py --mask 100663297

  python tools/qvmbits.py -1002487808 1134329856 1103101952
      (bare args: fbits + tfl + contents for each)
"""
from __future__ import print_function

import argparse
import struct
import sys


TFL = (
    (0x00000001, "TFL_INVALID"),
    (0x00000002, "TFL_WALK"),
    (0x00000004, "TFL_CROUCH"),
    (0x00000008, "TFL_BARRIERJUMP"),
    (0x00000010, "TFL_JUMP"),
    (0x00000020, "TFL_LADDER"),
    (0x00000040, "TFL_0x40"),
    (0x00000080, "TFL_WALKOFFLEDGE"),
    (0x00000100, "TFL_SWIM"),
    (0x00000200, "TFL_WATERJUMP"),
    (0x00000400, "TFL_TELEPORT"),
    (0x00000800, "TFL_ELEVATOR"),
    (0x00001000, "TFL_ROCKETJUMP"),
    (0x00002000, "TFL_BFGJUMP"),
    (0x00004000, "TFL_GRAPPLEHOOK"),
    (0x00008000, "TFL_DOUBLEJUMP"),
    (0x00010000, "TFL_RAMPJUMP"),
    (0x00020000, "TFL_STRAFEJUMP"),
    (0x00040000, "TFL_JUMPPAD"),
    (0x00080000, "TFL_AIR"),
    (0x00100000, "TFL_WATER"),
    (0x00200000, "TFL_SLIME"),
    (0x00400000, "TFL_LAVA"),
    (0x00800000, "TFL_DONOTENTER"),
    (0x01000000, "TFL_FUNCBOB"),
    (0x02000000, "TFL_FLIGHT"),
    (0x04000000, "TFL_BRIDGE"),
    (0x08000000, "TFL_NOTTEAM1"),
    (0x10000000, "TFL_NOTTEAM2"),
)

CONTENTS = (
    (1, "CONTENTS_SOLID"),
    (8, "CONTENTS_LAVA"),
    (16, "CONTENTS_SLIME"),
    (32, "CONTENTS_WATER"),
    (64, "CONTENTS_FOG"),
    (0x0080, "CONTENTS_NOTTEAM1"),
    (0x0100, "CONTENTS_NOTTEAM2"),
    (0x0200, "CONTENTS_NOBOTCLIP"),
    (0x8000, "CONTENTS_AREAPORTAL"),
    (0x10000, "CONTENTS_PLAYERCLIP"),
    (0x20000, "CONTENTS_MONSTERCLIP"),
    (0x40000, "CONTENTS_TELEPORTER"),
    (0x80000, "CONTENTS_JUMPPAD"),
    (0x100000, "CONTENTS_CLUSTERPORTAL"),
    (0x200000, "CONTENTS_DONOTENTER"),
    (0x400000, "CONTENTS_BOTCLIP"),
    (0x800000, "CONTENTS_MOVER"),
    (0x1000000, "CONTENTS_ORIGIN"),
    (0x2000000, "CONTENTS_BODY"),
    (0x4000000, "CONTENTS_CORPSE"),
    (0x8000000, "CONTENTS_DETAIL"),
    (0x10000000, "CONTENTS_STRUCTURAL"),
    (0x20000000, "CONTENTS_TRANSLUCENT"),
    (0x40000000, "CONTENTS_TRIGGER"),
    (0x80000000, "CONTENTS_NODROP"),
)

KNOWN_MASKS = {
    1: "MASK_SOLID",
    0x02010001: "MASK_PLAYERSOLID",  # SOLID|PLAYERCLIP|BODY
    0x00010001: "MASK_DEADSOLID",
    0x00000038: "MASK_WATER",
    0x00000019: "MASK_OPAQUE",
    0x06000001: "MASK_SHOT",
}


def parse_i32(s):
    v = int(s, 0)
    if v >= 2 ** 31:
        v -= 2 ** 32
    if v < -(2 ** 31) or v >= 2 ** 31:
        raise ValueError("not i32: %s" % s)
    return v


def i32_to_u32(v):
    return v & 0xFFFFFFFF


def i32_to_f32(v):
    return struct.unpack("<f", struct.pack("<i", v))[0]


def f32_to_i32(f):
    return struct.unpack("<i", struct.pack("<f", float(f)))[0]


def c_float(f):
    """C89 literal that round-trips through IEEE-754 binary32."""
    i = f32_to_i32(f)
    if f != f:  # NaN
        return "/* NaN bits %d */ 0.0f" % i
    if f == float("inf"):
        return "/* +inf bits %d */ 1.0e38f" % i
    if f == float("-inf"):
        return "/* -inf bits %d */ -1.0e38f" % i
    n = abs(f)
    if n == 0.0:
        return "-0.0f" if struct.pack("<f", f)[3] & 0x80 else "0.0f"
    if n >= 1e7 or (n != 0.0 and n < 1e-4):
        s = "%.9g" % f
    else:
        s = ("%.9g" % f)
    if "." not in s and "e" not in s and "E" not in s:
        s += ".0"
    lit = s + "f"
    got = f32_to_i32(float(s))
    if got != i:
        lit = "%.9ef" % f
        got = f32_to_i32(float(lit[:-1]))
    if got != i:
        return "/* bits %d (no exact C literal) */ %sf" % (i, s)
    return lit


def flag_names(v, table):
    u = i32_to_u32(v)
    names = []
    rest = u
    for bit, name in table:
        if u & bit:
            names.append(name)
            rest &= ~bit
    return names, rest


def print_flags(title, v, table, known=None):
    names, rest = flag_names(v, table)
    u = i32_to_u32(v)
    extra = ""
    if known and u in known:
        extra = "  == %s" % known[u]
    print("%s  %d  0x%08X%s" % (title, v, u, extra))
    if names:
        print("    " + " | ".join(names))
    if rest:
        print("    leftover 0x%X" % rest)


def print_fbits(vals):
    lits = []
    for v in vals:
        f = i32_to_f32(v)
        lit = c_float(f)
        lits.append(lit)
        back = f32_to_i32(f)
        ok = "  round-trip ok" if back == v else "  ROUND-TRIP FAIL got %d" % back
        print("i32 %d  u32 %u  0x%08X  float %r  C %s%s" % (
            v, i32_to_u32(v), i32_to_u32(v), f, lit, ok
        ))
    n = len(lits)
    if n == 3:
        print("VectorSet( v, %s, %s, %s );" % tuple(lits))
    elif n == 2:
        print("/* xy */ %s, %s" % tuple(lits))
    elif n > 3 and n % 3 == 0:
        for i in range(0, n, 3):
            print("VectorSet( v, %s, %s, %s );" % tuple(lits[i:i + 3]))


def print_floats(vals):
    lits = []
    bits = []
    for f in vals:
        i = f32_to_i32(f)
        lit = c_float(f)
        lits.append(lit)
        bits.append(i)
        print("float %r  C %s  i32 %d  u32 %u  0x%08X" % (
            f, lit, i, i32_to_u32(i), i32_to_u32(i)
        ))
    if len(bits) == 3:
        print("QVM blob_12 triplet: %d, %d, %d" % tuple(bits))
        print("VectorSet( v, %s, %s, %s );" % tuple(lits))


def main():
    ap = argparse.ArgumentParser(
        description="Decode QVM CONST i32 as float / TFL / CONTENTS. No .qvm needed."
    )
    ap.add_argument(
        "--fbits",
        nargs="+",
        metavar="I32",
        help="IEEE-754 bits as signed i32 or 0x hex (groups of 3 -> VectorSet)",
    )
    ap.add_argument(
        "--float",
        nargs="+",
        metavar="F",
        type=float,
        help="C floats -> QVM i32 bits",
    )
    ap.add_argument("--tfl", nargs="+", metavar="I32", help="travel-flag mask")
    ap.add_argument("--mask", nargs="+", metavar="I32", help="CONTENTS / MASK_*")
    ap.add_argument(
        "vals",
        nargs="*",
        help="bare i32s: print float + TFL + CONTENTS for each",
    )
    args = ap.parse_args()

    did = False
    if args.fbits:
        print_fbits([parse_i32(s) for s in args.fbits])
        did = True
    if args.float is not None:
        print_floats(args.float)
        did = True
    if args.tfl:
        for s in args.tfl:
            print_flags("TFL", parse_i32(s), TFL)
        did = True
    if args.mask:
        for s in args.mask:
            print_flags("CONTENTS", parse_i32(s), CONTENTS, KNOWN_MASKS)
        did = True
    if args.vals:
        nums = [parse_i32(s) for s in args.vals]
        print_fbits(nums)
        print("")
        for v in nums:
            print_flags("TFL", v, TFL)
            print_flags("CONTENTS", v, CONTENTS, KNOWN_MASKS)
        did = True
    if not did:
        ap.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
