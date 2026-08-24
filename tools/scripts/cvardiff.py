"""cvardiff.py -- INIT trap_Cvar_Register names vs a skeleton header.

Usage:
  python cvardiff.py <cvar_registration.txt> <skeleton_g_cvar.h>
"""
import re
import sys


def read_registrations(path):
    raw = open(path, 'rb').read()
    try:
        txt = raw.decode('utf-16')
    except Exception:
        txt = raw.decode('utf-8', errors='replace')
    reg = []
    pat = re.compile(
        r'trap_Cvar_Register\(3,\s*(\d+),\s*"([^"]+)",\s*("(?:[^"]*)"|28406|\d+),\s*(\d+)')
    for line in txt.splitlines():
        m = pat.search(line)
        if m:
            reg.append((m.group(2), m.group(3), int(m.group(4)), int(m.group(1))))
    return reg


def read_skeleton_names(path):
    names = set()
    for line in open(path, encoding='utf-8', errors='replace'):
        m = re.search(r'G_CVAR\(\s*\w+,\s*"([^"]+)",', line)
        if m:
            names.add(m.group(1).lower())
    return names


def main():
    reg_path, skel_path = sys.argv[1], sys.argv[2]
    reg = read_registrations(reg_path)
    skel = read_skeleton_names(skel_path)
    have = {n.lower() for n, _, _, _ in reg}
    print('in log, not in header:')
    for n, d, flags, _ in reg:
        if n.lower() not in skel:
            print('  ', n, d, flags)
    print('in header, not in log:')
    for n in sorted(skel - have):
        print('  ', n)


if __name__ == '__main__':
    main()
