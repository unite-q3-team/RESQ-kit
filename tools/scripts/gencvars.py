"""gencvars.py -- emit G_CVAR(...) lines for cvars missing from a header.

Usage:
  python gencvars.py <cvar_registration.txt> <qagame.qvm> <skeleton_g_cvar.h> <out_block.txt>

Registration log: probe_verify / seqdiff INIT output (UTF-16 or UTF-8).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qvmstr import QvmStrings

FLAGMAP = {1: 'CVAR_ARCHIVE', 2: 'CVAR_USERINFO', 4: 'CVAR_SERVERINFO',
           8: 'CVAR_SYSTEMINFO', 16: 'CVAR_INIT', 32: 'CVAR_LATCH',
           64: 'CVAR_ROM', 1024: 'CVAR_NORESTART'}


def flagname(f):
    parts = [n for v, n in FLAGMAP.items() if f & v]
    rest = f & ~sum(FLAGMAP)
    if rest:
        parts.append(str(rest))
    return ' | '.join(parts) if parts else '0'


def main():
    reg_path, qvm_path, skel_path, out_path = sys.argv[1:5]
    qvm = QvmStrings(qvm_path)

    raw = open(reg_path, 'rb').read()
    try:
        txt = raw.decode('utf-16')
    except Exception:
        txt = raw.decode('utf-8', errors='replace')

    skel = set()
    for line in open(skel_path, encoding='utf-8', errors='replace'):
        m = re.search(r'G_CVAR\(\s*\w+,\s*"([^"]+)",', line)
        if m:
            skel.add(m.group(1).lower())

    seen = set()
    out = []
    pat = re.compile(
        r'trap_Cvar_Register\(3,\s*(\d+),\s*"([^"]+)",\s*("(?:[^"]*)"|28406|\d+),\s*(\d+)')
    for line in txt.splitlines():
        m = pat.search(line)
        if not m:
            continue
        name = m.group(2)
        key = name.lower()
        if key in skel or key in seen:
            continue
        seen.add(key)
        d = m.group(3)
        if d.startswith('"'):
            dflt = d
        else:
            try:
                s = qvm.cstr(int(d))
                dflt = '"%s"' % s.replace('\\', '\\\\').replace('"', '\\"') if s is not None else '""'
            except ValueError:
                dflt = '""'
        var = re.sub(r'\W', '_', name)
        out.append('G_CVAR( %s, "%s", %s, %s, 0, qfalse, qfalse )'
                   % (var, name, dflt, flagname(int(m.group(4)))))

    open(out_path, 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')
    print('generated %d entries -> %s' % (len(out), out_path))


if __name__ == '__main__':
    main()
