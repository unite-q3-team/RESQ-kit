"""twostep.py -- find two-step field writes/increments in identity C.

Usage:
  python twostep.py <identity.c> <offset> [more_offsets...]

Identity C writes struct fields through a local: first
  *(int*)&loc_0[N] = (<base expr>) + OFFSET;
then access happens via *(int*)(*(int*)&loc_0[N]).
"""
import re
import sys


def main():
    path = sys.argv[1]
    offsets = sys.argv[2:]
    src = open(path, encoding='utf-8', errors='replace').read()
    funcs = [(m.group(1), m.start()) for m in
             re.finditer(r'(?m)^(?:int|void|float) (\w+)\([^)]*\) \{', src)]
    funcs.append(('__END__', len(src)))

    def fn_of(pos):
        fn = None
        for name, s in funcs:
            if s > pos:
                break
            fn = name
        return fn

    for t in offsets:
        print('==== field +' + t)
        pat = re.compile(
            r'\*\(int\*\)&(loc_0\[\d+\]) = \(([^;\n]{1,80})\) \+ ' + t + r';')
        hits = list(pat.finditer(src))
        if not hits:
            pat2 = re.compile(r'= \([^;\n]{1,80}\) \+ ' + t + r';')
            hits = [(m.start(), None, None) for m in pat2.finditer(src)]
        for m in hits:
            pos = m.start() if isinstance(m, tuple) else m.start()
            name = m.group(1) if not isinstance(m, tuple) and m.group(1) else '?'
            base = m.group(2) if not isinstance(m, tuple) and m.group(2) else ''
            seg = src[pos:pos + 150]
            marker = 'inc' if '+ 1;' in seg else ('copy' if '= *' in seg else '?')
            print('  %-12s %-6s via %-12s base: %s' % (fn_of(pos), marker, name, base[:48]))
        if not hits:
            print('  (none)')


if __name__ == '__main__':
    main()
