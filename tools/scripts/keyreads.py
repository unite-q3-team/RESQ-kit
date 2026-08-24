"""keyreads.py -- map Info_ValueForKey-style queries to enclosing functions.

Usage:
  python keyreads.py <struct_dump.c> <valueforkey_fn> [keys...]
"""
import re
import sys


def main():
    path, vk = sys.argv[1], sys.argv[2]
    only_keys = set(sys.argv[3:])

    src = open(path, encoding='utf-8', errors='replace').read()
    funcs = []
    for m in re.finditer(r'(?m)(?:int|void|float) (\w+)\(', src):
        if '{' not in src[m.start():m.start() + 200]:
            continue
        funcs.append((m.group(1), m.start()))

    def fname_of(pos):
        best = None
        for name, s in funcs:
            if s > pos:
                break
            best = name
        return best

    seen = {}
    pat = re.compile(re.escape(vk) + r'\([^,\n]+, "(\w+)"\)')
    for m in pat.finditer(src):
        k = m.group(1)
        if only_keys and k not in only_keys:
            continue
        seen.setdefault(fname_of(m.start()), set()).add(k)

    for fn in sorted(x for x in seen if x):
        print(fn, sorted(seen[fn]))


if __name__ == '__main__':
    main()
