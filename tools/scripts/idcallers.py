"""idcallers.py -- find callers of a function in identity C / struct dump.

Usage:
  python idcallers.py <identity.c> <fn_name>

Prints every reference site `fn_name(` with line number and the enclosing
function (definition whose `{` is at end-of-line, skipping prototypes).
"""
import re
import sys


def main():
    path, fn = sys.argv[1], sys.argv[2]
    src = open(path, encoding='utf-8', errors='replace').read()
    lines = src.splitlines()

    cur = None
    defs = {}
    for i, l in enumerate(lines):
        m = re.match(r'^(?:int|void|float) (\w+)\(', l)
        if m and l.rstrip().endswith('{'):
            cur = m.group(1)
        defs[i] = cur

    needle = fn + '('
    for i, l in enumerate(lines):
        if needle in l and not re.match(
            r'^(?:int|void|float) ' + re.escape(fn) + r'\(', l
        ):
            print(i + 1, defs.get(i), l.strip()[:110])


if __name__ == '__main__':
    main()
