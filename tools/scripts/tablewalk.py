"""tablewalk.py -- dump a data-segment struct array from a QVM.

Usage:
  python tablewalk.py <file.qvm> <table_base_vm> <count_addr_vm> [stride]

Default stride 28. Each row prints signed words; word 1 is tried as a C string
pointer (name tables). Pass true VM addresses (identity `qvm_mem + N` is N+4).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qvmstr import QvmStrings


def main():
    if len(sys.argv) < 4:
        sys.stderr.write('usage: tablewalk.py <qvm> <table_base_vm> <count_addr_vm> [stride]\n')
        sys.exit(2)
    qvm_path = sys.argv[1]
    base = int(sys.argv[2], 0)
    count_addr = int(sys.argv[3], 0)
    stride = int(sys.argv[4], 0) if len(sys.argv) > 4 else 28
    words = max(1, stride // 4)
    q = QvmStrings(qvm_path)

    n = q.word(count_addr)
    print('rows:', n, 'base:', base, 'stride:', stride)
    for k in range(n):
        r = base + stride * k
        f = q.words(r, words)
        name = ''
        if len(f) > 1 and f[1]:
            try:
                name = q.cstr(f[1])
            except ValueError:
                name = '?'
        rest = ' '.join(str(x) for x in f)
        print('%3d | %-24s %s' % (k, name, rest))


if __name__ == '__main__':
    main()
