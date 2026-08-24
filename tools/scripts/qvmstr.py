"""qvmstr.py -- shared reader for QVM data/lit segments.

Classic id header: magic, insnCount, codeOff, codeLen, dataOff, dataLen,
litLength, bssLength. Literals follow data in the file (no separate litOffset).
A trailing extra int after bssCount (some assemblers) is ignored.

Identity C renders `qvm_mem + N` for true VM address N + 4 (blob word 0 is a
NULL sentinel). Helpers here take TRUE VM addresses.
"""
import os
import struct
import sys


class QvmStrings:
    def __init__(self, path):
        self.b = open(path, 'rb').read()
        (self.magic, self.insn_count,
         self.code_off, self.code_len,
         self.data_off, self.data_len) = struct.unpack_from('<6i', self.b, 0)
        self.lit_count = struct.unpack_from('<i', self.b, 24)[0]
        self.bss_len = struct.unpack_from('<i', self.b, 28)[0]
        self.lit_off = self.data_off + self.data_len

    def _offset(self, vm_addr):
        if vm_addr < self.data_len:
            return self.data_off + vm_addr
        if vm_addr < self.data_len + self.lit_count:
            return self.lit_off + (vm_addr - self.data_len)
        return None

    def word(self, vm_addr):
        o = self._offset(vm_addr)
        if o is None:
            raise ValueError('address %d outside data+lit' % vm_addr)
        return struct.unpack_from('<i', self.b, o)[0]

    def cstr(self, vm_addr):
        o = self._offset(vm_addr)
        if o is None:
            raise ValueError('address %d outside data+lit' % vm_addr)
        end = self.b.index(0, o)
        return self.b[o:end].decode('latin1')

    def words(self, vm_addr, count):
        return [self.word(vm_addr + 4 * k) for k in range(count)]


def _scripts_dir():
    return os.path.dirname(os.path.abspath(__file__))


if _scripts_dir() not in sys.path:
    sys.path.insert(0, _scripts_dir())
