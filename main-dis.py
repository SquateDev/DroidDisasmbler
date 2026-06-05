# Создано при поддержке SquateDev
# Используются библиотеки: capstone, pyelftools, pefile, PySide6

import sys
import struct
import os
import re
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QHBoxLayout, QWidget, QMenuBar, QMenu,
    QFileDialog, QMessageBox, QSplitter, QPushButton, QLabel,
    QComboBox, QFontDialog, QToolBar, QStatusBar, QTextBrowser,
    QTabWidget, QTextEdit, QInputDialog, QLineEdit
)
from PySide6.QtCore import Qt, QUrl, QTimer
from PySide6.QtGui import (
    QAction, QFont, QColor, QPalette, QShortcut, QKeySequence
)

import capstone
from capstone import (
    x86_const, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
    CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB,
    CS_ARCH_ARM64, CS_MODE_ARM as CS_MODE_ARM64,
    arm_const, arm64_const
)
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import pefile


def demangle_cpp(name):
    if name.startswith('_Z'):
        try:
            import subprocess
            result = subprocess.run(['c++filt', name], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        try:
            result = subprocess.run(['undname', name], capture_output=True, text=True, shell=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        return manual_demangle(name)
    return name


def manual_demangle(name):
    if not name.startswith('_Z'):
        return name
    rest = name[2:]
    if rest.startswith('N'):
        depth = 0
        parts = []
        current = ''
        i = 1
        while i < len(rest):
            if rest[i] == 'E':
                if depth == 0:
                    break
                depth -= 1
                i += 1
                continue
            if rest[i].isdigit():
                num = ''
                while i < len(rest) and rest[i].isdigit():
                    num += rest[i]
                    i += 1
                length = int(num)
                parts.append(rest[i:i + length])
                i += length
            elif rest[i] == 'N':
                depth += 1
                i += 1
            else:
                break
        if parts:
            result = '::'.join(parts)
            paren_idx = rest.find('E')
            if paren_idx > 0:
                result += '(' + rest[paren_idx + 1:] + ')'
            return result
    elif rest.startswith('K'):
        return manual_demangle('_Z' + rest[1:]) + ' const'
    elif rest.startswith('P'):
        return manual_demangle('_Z' + rest[1:]) + '*'
    elif rest.startswith('R'):
        return manual_demangle('_Z' + rest[1:]) + '&'
    digits = ''
    i = 0
    while i < len(rest) and rest[i].isdigit():
        digits += rest[i]
        i += 1
    if digits:
        length = int(digits)
        func_name = rest[i:i + length]
        params = rest[i + length:]
        if params.startswith('v'):
            return f'{func_name}()'
        else:
            param_str = parse_params(params)
            return f'{func_name}({param_str})'
    return name


def parse_params(params):
    if not params or params == 'v':
        return ''
    param_types = {
        'i': 'int', 'j': 'unsigned int', 'l': 'long', 'm': 'unsigned long',
        'x': 'long long', 'y': 'unsigned long long', 'f': 'float', 'd': 'double',
        'c': 'char', 'a': 'signed char', 'h': 'unsigned char', 's': 'short',
        't': 'unsigned short', 'b': 'bool', 'v': 'void',
        'P': '*', 'R': '&', 'K': 'const ',
    }
    result = []
    i = 0
    while i < len(params):
        if params[i] in param_types:
            result.append(param_types[params[i]])
            i += 1
        elif params[i].isdigit():
            num = ''
            while i < len(params) and params[i].isdigit():
                num += params[i]
                i += 1
            length = int(num)
            result.append(params[i:i + length])
            i += length
        else:
            i += 1
    return ', '.join(result)


class Il2CppMetadata:
    def __init__(self, data):
        self.methods = []
        self._parse(data)

    def _read_string(self, buf, offset):
        end = buf.find(b'\0', offset)
        return buf[offset:end].decode('utf-8', errors='ignore')

    def _parse(self, data):
        if data[:4] != b'\xAF\x1B\xB1\xFA':
            return
        ptr_size = struct.unpack_from('<I', data, 4)[0]
        version = struct.unpack_from('<I', data, 8)[0]
        if version < 24:
            return
        header_size = 24 + 16
        if struct.unpack_from('<I', data, header_size)[0] != 0xFAB11BAF:
            return
        strings_off = struct.unpack_from('<I', data, header_size + 4)[0]
        strings_cnt = struct.unpack_from('<I', data, header_size + 8)[0]
        methods_off = struct.unpack_from('<I', data, header_size + 12)[0]
        methods_cnt = struct.unpack_from('<I', data, header_size + 16)[0]
        for i in range(methods_cnt):
            off = methods_off + i * 8
            method_ptr = struct.unpack_from('<Q', data, off)[0]
            if method_ptr:
                name_idx = struct.unpack_from('<I', data, method_ptr)[0]
                name = self._read_string(data, strings_off + name_idx)
                code_size = struct.unpack_from('<I', data, method_ptr + 4)[0]
                code_ptr = struct.unpack_from('<Q', data, method_ptr + 8)[0]
                self.methods.append((name, code_ptr, code_size))


class BinaryFile:
    def __init__(self, path):
        self.path = path
        self.arch = None
        self.mode = None
        self.sections = []
        self.all_sections = []
        self.entry = None
        self.base = 0
        self.format = None
        self.symbols = []
        self.exports = []
        self.il2cpp_meta = None
        self.error = None

        try:
            with open(path, 'rb') as f:
                self.raw = f.read()
        except Exception as e:
            self.error = str(e)
            return

        if self._try_parse_elf():
            return
        if self._try_parse_pe():
            return
        self.error = "Формат не распознан"

    def _try_parse_elf(self):
        if len(self.raw) < 64 or self.raw[:4] != b'\x7fELF':
            return False
        ei_class = self.raw[4]
        ei_data = self.raw[5]
        if ei_data == 1:
            endian = '<'
        elif ei_data == 2:
            endian = '>'
        else:
            return False
        if ei_class == 1:
            header = struct.unpack_from(endian + 'HHIIIIIHHHHHH', self.raw, 16)
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = header
        elif ei_class == 2:
            header = struct.unpack_from(endian + 'HHIQQQIHHHHHH', self.raw, 16)
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = header
        else:
            return False
        self.format = 'elf'
        self.base = 0
        self.entry = e_entry
        arch_map = {
            3: (CS_ARCH_X86, CS_MODE_32),
            62: (CS_ARCH_X86, CS_MODE_64),
            40: (CS_ARCH_ARM, CS_MODE_ARM),
            183: (CS_ARCH_ARM64, CS_MODE_ARM64),
        }
        if e_machine not in arch_map:
            self.error = f"ELF machine {e_machine} unsupported"
            return False
        self.arch, self.mode = arch_map[e_machine]
        if e_shoff == 0 or e_shnum == 0 or e_shstrndx == 0:
            self._load_elf_segments(e_phoff, e_phentsize, e_phnum, ei_class, endian)
        else:
            self._load_elf_sections(e_shoff, e_shentsize, e_shnum, e_shstrndx, ei_class, endian)
        self._load_elf_symbols(e_shoff, e_shentsize, e_shnum, e_shstrndx, ei_class, endian)
        if self.entry and self.entry not in [s[0] for s in self.symbols]:
            self.symbols.append((self.entry, "_start"))
        return True

    def _load_elf_sections(self, shoff, shentsize, shnum, shstrndx, ei_class, endian):
        if ei_class == 1:
            shdr_struct = endian + 'IIIIIIIIII'
        else:
            shdr_struct = endian + 'IIQQQQIIQQ'
        str_off = shoff + shstrndx * shentsize
        if ei_class == 1:
            str_shdr = struct.unpack_from(shdr_struct, self.raw, str_off)
            str_offset = str_shdr[3]
            str_size = str_shdr[4]
        else:
            str_shdr = struct.unpack_from(shdr_struct, self.raw, str_off)
            str_offset = str_shdr[3]
            str_size = str_shdr[4]
        strtab = self.raw[str_offset:str_offset + str_size]
        for i in range(shnum):
            off = shoff + i * shentsize
            if ei_class == 1:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                    shdr_struct, self.raw, off)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                    shdr_struct, self.raw, off)
            if sh_size == 0:
                continue
            name_end = strtab.find(b'\0', sh_name)
            name = strtab[sh_name:name_end].decode('ascii', errors='ignore')
            if sh_offset != 0 and sh_offset + sh_size <= len(self.raw):
                data = self.raw[sh_offset:sh_offset + sh_size]
            else:
                data = b'\x00' * sh_size
            is_exec = bool(sh_flags & 0x4)
            self.all_sections.append((name, sh_addr, sh_size, data, is_exec))
            if is_exec and sh_size > 0:
                self.sections.append((sh_addr, sh_size, data))

    def _load_elf_segments(self, phoff, phentsize, phnum, ei_class, endian):
        for i in range(phnum):
            off = phoff + i * phentsize
            if ei_class == 1:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                    endian + 'IIIIIIII', self.raw, off)
            else:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                    endian + 'IIQQQQQQ', self.raw, off)
            if p_type == 1 and p_filesz > 0:
                name = f"LOAD_{i}"
                data = self.raw[p_offset:p_offset + p_filesz]
                is_exec = bool(p_flags & 1)
                self.all_sections.append((name, p_vaddr, p_memsz, data, is_exec))
                if is_exec:
                    self.sections.append((p_vaddr, p_memsz, data))

    def _load_elf_symbols(self, shoff, shentsize, shnum, shstrndx, ei_class, endian):
        if ei_class == 1:
            shdr_struct = endian + 'IIIIIIIIII'
        else:
            shdr_struct = endian + 'IIQQQQIIQQ'
        str_offset = 0
        dynsym_off = None
        dynsym_size = 0
        symtab_off = None
        symtab_size = 0
        for i in range(shnum):
            off = shoff + i * shentsize
            if ei_class == 1:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                    shdr_struct, self.raw, off)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                    shdr_struct, self.raw, off)
            if sh_type == 11:
                dynsym_off = sh_offset
                dynsym_size = sh_size
                str_off = shoff + sh_link * (40 if ei_class == 1 else 64)
                if ei_class == 1:
                    str_shdr = struct.unpack_from(shdr_struct, self.raw, str_off)
                    str_offset = str_shdr[3]
                else:
                    str_shdr = struct.unpack_from(shdr_struct, self.raw, str_off)
                    str_offset = str_shdr[3]
            elif sh_type == 2:
                symtab_off = sh_offset
                symtab_size = sh_size
        if str_offset > 0:
            strtab = self.raw[str_offset:]
        else:
            return
        sym_off = dynsym_off or symtab_off
        sym_size = dynsym_size or symtab_size
        if not sym_off:
            return
        if ei_class == 1:
            sym_struct = endian + 'IIIBBH'
            sym_size_struct = 16
        else:
            sym_struct = endian + 'IIBBHQQ'
            sym_size_struct = 24
        for i in range(0, sym_size, sym_size_struct):
            if ei_class == 1:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(sym_struct, self.raw,
                                                                                             sym_off + i)
            else:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(sym_struct, self.raw,
                                                                                             sym_off + i)
            if st_value and (st_info & 0xf) == 2:
                name_end = strtab.find(b'\0', st_name)
                name = strtab[st_name:name_end].decode('ascii', errors='ignore')
                if name:
                    demangled = demangle_cpp(name)
                    self.symbols.append((st_value, demangled))
                    if sym_off == dynsym_off:
                        self.exports.append((st_value, demangled))

    def _try_parse_pe(self):
        if self.raw[:2] != b'MZ':
            return False
        try:
            pe = pefile.PE(data=self.raw)
        except:
            return False
        self.format = 'pe'
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            cor = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            if cor.Flags & 1:
                self.format = 'mono'
            else:
                self.format = 'il2cpp'
                self._load_il2cpp_metadata()
                if not self.il2cpp_meta:
                    self.format = 'pe'
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14c:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_32
        elif machine == 0x8664:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_64
        elif machine == 0x1c0:
            self.arch = CS_ARCH_ARM
            self.mode = CS_MODE_ARM
        elif machine == 0x1c4:
            self.arch = CS_ARCH_ARM
            self.mode = CS_MODE_THUMB
        elif machine == 0xaa64:
            self.arch = CS_ARCH_ARM64
            self.mode = CS_MODE_ARM64
        else:
            self.error = f"PE machine type {hex(machine)} unsupported"
            return True
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe.OPTIONAL_HEADER.AddressOfEntryPoint else None
        for sec in pe.sections:
            name = sec.Name.decode().rstrip('\x00')
            vaddr = self.base + sec.VirtualAddress
            raw_data = sec.get_data()
            size = sec.Misc_VirtualSize
            is_exec = bool(sec.Characteristics & 0x20000000)
            self.all_sections.append((name, vaddr, size, raw_data, is_exec))
            if is_exec and size > 0:
                self.sections.append((vaddr, size, raw_data))
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    addr = self.base + exp.address
                    name = exp.name if isinstance(exp.name, str) else exp.name.decode()
                    demangled = demangle_cpp(name)
                    self.symbols.append((addr, demangled))
                    self.exports.append((addr, demangled))
        if self.il2cpp_meta:
            for name, addr, sz in self.il2cpp_meta.methods:
                if addr:
                    self.symbols.append((addr + self.base, name))
        if self.entry and self.entry not in [s[0] for s in self.symbols]:
            self.symbols.append((self.entry, "entry"))
        return True

    def _load_il2cpp_metadata(self):
        base_dir = os.path.dirname(self.path)
        meta_path = os.path.join(base_dir, 'global-metadata.dat')
        if not os.path.exists(meta_path):
            for root, _, files in os.walk(base_dir):
                if 'global-metadata.dat' in files:
                    meta_path = os.path.join(root, 'global-metadata.dat')
                    break
        if os.path.exists(meta_path):
            with open(meta_path, 'rb') as f:
                self.il2cpp_meta = Il2CppMetadata(f.read())


class Disassembler:
    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        try:
            self.md = capstone.Cs(arch, mode)
            self.md.detail = True
        except:
            self.md = None
        self.insns = {}

    def disasm_section(self, code, base_addr):
        if not self.md:
            return
        for insn in self.md.disasm(code, base_addr):
            self.insns[insn.address] = insn


class BasicBlock:
    def __init__(self, start):
        self.start = start
        self.insns = []
        self.succs = []
        self.preds = []
        self.end = None


def is_branch_group(arch, insn):
    if arch == CS_ARCH_X86:
        return insn.group(x86_const.X86_GRP_JUMP) or insn.group(x86_const.X86_GRP_RET) or insn.group(
            x86_const.X86_GRP_CALL)
    elif arch == CS_ARCH_ARM:
        return (insn.group(arm_const.ARM_GRP_JUMP) or
                insn.mnemonic in ('bx', 'blx', 'pop', 'ldm') or
                insn.group(arm_const.ARM_GRP_CALL))
    elif arch == CS_ARCH_ARM64:
        return (insn.group(arm64_const.ARM64_GRP_JUMP) or
                insn.mnemonic == 'ret' or
                insn.group(arm64_const.ARM64_GRP_CALL))
    return False


def is_conditional_branch(arch, insn):
    if arch == CS_ARCH_X86:
        return insn.group(x86_const.X86_GRP_BRANCH_RELATIVE) and not insn.group(x86_const.X86_GRP_CALL)
    elif arch == CS_ARCH_ARM:
        if insn.group(arm_const.ARM_GRP_JUMP) and not insn.group(arm_const.ARM_GRP_CALL):
            return insn.mnemonic not in ('b', 'bx')
        return False
    elif arch == CS_ARCH_ARM64:
        if insn.group(arm64_const.ARM64_GRP_JUMP) and not insn.group(arm64_const.ARM64_GRP_CALL):
            return insn.mnemonic not in ('b', 'br', 'ret')
        return False
    return False


def is_unconditional_jump(arch, insn):
    if arch == CS_ARCH_X86:
        return (insn.group(x86_const.X86_GRP_JUMP) and
                not insn.group(x86_const.X86_GRP_BRANCH_RELATIVE) and
                not insn.group(x86_const.X86_GRP_CALL))
    elif arch == CS_ARCH_ARM:
        return insn.group(arm_const.ARM_GRP_JUMP) and insn.mnemonic == 'b'
    elif arch == CS_ARCH_ARM64:
        return insn.group(arm64_const.ARM64_GRP_JUMP) and insn.mnemonic == 'b'
    return False


def is_call_insn(arch, insn):
    if arch == CS_ARCH_X86:
        return insn.group(x86_const.X86_GRP_CALL)
    elif arch == CS_ARCH_ARM:
        return insn.mnemonic in ('bl', 'blx')
    elif arch == CS_ARCH_ARM64:
        return insn.mnemonic in ('bl', 'blr')
    return False


def find_all_functions(arch, insns, entry=None):
    func_starts = set()
    if entry and entry in insns:
        func_starts.add(entry)
    for addr, insn in insns.items():
        if is_call_insn(arch, insn):
            for op in insn.operands:
                if hasattr(op, 'imm') and op.imm in insns:
                    func_starts.add(op.imm)
        if is_unconditional_jump(arch, insn):
            for op in insn.operands:
                if hasattr(op, 'imm') and op.imm in insns:
                    func_starts.add(op.imm)
    return sorted(func_starts)


def build_cfg(arch, entry, insns):
    if entry not in insns:
        return []
    visited = {}
    blocks = []
    queue = [entry]
    while queue:
        addr = queue.pop(0)
        if addr in visited or addr not in insns:
            continue
        bb = BasicBlock(addr)
        cur = addr
        while cur in insns:
            insn = insns[cur]
            bb.insns.append(insn)
            if is_branch_group(arch, insn):
                break
            cur += insn.size
        bb.end = cur
        visited[addr] = bb
        blocks.append(bb)
        last = bb.insns[-1]
        if is_conditional_branch(arch, last):
            tgt = None
            if last.operands and hasattr(last.operands[0], 'imm'):
                tgt = last.operands[0].imm
            if tgt is not None and tgt not in visited:
                queue.append(tgt)
            fall = last.address + last.size
            if fall in insns and fall not in visited:
                queue.append(fall)
        elif is_unconditional_jump(arch, last):
            tgt = None
            if last.operands and hasattr(last.operands[0], 'imm'):
                tgt = last.operands[0].imm
            if tgt is not None and tgt not in visited:
                queue.append(tgt)
        elif not is_branch_group(arch, last):
            fall = last.address + last.size
            if fall in insns and fall not in visited:
                queue.append(fall)
    for bb in blocks:
        last = bb.insns[-1]
        if is_conditional_branch(arch, last):
            tgt = None
            if last.operands and hasattr(last.operands[0], 'imm'):
                tgt = last.operands[0].imm
            if tgt is not None and tgt in visited:
                bb.succs.append(visited[tgt])
                visited[tgt].preds.append(bb)
            fall = last.address + last.size
            if fall in visited:
                bb.succs.append(visited[fall])
                visited[fall].preds.append(bb)
        elif is_unconditional_jump(arch, last):
            tgt = None
            if last.operands and hasattr(last.operands[0], 'imm'):
                tgt = last.operands[0].imm
            if tgt is not None and tgt in visited:
                bb.succs.append(visited[tgt])
                visited[tgt].preds.append(bb)
        elif not is_branch_group(arch, last):
            fall = last.address + last.size
            if fall in visited:
                bb.succs.append(visited[fall])
                visited[fall].preds.append(bb)
    return blocks


def op_to_str(arch, insn, op):
    if arch == CS_ARCH_X86:
        if op.type == x86_const.X86_OP_REG:
            return insn.reg_name(op.reg)
        elif op.type == x86_const.X86_OP_IMM:
            return hex(op.imm) if abs(op.imm) > 9 else str(op.imm)
        elif op.type == x86_const.X86_OP_MEM:
            s = ''
            if op.mem.segment:
                s += insn.reg_name(op.mem.segment) + ':'
            if op.mem.base or op.mem.index:
                s += '['
                if op.mem.base: s += insn.reg_name(op.mem.base)
                if op.mem.index:
                    if op.mem.base: s += '+'
                    s += insn.reg_name(op.mem.index)
                    if op.mem.scale > 1: s += f'*{op.mem.scale}'
                if op.mem.disp:
                    sign = '+' if op.mem.disp >= 0 else '-'
                    s += f'{sign}{hex(abs(op.mem.disp))}'
                s += ']'
            else:
                if op.mem.disp:
                    s = f'[{hex(op.mem.disp)}]'
                else:
                    s = '[]'
            return s
    elif arch == CS_ARCH_ARM:
        if op.type == arm_const.ARM_OP_REG:
            return insn.reg_name(op.reg)
        elif op.type == arm_const.ARM_OP_IMM:
            return hex(op.imm) if abs(op.imm) > 9 else str(op.imm)
        elif op.type == arm_const.ARM_OP_MEM:
            base = insn.reg_name(op.mem.base) if op.mem.base != 0 else ''
            index = insn.reg_name(op.mem.index) if op.mem.index != 0 else ''
            disp = op.mem.disp
            result = '['
            if base: result += base
            if index:
                if base: result += ', '
                result += index
            if disp != 0:
                sign = '+' if disp >= 0 else '-'
                result += f', #{abs(disp)}'
            result += ']'
            return result
        elif op.type == arm_const.ARM_OP_FP:
            return f'#{op.fp}'
    elif arch == CS_ARCH_ARM64:
        if op.type == arm64_const.ARM64_OP_REG:
            return insn.reg_name(op.reg)
        elif op.type == arm64_const.ARM64_OP_IMM:
            return hex(op.imm) if abs(op.imm) > 9 else str(op.imm)
        elif op.type == arm64_const.ARM64_OP_MEM:
            base = insn.reg_name(op.mem.base) if op.mem.base != 0 else ''
            index = insn.reg_name(op.mem.index) if op.mem.index != 0 else ''
            disp = op.mem.disp
            result = '['
            if base: result += base
            if index:
                if base: result += ', '
                result += index
            if disp != 0:
                sign = '+' if disp >= 0 else '-'
                if not base and not index:
                    result += f'#{abs(disp)}'
                else:
                    result += f', #{abs(disp)}'
            result += ']'
            return result
        elif op.type == arm64_const.ARM64_OP_FP:
            return f'#{op.fp}'
    return op.str


def condition_str(arch, last, prev_insn):
    if arch == CS_ARCH_X86:
        cond_map = {
            'je': '==', 'jz': '==', 'jne': '!=', 'jnz': '!=',
            'jg': '>', 'jnle': '>', 'jge': '>=', 'jnl': '>=',
            'jl': '<', 'jnge': '<', 'jle': '<=', 'jng': '<=',
            'ja': '>', 'jnbe': '>', 'jae': '>=', 'jnb': '>=',
            'jb': '<', 'jnae': '<', 'jbe': '<=', 'jna': '<=',
            'jo': 'overflow', 'jno': '!overflow',
            'js': 'sign', 'jns': '!sign',
            'jpe': 'parity_even', 'jpo': 'parity_odd',
        }
        cond = cond_map.get(last.mnemonic, last.mnemonic)
        if prev_insn and prev_insn.mnemonic in ('cmp', 'test'):
            ops = prev_insn.operands
            if len(ops) >= 2:
                left = op_to_str(arch, prev_insn, ops[0])
                right = op_to_str(arch, prev_insn, ops[1])
                if prev_insn.mnemonic == 'cmp':
                    return f'({left} {cond} {right})'
                else:
                    return f'({left} & {right} {cond} 0)'
        return f'({last.mnemonic})'
    else:
        return f'({last.mnemonic} {last.op_str})'


def stmt_x86(arch, insn):
    m = insn.mnemonic
    o = insn.operands
    if m == 'mov' and len(o) == 2:
        return f'{op_to_str(arch, insn, o[0])} = {op_to_str(arch, insn, o[1])};'
    if m in ('add', 'sub', 'and', 'or', 'xor', 'adc', 'sbb') and len(o) == 2:
        return f'{op_to_str(arch, insn, o[0])} = {op_to_str(arch, insn, o[0])} {m} {op_to_str(arch, insn, o[1])};'
    if m in ('inc', 'dec', 'neg', 'not') and len(o) == 1:
        op_map = {'inc': '+', 'dec': '-', 'neg': '-', 'not': '~'}
        return f'{op_to_str(arch, insn, o[0])} = {op_map.get(m, m)}{op_to_str(arch, insn, o[0])};'
    if m == 'mul' and len(o) == 1:
        return f'eax = eax * {op_to_str(arch, insn, o[0])};'
    if m == 'imul':
        if len(o) == 1:
            return f'eax = eax * {op_to_str(arch, insn, o[0])};'
        elif len(o) == 2:
            return f'{op_to_str(arch, insn, o[0])} = {op_to_str(arch, insn, o[0])} * {op_to_str(arch, insn, o[1])};'
        elif len(o) == 3:
            return f'{op_to_str(arch, insn, o[0])} = {op_to_str(arch, insn, o[1])} * {op_to_str(arch, insn, o[2])};'
    if m == 'div' and len(o) == 1:
        return f'eax = eax / {op_to_str(arch, insn, o[0])};'
    if m == 'idiv' and len(o) == 1:
        return f'eax = eax / {op_to_str(arch, insn, o[0])};'
    if m == 'lea' and len(o) == 2:
        return f'{op_to_str(arch, insn, o[0])} = &{op_to_str(arch, insn, o[1])};'
    if m == 'cmp' and len(o) == 2:
        return f'// cmp {op_to_str(arch, insn, o[0])}, {op_to_str(arch, insn, o[1])}'
    if m == 'test' and len(o) == 2:
        return f'// test {op_to_str(arch, insn, o[0])}, {op_to_str(arch, insn, o[1])}'
    if m in ('shl', 'shr', 'sal', 'sar', 'rol', 'ror') and len(o) == 2:
        return f'{op_to_str(arch, insn, o[0])} = {op_to_str(arch, insn, o[0])} {m} {op_to_str(arch, insn, o[1])};'
    if m == 'push':
        return f'push({op_to_str(arch, insn, o[0])});'
    if m == 'pop':
        return f'{op_to_str(arch, insn, o[0])} = pop();'
    if m == 'call':
        target = op_to_str(arch, insn, o[0]) if o else ''
        return f'call {target};'
    if m == 'ret':
        return 'return;'
    if m == 'nop':
        return ';'
    if m in ('movsx', 'movsxd'):
        return f'{op_to_str(arch, insn, o[0])} = (int64_t)(int32_t){op_to_str(arch, insn, o[1])};'
    if m == 'movzx':
        return f'{op_to_str(arch, insn, o[0])} = (uint64_t){op_to_str(arch, insn, o[1])};'
    if m == 'cdqe':
        return 'rax = (int64_t)(int32_t)eax;'
    if m == 'cqo':
        return 'rdx = rax >> 63;'
    return f'{m} {", ".join(op_to_str(arch, insn, op) for op in o)};'


def stmt_from_insn(arch, insn):
    if arch == CS_ARCH_X86:
        return stmt_x86(arch, insn)
    elif arch in (CS_ARCH_ARM, CS_ARCH_ARM64):
        return f'{insn.mnemonic} {", ".join(op_to_str(arch, insn, op) for op in insn.operands)};'
    return f'{insn.mnemonic} {insn.op_str};'


def generate_structured_code(arch, blocks, insns, functions):
    func_map = {addr: name for addr, name in functions}
    indent = 0
    lines = []

    def add_line(text):
        lines.append('    ' * indent + text)

    def process_block(bb, visited=None):
        nonlocal indent
        if visited is None:
            visited = set()
        if bb.start in visited:
            return
        visited.add(bb.start)

        for insn in bb.insns[:-1]:
            stmt = stmt_from_insn(arch, insn)
            stmt = make_clickable_calls(stmt, func_map)
            add_line(stmt)

        last = bb.insns[-1]

        if is_conditional_branch(arch, last):
            prev = bb.insns[-2] if len(bb.insns) >= 2 else None
            true_tgt = None
            if last.operands and hasattr(last.operands[0], 'imm'):
                true_tgt = last.operands[0].imm
            cond = condition_str(arch, last, prev)
            fall = last.address + last.size

            true_bb = next((s for s in bb.succs if s.start == true_tgt), None)
            false_bb = next((s for s in bb.succs if s.start == fall), None)

            if true_bb and false_bb:
                add_line(f'if {cond} {{')
                indent += 1
                process_block(true_bb, visited.copy())
                indent -= 1
                add_line('} else {')
                indent += 1
                process_block(false_bb, visited.copy())
                indent -= 1
                add_line('}')
            elif true_bb:
                add_line(f'if {cond} {{')
                indent += 1
                process_block(true_bb, visited.copy())
                indent -= 1
                add_line('}')
            else:
                add_line(f'if {cond} {{ /* ... */ }}')

        elif is_unconditional_jump(arch, last):
            tgt = None
            if last.operands and hasattr(last.operands[0], 'imm'):
                tgt = last.operands[0].imm
            target_bb = next((s for s in bb.succs if s.start == tgt), None)
            if target_bb:
                process_block(target_bb, visited)

        elif is_branch_group(arch, last) and last.mnemonic == 'ret':
            add_line('return;')
        else:
            stmt = stmt_from_insn(arch, last)
            stmt = make_clickable_calls(stmt, func_map)
            add_line(stmt)
            if bb.succs:
                for succ in bb.succs:
                    process_block(succ, visited.copy())

    if blocks:
        process_block(blocks[0])

    return '\n'.join(lines)


def make_clickable_calls(stmt, func_map):
    if 'call 0x' in stmt:
        parts = stmt.split('call ')
        if len(parts) == 2:
            addr_str = parts[1].replace(';', '').strip()
            if addr_str.startswith('0x'):
                try:
                    addr = int(addr_str, 16)
                    target_name = func_map.get(addr, f'sub_{addr:x}')
                    return f'{parts[0]}call <a href="#{target_name}">{target_name}</a>;'
                except:
                    pass
    return stmt


def escape_html(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


class DecompilerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DroidDisasmbler")
        self.resize(1400, 800)
        self.binary = None
        self.disasm = None
        self.functions = []
        self.custom_names = {}
        self.current_theme = "dark"
        self.search_timer = QTimer()
        self.search_timer.setSingleShot(True)
        self.search_timer.timeout.connect(self._do_search)

        self._create_actions()
        self._create_menu()
        self._create_toolbar()
        self._create_central_widget()
        self._create_status_bar()
        self._apply_theme("dark")

    def _create_actions(self):
        self.open_action = QAction("Открыть файл...", self)
        self.open_action.triggered.connect(self.open_file)
        self.exit_action = QAction("Выход", self)
        self.exit_action.triggered.connect(self.close)
        self.export_action = QAction("Экспорт...", self)
        self.export_action.triggered.connect(self.export_code)
        self.rename_action = QAction("Переименовать функцию", self)
        self.rename_action.triggered.connect(self.rename_function)
        self.dark_theme_action = QAction("Тёмная тема", self)
        self.dark_theme_action.triggered.connect(lambda: self._apply_theme("dark"))
        self.light_theme_action = QAction("Светлая тема", self)
        self.light_theme_action.triggered.connect(lambda: self._apply_theme("light"))
        self.font_action = QAction("Шрифт...", self)
        self.font_action.triggered.connect(self._choose_font)

    def _create_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("Файл")
        file_menu.addAction(self.open_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        edit_menu = menubar.addMenu("Правка")
        edit_menu.addAction(self.rename_action)
        view_menu = menubar.addMenu("Вид")
        themes_menu = view_menu.addMenu("Тема")
        themes_menu.addAction(self.dark_theme_action)
        themes_menu.addAction(self.light_theme_action)
        view_menu.addAction(self.font_action)
        tools_menu = menubar.addMenu("Инструменты")
        tools_menu.addAction(self.export_action)

    def _create_toolbar(self):
        tb = QToolBar("Основная")
        self.addToolBar(tb)
        tb.addAction(self.open_action)
        tb.addAction(self.rename_action)
        tb.addAction(self.export_action)
        tb.addSeparator()
        tb.addWidget(QLabel("Поиск: "))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Alt+T для поиска функций...")
        self.search_box.textChanged.connect(self._on_search_text_changed)
        tb.addWidget(self.search_box)
        QShortcut(QKeySequence("Alt+T"), self, activated=self.search_box.setFocus)

    def _create_central_widget(self):
        main_splitter = QSplitter(Qt.Vertical)
        top_splitter = QSplitter(Qt.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.tab_widget = QTabWidget()

        func_widget = QWidget()
        func_layout = QVBoxLayout(func_widget)
        self.func_tree = QTreeWidget()
        self.func_tree.setHeaderLabels(["Адрес", "Имя"])
        self.func_tree.setColumnWidth(0, 120)
        self.func_tree.itemClicked.connect(self.on_function_selected)
        func_layout.addWidget(QLabel("Функции:"))
        func_layout.addWidget(self.func_tree)

        exp_widget = QWidget()
        exp_layout = QVBoxLayout(exp_widget)
        self.exp_tree = QTreeWidget()
        self.exp_tree.setHeaderLabels(["Адрес", "Имя"])
        self.exp_tree.setColumnWidth(0, 120)
        self.exp_tree.itemClicked.connect(self.on_export_selected)
        exp_layout.addWidget(QLabel("Экспорты:"))
        exp_layout.addWidget(self.exp_tree)

        sec_widget = QWidget()
        sec_layout = QVBoxLayout(sec_widget)
        self.sec_tree = QTreeWidget()
        self.sec_tree.setHeaderLabels(["Имя", "VAddr", "Размер", "Флаги"])
        self.sec_tree.itemClicked.connect(self.on_section_selected)
        sec_layout.addWidget(QLabel("Секции:"))
        sec_layout.addWidget(self.sec_tree)

        self.tab_widget.addTab(func_widget, "Функции")
        self.tab_widget.addTab(exp_widget, "Экспорты")
        self.tab_widget.addTab(sec_widget, "Секции")
        left_layout.addWidget(self.tab_widget)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(QLabel("Псевдокод:"))
        self.code_browser = QTextBrowser()
        self.code_browser.setOpenLinks(False)
        self.code_browser.anchorClicked.connect(self.on_anchor_clicked)
        right_layout.addWidget(self.code_browser)

        top_splitter.addWidget(left_widget)
        top_splitter.addWidget(right_widget)
        top_splitter.setSizes([350, 1050])

        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        bottom_layout.addWidget(QLabel("Лог:"))
        bottom_layout.addWidget(self.log_edit)

        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(bottom_widget)
        main_splitter.setSizes([600, 150])

        self.setCentralWidget(main_splitter)

    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов")

    def _apply_theme(self, theme):
        self.current_theme = theme
        if theme == "dark":
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(43, 43, 43))
            palette.setColor(QPalette.WindowText, QColor(212, 212, 212))
            palette.setColor(QPalette.Base, QColor(30, 30, 30))
            palette.setColor(QPalette.AlternateBase, QColor(43, 43, 43))
            palette.setColor(QPalette.Text, QColor(212, 212, 212))
            palette.setColor(QPalette.Button, QColor(62, 62, 62))
            palette.setColor(QPalette.ButtonText, QColor(212, 212, 212))
            palette.setColor(QPalette.Highlight, QColor(62, 62, 62))
            palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            self.setPalette(palette)
            self.code_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: #1e1e1e;
                    color: #dcdcaa;
                    font-family: 'Consolas', monospace;
                    font-size: 12px;
                }
                a { color: #569cd6; }
            """)
            self.log_edit.setStyleSheet("background-color: #1e1e1e; color: #dcdcaa;")
        else:
            self.setPalette(QApplication.style().standardPalette())
            self.code_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: white;
                    color: black;
                    font-family: 'Consolas', monospace;
                    font-size: 12px;
                }
                a { color: blue; }
            """)
            self.log_edit.setStyleSheet("")

    def _choose_font(self):
        font, ok = QFontDialog.getFont(self.code_browser.font(), self)
        if ok:
            self.code_browser.setFont(font)

    def log(self, msg):
        self.log_edit.append(msg)

    def _on_search_text_changed(self, text):
        self.search_timer.start(200)

    def _do_search(self):
        text = self.search_box.text().lower()
        if not text:
            for i in range(self.func_tree.topLevelItemCount()):
                self.func_tree.topLevelItem(i).setHidden(False)
            for i in range(self.exp_tree.topLevelItemCount()):
                self.exp_tree.topLevelItem(i).setHidden(False)
            return
        for i in range(self.func_tree.topLevelItemCount()):
            item = self.func_tree.topLevelItem(i)
            item.setHidden(text not in item.text(1).lower())
        for i in range(self.exp_tree.topLevelItemCount()):
            item = self.exp_tree.topLevelItem(i)
            item.setHidden(text not in item.text(1).lower())

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Открыть библиотеку", "", "Библиотеки (*.so *.dll);;Все (*.*)")
        if not path:
            return
        self.log(f"Открытие: {path}")
        self.binary = BinaryFile(path)
        if self.binary.error:
            QMessageBox.critical(self, "Ошибка", self.binary.error)
            self.log(f"Ошибка: {self.binary.error}")
            return
        if self.binary.format in ('mono', 'il2cpp'):
            self._load_managed()
            self._populate_sections()
            return
        self.disasm = Disassembler(self.binary.arch, self.binary.mode)
        for vaddr, size, code in self.binary.sections:
            self.disasm.disasm_section(code, vaddr)
        for addr, name in self.binary.exports:
            if addr not in self.disasm.insns:
                for vaddr, size, data in self.binary.sections:
                    if vaddr <= addr < vaddr + size:
                        offset = addr - vaddr
                        chunk = data[offset:offset + 4096]
                        self.disasm.disasm_section(chunk, addr)
                        break
        self.custom_names.clear()
        self._load_functions()
        self._populate_sections()
        self._populate_exports()
        self.status_bar.showMessage(f"Загружен: {os.path.basename(path)} | Функций: {len(self.functions)}")
        self.log(f"Загружен: архитектура {self.binary.arch}, режим {self.binary.mode}")
        self.code_browser.clear()

    def _load_managed(self):
        self.func_tree.clear()
        self.functions = []
        if self.binary.format == 'il2cpp' and self.binary.il2cpp_meta:
            for name, addr, sz in self.binary.il2cpp_meta.methods:
                if addr:
                    self.functions.append((addr, name))
            self.functions.sort(key=lambda x: x[0])
            for addr, name in self.functions:
                item = QTreeWidgetItem([f'0x{addr:x}', name])
                self.func_tree.addTopLevelItem(item)
            self.status_bar.showMessage(f"IL2CPP: {len(self.functions)} методов")
            self.disasm = Disassembler(CS_ARCH_X86, CS_MODE_64)
            for vaddr, size, code in self.binary.sections:
                self.disasm.disasm_section(code, vaddr)
        elif self.binary.format == 'mono':
            self.code_browser.setHtml("<p>Mono/.NET управляемый код не поддерживается.</p>")
            self.status_bar.showMessage("Mono сборка")
            self.log("Mono сборка не поддерживается")

    def _load_functions(self):
        self.func_tree.clear()
        self.functions = []
        arch = self.disasm.arch
        for addr, name in self.binary.symbols:
            if addr in self.disasm.insns:
                display_name = self.custom_names.get(addr, name)
                self.functions.append((addr, display_name))
        extra_funcs = find_all_functions(arch, self.disasm.insns, self.binary.entry)
        for addr in extra_funcs:
            if not any(a == addr for a, _ in self.functions):
                display_name = self.custom_names.get(addr, f"sub_{addr:x}")
                self.functions.append((addr, display_name))
        self.functions.sort(key=lambda x: x[0])
        for addr, name in self.functions:
            item = QTreeWidgetItem([f'0x{addr:x}', name])
            self.func_tree.addTopLevelItem(item)

    def _populate_sections(self):
        self.sec_tree.clear()
        if not self.binary:
            return
        for name, vaddr, size, data, is_exec in self.binary.all_sections:
            flags = 'X' if is_exec else 'R/W'
            item = QTreeWidgetItem([name, f'0x{vaddr:x}', hex(size), flags])
            self.sec_tree.addTopLevelItem(item)

    def _populate_exports(self):
        self.exp_tree.clear()
        if not self.binary:
            return
        for addr, name in self.binary.exports:
            display_name = self.custom_names.get(addr, name)
            item = QTreeWidgetItem([f'0x{addr:x}', display_name])
            self.exp_tree.addTopLevelItem(item)
        if self.binary.entry:
            display_name = self.custom_names.get(self.binary.entry, "entry")
            item = QTreeWidgetItem([f'0x{self.binary.entry:x}', display_name])
            self.exp_tree.addTopLevelItem(item)

    def on_function_selected(self, item, col):
        if not self.disasm:
            return
        addr_str = item.text(0)
        addr = int(addr_str, 16)
        self._decompile(addr)

    def on_export_selected(self, item, col):
        if not self.disasm:
            return
        addr_str = item.text(0)
        addr = int(addr_str, 16)
        self._decompile(addr)

    def _decompile(self, addr):
        insns = self.disasm.insns
        if addr not in insns:
            self.code_browser.setHtml("<p>Адрес не содержит кода</p>")
            return
        arch = self.disasm.arch
        blocks = build_cfg(arch, addr, insns)
        if not blocks:
            self.code_browser.setHtml("<p>Не удалось построить граф потока управления</p>")
            return
        func_name = next((n for a, n in self.functions if a == addr), f"sub_{addr:x}")
        pseudocode = generate_structured_code(arch, blocks, insns, self.functions)
        html = f'<h3>void {escape_html(func_name)}()</h3>\n<pre>{pseudocode}</pre>'
        self.code_browser.setHtml(html)

    def rename_function(self):
        sel = self.func_tree.selectedItems() or self.exp_tree.selectedItems()
        if not sel:
            QMessageBox.warning(self, "Переименование", "Выберите функцию в дереве")
            return
        item = sel[0]
        old_addr = int(item.text(0), 16)
        old_name = item.text(1)
        new_name, ok = QInputDialog.getText(self, "Переименовать", "Новое имя:", QLineEdit.Normal, old_name)
        if ok and new_name:
            self.custom_names[old_addr] = new_name
            for i in range(len(self.functions)):
                if self.functions[i][0] == old_addr:
                    self.functions[i] = (old_addr, new_name)
                    break
            item.setText(1, new_name)
            self._decompile(old_addr)

    def on_anchor_clicked(self, url):
        fragment = url.fragment()
        if fragment.startswith('sub_') or fragment.startswith('func_'):
            try:
                addr = int(fragment.split('_', 1)[1], 16)
            except:
                for a, n in self.functions:
                    if n == fragment:
                        addr = a
                        break
                else:
                    return
            if addr in self.disasm.insns:
                self._decompile(addr)
                for i in range(self.func_tree.topLevelItemCount()):
                    item = self.func_tree.topLevelItem(i)
                    if int(item.text(0), 16) == addr:
                        self.func_tree.setCurrentItem(item)
                        break

    def on_section_selected(self, item, col):
        if not self.binary:
            return
        name = item.text(0)
        sec = next((s for s in self.binary.all_sections if s[0] == name), None)
        if sec:
            _, vaddr, size, data, _ = sec
            dump = self._hexdump(data, vaddr)
            self.code_browser.setPlainText(f"Секция {name} (0x{vaddr:x} - 0x{vaddr + size:x})\n\n{dump}")

    def _hexdump(self, data, base=0):
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexa = ' '.join(f'{b:02x}' for b in chunk)
            ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{base + i:08x}  {hexa:<48}  {ascii}')
        return '\n'.join(lines)

    def export_code(self):
        text = self.code_browser.toPlainText()
        if not text.strip():
            QMessageBox.warning(self, "Экспорт", "Нет кода")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", "", "C файлы (*.c);;Текстовые (*.txt)")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            self.status_bar.showMessage(f"Сохранено в {path}")


def main():
    app = QApplication(sys.argv)
    window = DecompilerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
