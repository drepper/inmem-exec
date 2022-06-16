#!/usr/bin/env python3
import math
import ctypes
import enum
import os
import platform
import fnmatch
import resource
import sys
import locale
import ast
import copy
from dataclasses import dataclass


@enum.unique
class RegType(enum.Enum):
    none = 0
    int8 = 1
    int16 = 2
    int32 = 3
    int64 = 4
    uint8 = 5
    uint16 = 6
    uint32 = 7
    uint64 = 8
    ptr = 9
    float32 = 10
    float64 = 11


def get_type(value):
    match value:
        case ast.Constant(value):
            if type(value) == int:
                return RegType.int32 if value >= -2**31 and value < 2**31 else RegType.int64
            if type(value) == str:
                return RegType.ptr
            if type(value) == float:
                return RegType.float64
        case str(s):
            return RegType[s]
    raise RuntimeError(f'invalid value type {type(value)}')


def get_type_size(t: RegType):
    match t:
        case RegType.int8 | RegType.uint8:
            return 1
        case RegType.int16 | RegType.uint16:
            return 2
        case RegType.int32 | RegType.uint32 | RegType.float32 | RegType.ptr:
            return 4
        case RegType.int64 | RegType.uint64 | RegType.float64:
            return 8
        case _:
            raise RuntimeError(f'no size for type {t}')

def type_is_int(t: RegType):
    return t != RegType.none and t != RegType.float32 and t != RegType.float64


@enum.unique
class RelType(enum.Enum):
    none = 0
    abs4 = 1
    rvhi = 2
    rvlo = 3
    rvlo2 = 4
    armmovwabs = 5
    armmovtabs = 6
    aarch64lo16abs = 7
    aarch64hi16abs = 8
    rel4a = 9
    rvjal = 10
    armb24 = 11
    aarch64bc19 = 12
    aarch64b26 = 13


@dataclass
class Symbol:
    name: str
    size: int
    stype: RegType
    section: bytes
    addr: int


@dataclass
class Relocation:
    symref: str
    section: bytes
    offset: int
    reltype: RelType


class RegMask(object):
    def __init__(self, **kwargs):
        if 'n' in kwargs:
            self.n = kwargs['n']
            self.a = [ False ] * self.n
        elif 'src' in kwargs and type(kwargs['src']) == RegMask:
            self.n = kwargs['src'].n
            self.a = kwargs['src'].a.copy()
        else:
            raise RuntimeError('invalid constructor for RegMask')

    def __setitem__(self, key, val):
        if type(key) == slice:
            r = range(key.start if key.start else 0, key.stop if key.stop else len(self.a), key.step if key.step else 1)
            if type(val) == list:
                for i,ii in enumerate(r):
                    self.a[ii] = val[i % len(val)]
            else:
                for ii in r:
                    self.a[ii] = val
        else:
            self.a[key] = val

    def __getitem__(self, key):
        return self.a[key]


class RegAlloc(object):
    def __init__(self, first_int, n_int_regs, first_fp, n_fp_regs):
        n_regs = self.n_int_regs + self.n_fp_regs
        self.int_regs_mask = RegMask(n=n_regs)
        self.int_regs_mask[first_int:n_int_regs] = True
        self.fp_regs_mask = RegMask(n=n_regs)
        self.fp_regs_mask[n_int_regs+first_fp:] = True
        self.cur_used = RegMask(n=n_regs)

    def clear_used(self, parmregs):
        self.cur_used[:] = False
        for reg in parmregs:
            if reg.is_int:
                self.cur_used[reg.n]  = True
            else:
                self.cur_used[self.n_int_regs + reg.n] = True


    def get_unused_reg(self, regtype):
        match regtype:
            case RegType.int32 | RegType.int64 | RegType.ptr:
                mask = self.int_regs_mask
            case RegType.float32 | RegType.float64:
                mask = self.fp_regs_mask
            case _:
                raise RuntimeError(f'invalid register type {regtype}')
        for i,u in enumerate(self.cur_used):
            if not u and mask[i]:
                self.cur_used[i] = True
                return Register(regtype, i if i < self.n_int_regs else (i - self.n_int_regs))
        raise RuntimeError('too many registers used')

    def mark_used(self, reg):
        if reg.is_int:
            assert not self.cur_used[reg.n]
            self.cur_used[reg.n] = True
        else:
            assert not self.cur_used[len(self.int_regs_mask) + reg.n]
            self.cur_used[len(self.int_regs_mask) + reg.n] = True

    def release_reg(self, reg):
        self.cur_used[reg.n] = False


class Register(object):
    __match_args__ = ('is_int', 'n')
    def __init__(self, regtype: RegType, n: int):
        assert type(n) == int
        self.is_int = regtype == RegType.int32 or regtype == RegType.int64 or regtype == RegType.ptr
        self.n = n
    def __str__(self):
        return f'is_int={self.is_int}, n={self.n}'


class StackSlot(object):
    __match_args__ = ('is_int', 'offset')
    def __init__(self, is_int: bool, offset: int):
        self.is_int = is_int
        self.offset = offset
    def __str__(self):
        return f'is_int={self.is_int}, offset={self.offset}'


class Flags(object):
    __match_args__ = ('op', 'reg')
    def __init__(self, op, reg):
        self.op = op
        self.reg = reg


class elfdef(object):
    EV_CURRENT = 1
    ET_EXEC = 2
    C_WRITE = 3
    EI_CLASS = 4
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    EI_DATA = 5
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2
    EI_VERSION = 6
    EI_OSABI = 7
    ELFOSABI_NONE = 0
    EI_ABIVERSION = 8
    EM_386 = 3
    EM_ARM = 40
    EM_X86_64 = 62
    EM_AARCH64 = 183
    EM_RISCV = 243
    SHT_PROGBITS = 1
    SHT_STRTAB = 3
    SHF_WRITE = 1
    SHF_ALLOC = 2
    SHF_EXECINSTR = 4
    ELF_T_BYTE = 0
    ELF_C_NULL = 0
    ELF_C_WRITE_MMAP = 10
    PT_LOAD = 1
    PF_R = 4
    PF_W = 2
    PF_X = 1


class x86_64_encoding(RegAlloc):
    nbits = 64           # processor bits
    elf_machine = elfdef.EM_X86_64

    n_int_regs = 16
    n_fp_regs = 16

    rAX = 0b0000
    rCX = 0b0001
    rDX = 0b0010
    rBX = 0b0011
    rSP = 0b0100
    rBP = 0b0101
    rSI = 0b0110
    rDI = 0b0111
    r8  = 0b1000
    r9  = 0b1001
    r10 = 0b1010
    r11 = 0b1011
    r12 = 0b1100
    r13 = 0b1101
    r14 = 0b1110
    r15 = 0b1111
    rXMM0 = 0b0000
    rXMM1 = 0b0001
    rXMM2 = 0b0010
    rXMM3 = 0b0011
    rXMM4 = 0b0100
    rXMM5 = 0b0101
    rXMM6 = 0b0110
    rXMM7 = 0b0111

    def __init__(self):
        super().__init__(0, self.n_int_regs, 0, self.n_fp_regs)

    function_int_arg_regs = [
        rAX,
        rDI,
        rSI,
        rDX,
        rCX,
        r8,
        r9
    ]
    function_fp_arg_regs = [
        rXMM0,
        rXMM1,
        rXMM2,
        rXMM3,
        rXMM4,
        rXMM5,
        rXMM6,
        rXMM7
    ]
    @classmethod
    def get_function_int_arg_reg(cls, nr):
        return Register(RegType.int64, cls.function_int_arg_regs[nr])
    @classmethod
    def get_function_fp_arg_reg(cls, nr):
        return Register(RegType.float64, cls.function_fp_arg_regs[nr])

    @classmethod
    def get_function_res_reg(cls, is_int):
        if is_int:
            return Register(RegType.int64, cls.function_int_arg_regs[0])
        else:
            return Register(RegType.float64, cls.function_fp_arg_regs[0])

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        if reg.is_int:
            rex = 0x41 if reg.n >= 8 else 0
            if (val < -2147483648 or val > 2147483647) if signed else val > 4294967295:
                rex |= 0x48
                valwidth = 8
            else:
                valwidth = 4
            res = (rex.to_bytes(1, 'little') if rex else b'') + (0xb8 + (reg.n & 0b111)).to_bytes(1, 'little') + val.to_bytes(valwidth, 'little')
            return res
        else:
            raise NotImplementedError('fp loadimm not yet handled')

    @classmethod
    def gen_loadmem(cls, reg, width):
        if reg.is_int:
            rex = 0x44 if reg.n >= 8 else 0
            if width > 4:
                rex |= 0x48
            res = (rex.to_bytes(1, 'little') if rex else b'') + b'\x8b' + (0x04 + ((reg.n & 0b111) << 3)).to_bytes(1, 'little') + b'\x25' + b'\x00\x00\x00\x00'
            return [ (res, (4 if rex else 3), RelType.abs4) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @staticmethod
    def gen_loadref(reg, offset):
        # We always assume a small memory model, references are 4 bytes
        assert reg.is_int
        rex = 0x41 if reg.n >= 8 else 0
        res = (rex.to_bytes(1, 'little') if rex else b'') + (0xb8 + (reg.n & 0b111)).to_bytes(1, 'little') + offset.to_bytes(4, 'little')
        return [ (res, (2 if rex else 1), RelType.abs4) ]

    @classmethod
    def gen_saveimm(cls, val, width):
        if type(val.value) != int or width > 4:
            return None
        if width == 4:
            res = b'\xc7'
        elif width == 2:
            res = b'\x66\xc7'
        else:
            res = b'\xc6'
        off = 2 + len(res)
        res += b'\x04\x25\x00\x00\x00\x00' + val.value.to_bytes(width, 'little')
        return [ (res, off, RelType.abs4) ]

    @classmethod
    def gen_aug_saveimm(cls, op, val, width):
        if type(val.value) != int or val.value < -2^31 or val.value >= 2^31:
            return None
        match op:
            case ast.Add():
                op = b'\x04'
            case _:
                return None
        is_imm8 = val.value >= -128 and val.value < 128
        if width == 8:
            res = b'\x48\x83' if is_imm8 else b'\x48\x81'
        elif width == 4:
            res = b'\x83' if is_imm8 else b'\x81'
        elif width == 2:
            res = b'\x66\x83' if is_imm8 else b'\x81'
        else:
            res = b'\x82'
        off = 2 + len(res)
        res += op + b'\x25\x00\x00\x00\x00' + val.value.to_bytes(1 if is_imm8 else min(4, width), 'little')
        return [ (res, off, RelType.abs4) ]

    @classmethod
    def gen_savemem(cls, reg, width):
        if reg.is_int:
            rex = 0x44 if reg.n >= 8 else 0
            if width > 4:
                rex |= 0x48
            res = (rex.to_bytes(1, 'little') if rex else b'') + b'\x89' + (0x04 + ((reg.n & 0b111) << 3)).to_bytes(1, 'little') + b'\x25' + b'\x00\x00\x00\x00'
            return [ (res, (4 if rex else 3), RelType.abs4) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @classmethod
    def gen_aug_savemem(cls, op, reg, width):
        match op:
            case ast.Add():
                res = b'\x02' if width == 1 else b'\x01'
            case ast.Sub():
                res = b'\x2a' if width == 1 else b'\x29'
            case _:
                return None
        if width == 8:
            res = b'\x48' + res
        elif width == 2:
            res = b'\66' + res
        off = 2 + len(res)
        res += (0x04 | ((reg.n & 0b111) << 3)).to_bytes(1, 'little') + b'\x25\x00\x00\x00\x00'
        return [ (res, off, RelType.abs4) ]

    def gen_binop(self, resreg, rreg, op):
        if resreg.is_int:
            assert rreg.is_int
            res = (0x48 | (1 if resreg.n >= 8 else 0) | (4 if rreg.n >= 8 else 0)).to_bytes(1, 'little')
            match op:
                # XYZ always 64-bit operation
                case ast.Add():
                    res += b'\x01'
                case ast.Sub():
                    res += b'\x29'
                case ast.BitAnd():
                    res += b'\x21'
                case ast.BitOr():
                    res += b'\x09'
                case ast.BitXor():
                    res += b'\x31'
                case _:
                    raise NotImplementedError(f'unsupported binop {op}')
            res += (0xc0 + (rreg.n << 3) + resreg.n).to_bytes(1, 'little')
            self.release_reg(rreg)
            return res
        else:
            assert not resreg.is_int
            assert not rreg.is_int
            raise NotImplementedError('fp binop not yet implemented')

    def gen_compare(self, l, r, op, condjmpctx):
        if l.is_int:
            assert r.is_int
            res = (0x48 | (1 if l.n >= 8 else 0) | (4 if r.n >= 8 else 0)).to_bytes(1, 'little')
            res += b'\x39' + (0xc0 + (r.n << 3) + l.n).to_bytes(1, 'little')
            self.release_reg(l)
            self.release_reg(r)
            return res, None
        else:
            assert not l.is_int
            assert not r.is_int
            raise NotImplementedError('fp compare not yet implemented')

    def gen_store_flag(self, op, reg):
        if not reg:
            reg = self.get_unused_reg(RegType.int64)
        res = self.gen_loadimm(reg, 0)
        if reg.n >= 8:
            res += b'\x41'
        res += b'\x0f'
        match op:
            case ast.Eq():
                res += b'\x94'
            case ast.NotEq():
                res += b'\x95'
            case _:
                raise NotImplementedError(f'unsupported comparison {op}')
        res += (0xc0 + (reg.n & 0b111)).to_bytes(1, 'little')
        return res, reg

    @staticmethod
    def gen_condjump(curoff, flags, exp, lab):
        res = b'\x0f'
        match (flags.op, exp):
            case (ast.Eq(), False) | (ast.NotEq(), True):
                res += b'\x85'
            case (ast.Eq(), True) | (ast.NotEq(), False):
                res += b'\x84'
            case _:
                raise NotImplementedError(f'unhandled condjump {flags.op}/{exp}')
        return [ (res + b'\x00\x00\x00\x00', Relocation(lab, b'.text', curoff + 2, RelType.rel4a)) ]

    @staticmethod
    def gen_jump(curoff, lab):
        return [ (b'\xe9\x00\x00\x00\x00', Relocation(lab, b'.text', curoff + 1, RelType.rel4a)) ]

    @staticmethod
    def gen_call(curoff, lab):
        return [ (b'\xe8\x00\x00\x00\x00', Relocation(lab, b'.text', curoff + 1, RelType.rel4a)) ]

    @staticmethod
    def gen_return():
        return b'\xc3'

    @staticmethod
    def gen_create_stackframe():
        return b'\x55\x48\x89\xe5'

    @staticmethod
    def gen_destroy_stackframe():
        return b'\xc9'

    @staticmethod
    def gen_frame_store(reg):
        if reg.is_int:
            res = b'\x41' if reg.n >= 8 else b''
            res += (0x50 + (reg.n & 0b111)).to_bytes(1, 'little')
            return res, 8
        else:
            raise NotImplementedError(f'store fp on stack frame not supported')

    @staticmethod
    def gen_frame_load(reg, offset):
        assert offset > 0
        if reg.is_int:
            res = (b'\x48' if reg.n < 8 else b'\x4c') + b'\x8b'
            if offset <= 128:
                res += (0x45 + ((reg .n & 0b111) << 3)).to_bytes(1, 'little') + (-offset).to_bytes(1, 'little', signed=True)
            else:
                res += (0x85 + ((reg .n & 0b111) << 3)).to_bytes(1, 'little') + (-offset).to_bytes(4, 'little', signed=True)
        else:
            raise NotImplementedError(f'load fp from frame not supported')
        return res

class i386_encoding(RegAlloc):
    nbits = 32           # processor bits
    elf_machine = elfdef.EM_386

    n_int_regs = 8
    n_fp_regs = 8

    rAX = 0b000
    rCX = 0b001
    rDX = 0b010
    rBX = 0b011
    rSP = 0b100
    rBP = 0b101
    rSI = 0b110
    rDI = 0b111
    rXMM0 = 0b000
    rXMM1 = 0b001
    rXMM2 = 0b010
    rXMM3 = 0b011
    rXMM4 = 0b100
    rXMM5 = 0b101
    rXMM6 = 0b110
    rXMM7 = 0b111

    def __init__(self):
        super().__init__(0, self.n_int_regs, 0, self.n_fp_regs)

    function_int_arg_regs = [
        rAX,
        rDI,
        rSI,
        rDX,
        rCX,
        rBP
    ]
    function_fp_arg_regs = [
        rXMM0,
        rXMM1,
        rXMM2,
        rXMM3,
        rXMM4,
        rXMM5,
        rXMM6,
        rXMM7
    ]
    @classmethod
    def get_function_int_arg_reg(cls, nr):
        return Register(RegType.int32, cls.function_int_arg_regs[nr])
    @classmethod
    def get_function_fp_arg_reg(cls, nr):
        return Register(RegType.float64, cls.function_fp_arg_regs[nr])

    @classmethod
    def get_function_res_reg(cls, is_int):
        if is_int:
            return Register(RegType.int32, cls.function_int_arg_regs[0])
        else:
            return Register(RegType.float64, cls.function_fp_arg_regs[0])

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        if reg.is_int:
            res = (0xb8 + reg.n).to_bytes(1, 'little') + val.to_bytes(4, 'little')
            return res
        else:
            raise NotImplementedError('fp loadimm not yet handled')

    @staticmethod
    def gen_loadmem(reg, width):
        if reg.is_int:
            res = b'\x8b' + (0x05 + (reg.n << 3)).to_bytes(1, 'little') + b'\x00\x00\x00\x00'
            return [ (res, 2, RelType.abs4) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @staticmethod
    def gen_loadref(reg, offset):
        # We always assume a small memory model, references are 4 bytes
        assert reg.is_int
        res = (0xb8 + reg.n).to_bytes(1, 'little') + offset.to_bytes(4, 'little')
        return [ (res, 1, RelType.abs4) ]

    @classmethod
    def gen_saveimm(cls, val, width):
        if type(val.value) != int:
            return False
        if width == 4:
            res = b'\xc7'
        elif width == 2:
            res = b'\x66\xc7'
        else:
            res = b'\xc6'
        off = 2 + len(res)
        res += b'\x04\x25\x00\x00\x00\x00' + val.value.to_bytes(width, 'little')
        return [ (res, off, RelType.abs4) ]

    @classmethod
    def gen_aug_saveimm(cls, op, val, width):
        if type(val.value) != int or val.value < -2^31 or val.value >= 2^31:
            return None
        match op:
            case ast.Add():
                op = b'\x04'
            case _:
                return None
        is_imm8 = val.value >= -128 and val.value < 128
        if width == 4:
            res = b'\x83' if is_imm8 else b'\x81'
        elif width == 2:
            res = b'\x66\x83' if is_imm8 else b'\x81'
        else:
            res = b'\x82'
        off = 2 + len(res)
        res += op + b'\x25\x00\x00\x00\x00' + val.value.to_bytes(1 if is_imm8 else min(4, width), 'little')
        return [ (res, off, RelType.abs4) ]

    @classmethod
    def gen_savemem(cls, reg, width):
        if reg.is_int:
            res = b'\x89' + (0x04 + ((reg.n & 0b111) << 3)).to_bytes(1, 'little') + b'\x25' + b'\x00\x00\x00\x00'
            return [ (res, 3, RelType.abs4) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @classmethod
    def gen_aug_savemem(cls, op, reg, width):
        match op:
            case ast.Add():
                res = b'\x02' if width == 1 else b'\x01'
            case ast.Sub():
                res = b'\x2a' if width == 1 else b'\x29'
            case _:
                return None
        if width == 2:
            res = b'\66' + res
        off = 2 + len(res)
        res += (0x04 | ((reg.n & 0b111) << 3)).to_bytes(1, 'little') + b'\x25\x00\x00\x00\x00'
        return [ (res, off, RelType.abs4) ]

    def gen_binop(self, resreg, rreg, op):
        if resreg.is_int:
            assert resreg.is_int
            assert rreg.is_int
            match op:
                case ast.Add():
                    res = b'\x01'
                case ast.Sub():
                    res = b'\x29'
                case ast.BitAnd():
                    res = b'\x21'
                case ast.BitOr():
                    res = b'\x09'
                case ast.BitXor():
                    res = b'\x31'
                case _:
                    raise NotImplementedError(f'unsupported binop {op}')
            res += (0xc0 + (rreg.n << 3) + resreg.n).to_bytes(1, 'little')
            self.release_reg(rreg)
            return res
        else:
            assert not resreg.is_int
            assert not rreg.is_int
            raise NotImplementedError('fp binop not yet implemented')

    def gen_compare(self, l, r, op, condjmpctx):
        if l.is_int:
            assert r.is_int
            res = b'\x39' + (0xc0 + (r.n << 3) + l.n).to_bytes(1, 'little')
            self.release_reg(l)
            self.release_reg(r)
            return res, None
        else:
            assert not l.is_int
            assert not r.is_int
            raise NotImplementedError('fp compare not yet implemented')

    def gen_store_flag(self, op, reg):
        if not reg:
            reg = self.get_unused_reg(RegType.int32)
        res = self.gen_loadimm(reg, 0)
        res += b'\x0f'
        match op:
            case ast.Eq():
                res += b'\x94'
            case ast.NotEq():
                res += b'\x95'
            case _:
                raise NotImplementedError(f'unsupported comparison {op}')
        res += (0xc0 + (reg.n & 0b111)).to_bytes(1, 'little')
        return res, reg

    @staticmethod
    def gen_condjump(curoff, flags, exp, lab):
        res = b'\x0f'
        match (flags.op, exp):
            case (ast.Eq(), False) | (ast.NotEq(), True):
                res += b'\x85'
            case (ast.Eq(), True) | (ast.NotEq(), False):
                res += b'\x84'
            case _:
                raise NotImplementedError(f'unhandled condjump {flags.op}/{exp}')
        return [ (res + b'\x00\x00\x00\x00', Relocation(lab, b'.text', curoff + 2, RelType.rel4a)) ]

    @staticmethod
    def gen_jump(curoff, lab):
        return [ (b'\xe9\x00\x00\x00\x00', Relocation(lab, b'.text', curoff + 1, RelType.rel4a)) ]

    @staticmethod
    def gen_call(curoff, lab):
        return [ (b'\xe8\x00\x00\x00\x00', Relocation(lab, b'.text', curoff + 1, RelType.rel4a)) ]

    @staticmethod
    def gen_return():
        return b'\xc3'

    @staticmethod
    def gen_create_stackframe():
        return b'\x55\x89\xe5'

    @staticmethod
    def gen_destroy_stackframe():
        return b'\xc9'

    @staticmethod
    def gen_frame_store(reg):
        if reg.is_int:
            res = (0x50 + (reg.n & 0b111)).to_bytes(1, 'little')
            return res, 8
        else:
            raise NotImplementedError(f'store fp on stack frame not supported')

    @staticmethod
    def gen_frame_load(reg, offset):
        assert offset > 0
        if reg.is_int:
            res = b'\x8b'
            if offset <= 128:
                res += (0x45 + ((reg .n & 0b111) << 3)).to_bytes(1, 'little') + (-offset).to_bytes(1, 'little', signed=True)
            else:
                res += (0x85 + ((reg .n & 0b111) << 3)).to_bytes(1, 'little') + (-offset).to_bytes(4, 'little', signed=True)
        else:
            raise NotImplementedError(f'load fp from frame not supported')
        return res


class rv_encoding(RegAlloc):
    elf_machine = elfdef.EM_RISCV

    n_int_regs = 32
    n_fp_regs = 32

    rRA = 0b00001
    rSP = 0b00010
    rFP = 0b01000
    rA0 = 0b01010
    rA1 = 0b01011
    rA2 = 0b01100
    rA3 = 0b01101
    rA4 = 0b01110
    rA5 = 0b01111
    rA6 = 0b10000
    rA7 = 0b10001
    rFA0 = 0b01010
    rFA1 = 0b01011
    rFA2 = 0b01100
    rFA3 = 0b01101
    rFA4 = 0b01110
    rFA5 = 0b01111
    rFA6 = 0b10000
    rFA7 = 0b10001

    def __init__(self):
        super().__init__(5, self.n_int_regs, 0, self.n_fp_regs)

    function_int_arg_regs = [
        rA0,
        rA1,
        rA2,
        rA3,
        rA4,
        rA5,
        rA6,
        rA7
    ]
    function_fp_arg_regs = [
        rFA0,
        rFA1,
        rFA2,
        rFA3,
        rFA4,
        rFA5,
        rFA6,
        rFA7
    ]

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        if reg.is_int:
            if val >= -2048 and val < 2048:
                word = ((val & 0xfff) << 20) | (reg.n << 7) | 0b0010011
                res = word.to_bytes(4, 'little')
            else:
                word1 = (val & 0xfffff000) | (reg.n << 7) | 0b0110111
                word2 = ((val & 0xfff) << 20) | (reg.n << 15) | (reg.n << 7) | 0b0010011
                res = word1.to_bytes(4, 'little') + word2.to_bytes(4, 'little')
            return res
        else:
            raise NotImplementedError('fp loadimm not yet handled')

    @staticmethod
    def gen_loadmem(reg, width, signed = False):
        if reg.is_int:
            word1 = (reg.n << 7) | 0b0110111
            res1 = word1.to_bytes(4, 'little')
            logwidth = math.frexp(width)[1] - 1
            word2 = (reg.n << 15) | ((logwidth | (0 if signed or width == 4 else 0b100)) << 12) | (reg.n << 7) | 0b0000011
            res2 = word2.to_bytes(4, 'little')
            return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @staticmethod
    def gen_loadref(reg, offset):
        # We always assume a small memory model, references are 4 bytes
        assert reg.is_int
        word1 = (reg.n << 7) | 0b0110111
        res1 = word1.to_bytes(4, 'little')
        word2 = (reg.n << 15) | (reg.n << 7) | 0b0010011
        res2 = word2.to_bytes(4, 'little')
        return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo) ]

    def gen_savemem(self, reg, width):
        if reg.is_int:
            addrreg = self.get_unused_reg(RegType.ptr)
            word1 = (addrreg.n << 7) | 0b0110111
            res1 = word1.to_bytes(4, 'little')
            logwidth = math.frexp(width)[1] - 1
            word2 = (reg.n << 20) | (addrreg.n << 15) | (logwidth << 12) | 0b0100011
            res2 = word2.to_bytes(4, 'little')
            self.release_reg(addrreg)
            return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo2) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    def gen_binop(self, resreg, rreg, op):
        if resreg.is_int:
            assert resreg.is_int
            assert rreg.is_int
            match op:
                case ast.Add():
                    word = (0b000 << 12) | 0b0110011
                case ast.Sub():
                    word = (0b0100000 << 25) | (0b000 << 12) | 0b0110011
                case ast.BitAnd():
                    word = (0b111 << 12) | 0b0110011
                case ast.BitOr():
                    word = (0b110 << 12) | 0b0110011
                case ast.BitXor():
                    word = (0b100 << 12) | 0b0110011
                case _:
                    raise NotImplementedError(f'unsupported binop {op}')
            self.release_reg(rreg)
            return (word | (rreg.n << 20) | (resreg.n << 15) | (resreg.n << 7)).to_bytes(4, 'little')
        else:
            assert not resreg.is_int
            assert not rreg.is_int
            raise NotImplementedError('fp binop not yet implemented')

    def gen_compare(self, l, r, op, condjmpctx):
        if l.is_int:
            assert r.is_int
            if condjmpctx:
                return b'', (l, r)
            match op:
                case ast.Eq():
                    res = self.gen_binop(l, r, ast.Sub())
                    res += ((0b000000000001 << 20) | (l.n << 15) | (0b011 << 12) | (l.n << 7) | 0b0010011).to_bytes(4, 'little')
                case ast.NotEq():
                    res = self.gen_binop(l, r, ast.Sub())
                    res += ((l.n << 20) | (0b011 << 12) | (l.n << 7) | 0b0110011).to_bytes(4, 'little')
                case _:
                    raise NotImplementedError(f'unsupported compare {op}')
            return res, l
        else:
            assert not r.is_int
            raise NotImplementedError('fp compare not yet implemented')

    def gen_condjump(self, curoff, flags, exp, lab):
        assert type(flags.reg) == tuple and len(flags.reg) == 2
        if flags.reg[0].is_int:
            assert flags.reg[1].is_int
            match (flags.op, exp):
                case (ast.Eq(), True) | (ast.NotEq(), False):
                    word1 = ((flags.reg[1].n << 20) | (flags.reg[0].n << 15) | (0b001 << 12) | ((8 >> 1) << 8) | 0b1100011)
                    word2 = 0b1101111
                    return [ (word1.to_bytes(4, 'little'), None), (word2.to_bytes(4, 'little'), Relocation(lab, b'.text', curoff + 4, RelType.rvjal)) ]
                case (ast.Eq(), False) | (ast.NotEq(), True):
                    word1 = ((flags.reg[1].n << 20) | (flags.reg[0].n << 15) | (0b000 << 12) | ((8 >> 1) << 8) | 0b1100011)
                    word2 = 0b1101111
                    return [ (word1.to_bytes(4, 'little'), None), (word2.to_bytes(4, 'little'), Relocation(lab, b'.text', curoff + 4, RelType.rvjal)) ]
                case _:
                    raise NotImplementedError(f'unhandled condjump {flags.op}/{exp}')
        else:
            assert not flags.reg[1].is_int

    @staticmethod
    def gen_jump(curoff, lab):
        return [ ((0b1101111).to_bytes(4, 'little'), Relocation(lab, b'.text', curoff, RelType.rvjal)) ]

    @classmethod
    def gen_call(cls, curoff, lab):
        return [ (((cls.rRA << 7) | 0b1101111).to_bytes(4, 'little'), Relocation(lab, b'.text', curoff, RelType.rvjal)) ]

    @classmethod
    def gen_return(cls):
        return ((cls.rRA << 15) | 0b1100111).to_bytes(4, 'little')

    @classmethod
    def gen_create_stackframe(cls):
        res = (((-(cls.nbits // 8) & 0xfff) << 20) | (cls.rSP << 15) | (cls.rSP << 7) | 0b0010011).to_bytes(4, 'little')
        logwidth = math.frexp(cls.nbits / 8)[1] - 1
        res += ((cls.rFP << 20) | (cls.rSP << 15) | (logwidth << 12) | 0b0100011).to_bytes(4, 'little')
        res += (((cls.nbits // 8) & 0xfff) << 20 | (cls.rSP << 15) | (cls.rFP << 7) | 0b0010011).to_bytes(4, 'little')
        return res

    @classmethod
    def gen_destroy_stackframe(cls):
        res = ((-(cls.nbits // 8) & 0xfff) << 20 | (cls.rFP << 15) | (cls.rSP << 7) | 0b0010011).to_bytes(4, 'little')
        logwidth = math.frexp(cls.nbits / 8)[1] - 1
        res += ( (cls.rSP << 15) | (logwidth << 12) | (cls.rFP << 7) |0b0000011).to_bytes(4, 'little')
        res += (((cls.nbits // 8) & 0xfff) << 20 | (cls.rSP << 15) | (cls.rSP << 7) | 0b0010011).to_bytes(4, 'little')
        return res

    @classmethod
    def gen_frame_store(cls, reg):
        res = ((-(cls.nbits // 8) & 0xfff) << 20 | (cls.rSP << 15) | (cls.rSP << 7) | 0b0010011).to_bytes(4, 'little')
        logwidth = math.frexp(cls.nbits / 8)[1] - 1
        res += ((reg.n << 20) | (cls.rSP << 15) | (logwidth << 12) | 0b0100011).to_bytes(4, 'little')
        return res, cls.nbits // 8

    @classmethod
    def gen_frame_load(cls, reg, offset):
        # The FP register by convention points before the stored previous value.  So the frame is one slot larger.
        offset += cls.nbits // 8
        logwidth = math.frexp(cls.nbits / 8)[1] - 1
        res = (((-offset & 0xfff) << 20) | (cls.rSP << 15) | (logwidth << 12) | (reg.n << 7) | 0b0000011).to_bytes(4, 'little')
        return res

    @classmethod
    def gen_move_reg(cls, dreg, sreg):
        return ((sreg.n << 15) | (dreg.n << 7) | 0b0010011).to_bytes(4, 'little')

class rv32_encoding(rv_encoding):
    nbits = 32           # processor bits

    @classmethod
    def get_function_int_arg_reg(cls, nr):
        return Register(RegType.int64, cls.function_int_arg_regs[nr])
    @classmethod
    def get_function_fp_arg_reg(cls, nr):
        return Register(RegType.float64, cls.function_fp_arg_regs[nr])

    @classmethod
    def get_function_res_reg(cls, is_int):
        if is_int:
            return Register(RegType.int64, cls.function_int_arg_regs[0])
        else:
            return Register(RegType.float64, cls.function_fp_arg_regs[0])


class rv64_encoding(rv_encoding):
    nbits = 64           # processor bits

    @classmethod
    def get_function_int_arg_reg(cls, nr):
        return Register(RegType.int32, cls.function_int_arg_regs[nr])
    @classmethod
    def get_function_fp_arg_reg(cls, nr):
        return Register(RegType.float64, cls.function_fp_arg_regs[nr])

    @classmethod
    def get_function_res_reg(cls, is_int):
        if is_int:
            return Register(RegType.int32, cls.function_int_arg_regs[0])
        else:
            return Register(RegType.float64, cls.function_fp_arg_regs[0])


class arm_encoding(RegAlloc):
    nbits = 32           # processor bits
    elf_machine = elfdef.EM_ARM
    endian = 'little'

    n_int_regs = 16
    n_fp_regs = 16

    r0 = 0b0000
    r1 = 0b0001
    r2 = 0b0010
    r3 = 0b0011
    r4 = 0b0100
    r5 = 0b0101
    r6 = 0b0110
    r7 = 0b0111
    rFP = 0b1011
    rSP = 0b1101
    rLR = 0b1110
    rF0 = 0b0000
    rF1 = 0b0001
    rF2 = 0b0010
    rF3 = 0b0011
    rF4 = 0b0100
    rF5 = 0b0101
    rF6 = 0b0110
    rF7 = 0b0111

    def __init__(self):
        super().__init__(0, self.n_int_regs, 0, self.n_fp_regs)

    function_int_arg_regs = [
        r0,
        r1,
        r2,
        r3,
        r4,
        r5
    ]
    function_fp_arg_regs = [
        rF0,
        rF1,
        rF2,
        rF3,
        rF4,
        rF5,
        rF6,
        rF7
    ]
    @classmethod
    def get_function_int_arg_reg(cls, nr):
        return Register(RegType.int32, cls.function_int_arg_regs[nr])
    @classmethod
    def get_function_fp_arg_reg(cls, nr):
        return Register(RegType.float64, cls.function_fp_arg_regs[nr])

    @classmethod
    def get_function_res_reg(cls, is_int):
        if is_int:
            return Register(RegType.int32, cls.function_int_arg_regs[0])
        else:
            return Register(RegType.float64, cls.function_fp_arg_regs[0])

    @classmethod
    def gen_loadimm(cls, reg, val, width = 0, signed = False):
        if reg.is_int:
            if val >= 0:
                if val < 4096:
                    res = (0xe3a00000 | (reg.n << 12) | val).to_bytes(4, cls.endian)
                else:
                    res = (0xe3000000 | ((val & 0xf000) << 4) | (reg.n << 12) | (val & 0xfff)).to_bytes(4, cls.endian)
                    if val >= 65536:
                        res += (0xe3400000 | ((val >> 12) & 0xf0000) | ((val >> 16) & 0xfff)).to_bytes(4, cls.endian)
            else:
                if val >= -0x101:
                    res = (0xe3e00000 | ~val).to_bytes(4, cls.endian)
                else:
                    res = (0xe3000000 | ((val & 0xf000) << 4) | (val & 0xfff)).to_bytes(4, cls.endian)
                    res += (0xe3400000 | ((val >> 12) & 0xf0000) | ((val >> 16) & 0xfff)).to_bytes(4, cls.endian)
            return res
        else:
            raise NotImplementedError('fp loadimm not yet handled')

    @classmethod
    def gen_loadmem(cls, reg, width, signed = False):
        if reg.is_int:
            res1 = (0xe3000000 | (reg.n << 12)).to_bytes(4, cls.endian)
            res2 = (0xe3400000 | (reg.n << 12)).to_bytes(4, cls.endian)
            res3 = (0xe5900000 | (reg.n << 16) | (reg.n << 12)).to_bytes(4, cls.endian)
            return [ (res1, 0, RelType.armmovwabs), (res2, 0, RelType.armmovtabs), (res3, 0, RelType.none) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @classmethod
    def gen_loadref(cls, reg, offset):
        assert reg.is_int
        res1 = (0xe3000000 | (reg.n << 12)).to_bytes(4, cls.endian)
        res2 = (0xe3400000 | (reg.n << 12)).to_bytes(4, cls.endian)
        return [ (res1, 0, RelType.armmovwabs), (res2, 0, RelType.armmovtabs) ]

    def gen_savemem(self, reg, width):
        if reg.is_int:
            addrreg = self.get_unused_reg(RegType.ptr)
            res1 = (0xe3000000 | (addrreg.n << 12)).to_bytes(4, self.endian)
            res2 = (0xe3400000 | (addrreg.n << 12)).to_bytes(4, self.endian)
            res3 = (0xe5800000 | (addrreg.n << 16) | (reg.n << 12)).to_bytes(4, self.endian)
            self.release_reg(addrreg)
            return [ (res1, 0, RelType.armmovwabs), (res2, 0, RelType.armmovtabs), (res3, 0, RelType.none) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    def gen_binop(self, resreg, rreg, op):
        if resreg.is_int:
            assert resreg.is_int
            assert rreg.is_int
            match op:
                case ast.Add():
                    word = 0xe0800000
                case ast.Sub():
                    word = 0xe0400000
                case ast.BitAnd():
                    word = 0xe0000000
                case ast.BitOr():
                    word = 0xe1800000
                case ast.BitXor():
                    word = 0xe0200000
                case _:
                    raise NotImplementedError(f'unsupported binop {op}')
            self.release_reg(rreg)
            return (word | (resreg.n << 16) | (resreg.n << 12) | rreg.n).to_bytes(4, self.endian)
        else:
            assert not resreg.is_int
            assert not rreg.is_int
            raise NotImplementedError('fp binop not yet implemented')

    def gen_compare(self, l, r, op, condjmpctx):
        if l.is_int:
            assert r.is_int
            res = (0xe1500000 | (l.n << 16) | r.n).to_bytes(4, self.endian)
            self.release_reg(l)
            self.release_reg(r)
            return res, None
        else:
            assert not l.is_int
            assert not r.is_int
            raise NotImplementedError('fp compare not yet implemented')

    def gen_store_flag(self, op, reg):
        if not reg:
            reg = self.get_unused_reg(RegType.int32)
        res = self.gen_loadimm(reg, 0)
        match op:
            case ast.Eq():
                res += ((0b0000 << 28) | 0x3a00000 | (reg.n << 12) | 1).to_bytes(4, self.endian)
            case ast.NotEq():
                res += ((0b0001 << 28) | 0x3a00000 | (reg.n << 12) | 1).to_bytes(4, self.endian)
            case _:
                raise NotImplementedError(f'unsupported comparison {op}')
        return res, reg

    def gen_condjump(self, curoff, flags, exp, lab):
        match (flags.op, exp):
            case (ast.Eq(), True) | (ast.NotEq(), False):
                cond = 0b0000
            case (ast.Eq(), False) | (ast.NotEq(), True):
                cond = 0b0001
            case _:
                raise NotImplementedError(f'unhandled condjump {flags.op}/{exp}')
        return [ (((cond << 28) | (0b1010 << 24)).to_bytes(4, self.endian), Relocation(lab, b'.text', curoff, RelType.armb24)) ]

    def gen_jump(self, curoff, lab):
        return [ (((0b1110 << 28) | (0b1010 << 24)).to_bytes(4, self.endian), Relocation(lab, b'.text', curoff, RelType.armb24)) ]

    def gen_call(self, curoff, lab):
        return [ (((0b1110 << 28) | (0b1011 << 24)).to_bytes(4, self.endian), Relocation(lab, b'.text', curoff, RelType.armb24)) ]

    def gen_return(self):
        return (0xe12fff10 | self.rLR).to_bytes(4, self.endian)

    def gen_create_stackframe(self):
        res = ((0xe92d << 16) | (1 << self.rLR) | (1 << self.rFP)).to_bytes(4, self.endian)
        res += ((0xe28 << 20) | (self.rSP << 16) | (self.rFP << 12) | 0b000000000100).to_bytes(4, self.endian)
        return res

    def gen_destroy_stackframe(self):
        res = ((0xe24 << 20) | (self.rFP << 16) | (self.rSP << 12) | 0b000000000100).to_bytes(4, self.endian)
        res += ((0xe8bd << 16) | (1 << self.rLR) | (1 << self.rFP)).to_bytes(4, self.endian)
        return res

    def gen_frame_store(self, reg):
        if reg.is_int:
            res = ((0xe92d << 16) | (1 << reg.n)).to_bytes(4, self.endian)
            return res, 4
        else:
            raise NotImplementedError(f'store fp on stack frame not supported')

    def gen_frame_load(self, reg, offset):
        if reg.is_int:
            res = ((0xe59 << 20) | (reg.n << 16) | (self.rFP << 12) | ((-4 - offset) & 0xfff)).to_bytes(4, self.endian)
        else:
            raise NotImplementedError(f'load fp from frame not supported')
        return res


class aarch64_encoding(RegAlloc):
    nbits = 64           # processor bits
    elf_machine = elfdef.EM_AARCH64
    endian = 'little'

    n_int_regs = 16
    n_fp_regs = 16

    x0 = 0b00000
    x1 = 0b00001
    x2 = 0b00010
    x3 = 0b00011
    x4 = 0b00100
    x5 = 0b00101
    x6 = 0b00110
    x7 = 0b00111
    x8 = 0b01000

    def __init__(self):
        super().__init__(0, self.n_int_regs, 0, self.n_fp_regs)

    @classmethod
    def gen_loadimm(cls, reg, val, width = 0, signed = False):
        if reg.is_int:
            if val >= 0 and val < 65536:
                res = (0xd2800000 | (val << 5) | reg.n).to_bytes(4, cls.endian)
            elif val < 0 and -val >= 0x10000:
                res = (0x92800000 | ((-val - 1) << 5) | reg.n).to_bytes(4, cls.endian)
            elif -val == 0x10001:
                res = (0x92a00020 | reg.n).to_bytes(4, cls.endian)
            elif val < 0 and -val <= 0xffffffff:
                res = (0x92800000 | (((-val & 0xffff) - 1) << 5) | reg.n).to_bytes(4, cls.endian)
                res += (0xf2a00000 | ((val >> 11) & 0x1fffe0) | reg.n).to_bytes(4, cls.endian)
            elif val >= 0 and val <= 0xffffffff:
                res = (0xd2800000 | ((val & 0xffff) << 5) | reg.n).to_bytes(4, cls.endian)
                res += (0xf2a00000 | ((val >> 11) & 0x1fffe0) | reg.n).to_bytes(4, cls.endian)
            return res
        else:
            raise NotImplementedError('fp loadimm not yet handled')

    @classmethod
    def gen_loadmem(cls, reg, width, signed = False):
        if reg.is_int:
            res1 = (0xd2800000 | reg.n).to_bytes(4, cls.endian)
            res2 = (0xf2a00000 | reg.n).to_bytes(4, cls.endian)
            res3 = ((0xf9400000 if width == 8 else 0xb9400000) | (reg.n << 5) | reg.n).to_bytes(4, cls.endian)
            return [ (res1, 0, RelType.aarch64lo16abs), (res2, 0, RelType.aarch64hi16abs), (res3, 0, RelType.none) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    @classmethod
    def gen_loadref(cls, reg, offset):
        # We always assume a small memory model, references are 4 bytes
        assert reg.is_int
        res1 = (0xd2800000 | reg.n).to_bytes(4, cls.endian)
        res2 = (0xf2a00000 | reg.n).to_bytes(4, cls.endian)
        return [ (res1, 0, RelType.aarch64lo16abs), (res2, 0, RelType.aarch64hi16abs) ]

    def gen_savemem(self, reg, width):
        if reg.is_int:
            addrreg = self.get_unused_reg(RegType.ptr)
            res1 = (0xd2800000 | addrreg.n).to_bytes(4, self.endian)
            res2 = (0xf2a00000 | addrreg.n).to_bytes(4, self.endian)
            res3 = ((0xf9000000 if width == 8 else 0xb9000000) | (addrreg.n << 5) | reg.n).to_bytes(4, self.endian)
            self.release_reg(addrreg)
            return [ (res1, 0, RelType.aarch64lo16abs), (res2, 0, RelType.aarch64hi16abs), (res3, 0, RelType.none) ]
        else:
            raise NotImplementedError('fp regs not yet handled')

    def gen_binop(self, resreg, rreg, op):
        if resreg.is_int:
            assert resreg.is_int
            assert rreg.is_int
            match op:
                case ast.Add():
                    word = 0x8b000000
                case ast.Sub():
                    word = 0xcb000000
                case ast.BitAnd():
                    word = 0x8a000000
                case ast.BitOr():
                    word = 0xaa000000
                case ast.BitXor():
                    word = 0xca000000
                case _:
                    raise NotImplementedError(f'unsupported binop {op}')
            self.release_reg(rreg)
            return (word | (rreg.n << 16) | (resreg.n << 5) | resreg.n).to_bytes(4, self.endian)
        else:
            assert not resreg.is_int
            assert not rreg.is_int
            raise NotImplementedError('fp binop not yet implemented')

    def gen_compare(self, l, r, op, condjmpctx):
        if l.is_int:
            assert r.is_int
            res = (0xeb00001f | (r.n << 16) | (l.n << 5)).to_bytes(4, self.endian)
            self.release_reg(l)
            self.release_reg(r)
            return res, None
        else:
            assert not l.is_int
            assert not r.is_int
            raise NotImplementedError('fp compare not yet implemented')

    def gen_store_flag(self, op, reg):
        if not reg:
            reg = self.get_unused_reg(RegType.int32)
        res = self.gen_loadimm(reg, 0)
        match op:
            case ast.Eq():
                res = (0x9a9f17e0 | reg.n).to_bytes(4, self.endian)
            case _:
                raise NotImplementedError(f'unsupported comparison {op}')
        return res, reg

    def gen_condjump(self, curoff, flags, exp, lab):
        match (flags.op, exp):
            case (ast.Eq(), True) | (ast.NotEq(), False):
                cond = 0b0000
            case (ast.Eq(), False) | (ast.NotEq(), True):
                cond = 0b0001
            case _:
                raise NotImplementedError(f'unhandled condjump {flags.op}/{exp}')
        return [ (((0b01010100 << 24) | cond).to_bytes(4, self.endian), Relocation(lab, b'.text', curoff, RelType.aarch64bc19)) ]

    def gen_jump(self, curoff, lab):
        return [ ((0b000101 << 26).to_bytes(4, self.endian), Relocation(lab, b'.text', curoff, RelType.aarch64b26))]

# OS traits
class linux_traits:
    libelfdso = '/$LIB/libelf.so.1'


class freebsd_traits:
    libelfdso = '/lib/libelf.so.2'


# OS+CPU traits
class linux_x86_64_traits(x86_64_encoding, linux_traits):
    SYS_write = 1
    SYS_exit = 231       # actually SYS_exit_group

    @staticmethod
    def get_endian():
        return elfdef.ELFDATA2LSB

    syscall_arg_regs = [
        x86_64_encoding.rDI,
        x86_64_encoding.rSI,
        x86_64_encoding.rDX,
        x86_64_encoding.r10,
        x86_64_encoding.r8,
        x86_64_encoding.r9
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int64, cls.syscall_arg_regs[nr])

    @classmethod
    def get_syscall_res_reg(cls):
        return Register(RegType.int64, cls.rAX)

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(Register(RegType.int64, cls.rAX), nr)
        res += b'\x0f\x05'                          # syscall
        return res


class linux_i386_traits(i386_encoding, linux_traits):
    SYS_write = 4
    SYS_exit = 252       # actually SYS_exit_group

    @staticmethod
    def get_endian():
        return elfdef.ELFDATA2LSB

    syscall_arg_regs = [
        i386_encoding.rBX,
        i386_encoding.rCX,
        i386_encoding.rDX,
        i386_encoding.rSI,
        i386_encoding.rDI,
        i386_encoding.rBP
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int32, cls.syscall_arg_regs[nr])

    @classmethod
    def get_syscall_res_reg(cls):
        return Register(RegType.int64, cls.rAX)

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(Register(RegType.int32, cls.rAX), nr)
        res += b'\xcd\x80'                          # int $0x80
        return res


class linux_rv32_traits(rv32_encoding, linux_traits):
    SYS_write = 64
    SYS_exit = 94       # actually SYS_exit_group

    @staticmethod
    def get_endian():
        return elfdef.ELFDATA2LSB

    syscall_arg_regs = [
        rv32_encoding.rA0,
        rv32_encoding.rA1,
        rv32_encoding.rA2,
        rv32_encoding.rA3,
        rv32_encoding.rA4,
        rv32_encoding.rA5
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int32, cls.syscall_arg_regs[nr])

    @classmethod
    def get_syscall_res_reg(cls):
        return Register(RegType.int32, cls.rA0)

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(Register(RegType.int32, cls.rA7), nr)
        res += b'\x73\x00\x00\x00'       # ecall
        return res


class linux_rv64_traits(rv64_encoding, linux_traits):
    SYS_write = 64
    SYS_exit = 94       # actually SYS_exit_group

    @staticmethod
    def get_endian():
        return elfdef.ELFDATA2LSB

    syscall_arg_regs = [
        rv32_encoding.rA0,
        rv32_encoding.rA1,
        rv32_encoding.rA2,
        rv32_encoding.rA3,
        rv32_encoding.rA4,
        rv32_encoding.rA5
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int64, cls.syscall_arg_regs[nr])

    @classmethod
    def get_syscall_res_reg(cls):
        return Register(RegType.int64, cls.rA0)

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(Register(RegType.int64, cls.rA7), nr)
        res += b'\x73\x00\x00\x00'       # ecall
        return res


class linux_arm_traits(arm_encoding, linux_traits):
    SYS_write = 4
    SYS_exit = 248       # actually SYS_exit_group

    @classmethod
    def get_endian(cls):
        return elfdef.ELFDATA2LSB if cls.endian == 'little' else elfdef.ELFDATA2MSB

    syscall_arg_regs = [
        arm_encoding.r0,
        arm_encoding.r1,
        arm_encoding.r2,
        arm_encoding.r3,
        arm_encoding.r4,
        arm_encoding.r5
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int32, cls.syscall_arg_regs[nr])

    @classmethod
    def get_syscall_res_reg(cls):
        return Register(RegType.int32, cls.r0)

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(Register(RegType.int32, cls.r7), nr)
        res += (0xef000000).to_bytes(4, cls.endian)  # swi #0
        return res


class linux_aarch64_traits(aarch64_encoding, linux_traits):
    SYS_write = 64
    SYS_exit = 94       # actually SYS_exit_group

    @classmethod
    def get_endian(cls):
        return elfdef.ELFDATA2LSB if cls.endian == 'little' else elfdef.ELFDATA2MSB

    syscall_arg_regs = [
        aarch64_encoding.x0,
        aarch64_encoding.x1,
        aarch64_encoding.x2,
        aarch64_encoding.x3,
        aarch64_encoding.x4,
        aarch64_encoding.x5
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int64, cls.syscall_arg_regs[nr])

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(Register(RegType.int64, cls.x8), nr)
        res += (0xd4000001).to_bytes(4, cls.endian)  # svc #0
        return res


class freebsd_x86_64_traits(x86_64_encoding, freebsd_traits):
    SYS_write = 4
    SYS_exit = 1

    @staticmethod
    def get_endian():
        return elfdef.ELFDATA2LSB

    syscall_arg_regs = [
        x86_64_encoding.rDI,
        x86_64_encoding.rSI,
        x86_64_encoding.rDX,
        x86_64_encoding.rCX,
        x86_64_encoding.r8,
        x86_64_encoding.r9
    ]
    @classmethod
    def get_syscall_arg_reg(cls, nr):
        return Register(RegType.int32, cls.syscall_arg_regs[nr])

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.rAX, nr)
        res += b'\x0f\x05'                          # syscall
        return res


class elfstrtab(object):
    def __init__(self):
        self.s = b'\x00'
    def data(self):
        return self.s
    def __len__(self):
        return len(self.s)
    def push(self, n):
        res = len(self.s)
        self.s += n
        self.s += b'\000'
        return res


class bytebuf(object):
    def __init__(self, b=b''):
        self.b = b
    def data(self):
        return self.b
    def __len__(self):
        return len(self.b)
    def __iadd__(self, b):
        self.b += b
        return self


class elf_data(ctypes.Structure):
    _fields_ = [
        ('buf', ctypes.POINTER(ctypes.c_byte)),
        ('type', ctypes.c_uint32),
        ('version', ctypes.c_uint32),
        ('size', ctypes.c_size_t),
        ('off', ctypes.c_int64),
        ('align', ctypes.c_size_t)
    ]


class elf32_ehdr(ctypes.Structure):
    _fields_ = [
        ('ident', ctypes.c_byte * 16),
        ('type', ctypes.c_uint16),
        ('machine', ctypes.c_uint16),
        ('version', ctypes.c_uint32),
        ('entry', ctypes.c_uint32),
        ('phoff', ctypes.c_uint32),
        ('shoff', ctypes.c_uint32),
        ('flags', ctypes.c_uint32),
        ('ehsize', ctypes.c_uint16),
        ('phentsize', ctypes.c_uint16),
        ('phnum', ctypes.c_uint16),
        ('shentsize', ctypes.c_uint16),
        ('shnum', ctypes.c_uint16),
        ('shstrndx', ctypes.c_uint16)
    ]


class elf32_phdr(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_uint32),
        ('offset', ctypes.c_uint32),
        ('vaddr', ctypes.c_uint32),
        ('paddr', ctypes.c_uint32),
        ('filesz', ctypes.c_uint32),
        ('memsz', ctypes.c_uint32),
        ('flags', ctypes.c_uint32),
        ('align', ctypes.c_uint32)
    ]


class elf32_shdr(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_uint32),
        ('type', ctypes.c_uint32),
        ('flags', ctypes.c_uint32),
        ('addr', ctypes.c_uint32),
        ('offset', ctypes.c_uint32),
        ('size', ctypes.c_uint32),
        ('link', ctypes.c_uint32),
        ('info', ctypes.c_uint32),
        ('addralign', ctypes.c_uint32),
        ('entsize', ctypes.c_uint32)
    ]


class elf64_ehdr(ctypes.Structure):
    _fields_ = [
        ('ident', ctypes.c_byte * 16),
        ('type', ctypes.c_uint16),
        ('machine', ctypes.c_uint16),
        ('version', ctypes.c_uint32),
        ('entry', ctypes.c_uint64),
        ('phoff', ctypes.c_uint64),
        ('shoff', ctypes.c_uint64),
        ('flags', ctypes.c_uint32),
        ('ehsize', ctypes.c_uint16),
        ('phentsize', ctypes.c_uint16),
        ('phnum', ctypes.c_uint16),
        ('shentsize', ctypes.c_uint16),
        ('shnum', ctypes.c_uint16),
        ('shstrndx', ctypes.c_uint16)
    ]


class elf64_phdr(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_uint32),
        ('flags', ctypes.c_uint32),
        ('offset', ctypes.c_uint64),
        ('vaddr', ctypes.c_uint64),
        ('paddr', ctypes.c_uint64),
        ('filesz', ctypes.c_uint64),
        ('memsz', ctypes.c_uint64),
        ('align', ctypes.c_uint64)
    ]


class elf64_shdr(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_uint32),
        ('type', ctypes.c_uint32),
        ('flags', ctypes.c_uint64),
        ('addr', ctypes.c_uint64),
        ('offset', ctypes.c_uint64),
        ('size', ctypes.c_uint64),
        ('link', ctypes.c_uint32),
        ('info', ctypes.c_uint32),
        ('addralign', ctypes.c_uint64),
        ('entsize', ctypes.c_uint64)
    ]


class elf32_traits(object):
    Word = ctypes.c_int32
    Xword = ctypes.c_int32
    Addr = ctypes.c_int32

    def __init__(self, e, machine, libelf):
        self.libelf = libelf
        self.libelf.elf32_newehdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf32_newehdr.restype = (ctypes.POINTER(elf32_ehdr))
        self.libelf.elf32_getehdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf32_getehdr.restype = (ctypes.POINTER(elf32_ehdr))
        self.libelf.elf32_newphdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf32_newphdr.restype = (ctypes.POINTER(elf32_phdr))
        self.libelf.elf32_getshdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf32_getshdr.restype = (ctypes.POINTER(elf32_shdr))
        self.elfclass = elfdef.ELFCLASS32
        self.machine = machine
        self.phdr_type = elf32_phdr
    def newehdr(self, e):
        return self.libelf.elf32_newehdr(e)
    def getehdr(self, e):
        return self.libelf.elf32_getehdr(e)
    def newphdr(self, e, cnt):
        return ctypes.cast(self.libelf.elf32_newphdr(e, cnt), ctypes.POINTER(elf32_phdr * cnt))
    def getshdr(self, scn):
        return self.libelf.elf32_getshdr(scn)


class elf64_traits(object):
    Word = ctypes.c_int32
    Xword = ctypes.c_int64
    Addr = ctypes.c_int64

    def __init__(self, e, machine, libelf):
        self.libelf = libelf
        self.libelf.elf64_newehdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_newehdr.restype = (ctypes.POINTER(elf64_ehdr))
        self.libelf.elf64_getehdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_getehdr.restype = (ctypes.POINTER(elf64_ehdr))
        self.libelf.elf64_newphdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_newphdr.restype = (ctypes.POINTER(elf64_phdr))
        self.libelf.elf64_getshdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_getshdr.restype = (ctypes.POINTER(elf64_shdr))
        self.elfclass = elfdef.ELFCLASS64
        self.machine = machine
        self.phdr_type = elf64_phdr
    def newehdr(self, e):
        return self.libelf.elf64_newehdr(e)
    def getehdr(self, e):
        return self.libelf.elf64_getehdr(e)
    def newphdr(self, e, cnt):
        return ctypes.cast(self.libelf.elf64_newphdr(e, cnt), ctypes.POINTER(elf64_phdr * cnt))
    def getshdr(self, scn):
        return self.libelf.elf64_getshdr(scn)


class elf(object):
    def __init__(self, arch_os_traits):
        self.libelf = ctypes.cdll.LoadLibrary(arch_os_traits.libelfdso)
        if self.libelf.elf_version(elfdef.EV_CURRENT) != elfdef.EV_CURRENT:
            raise RuntimeError("invalid libelf version")
        self.libelf.elf_begin.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        self.libelf.elf_begin.restype = (ctypes.c_void_p)
        self.libelf.elf_newscn.argtypes = [ctypes.c_void_p]
        self.libelf.elf_newscn.restype = (ctypes.c_void_p)
        self.libelf.elf_newdata.argtypes = [ctypes.c_void_p]
        self.libelf.elf_newdata.restype = (ctypes.POINTER(elf_data))
        self.libelf.elf_getdata.argtypes = [ctypes.c_void_p, ctypes.POINTER(elf_data)]
        self.libelf.elf_getdata.restype = (ctypes.POINTER(elf_data))
        self.libelf.elf_update.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.libelf.elf_update.restype = (ctypes.c_uint64)
        self.libelf.elf_end.argtypes = [ctypes.c_void_p]
        self.libelf.elf_end.restype = (ctypes.c_int)
        self.libelf.elf_ndxscn.argtypes = [ctypes.c_void_p]
        self.libelf.elf_ndxscn.restype = (ctypes.c_size_t)
        self.libelf.elf_getscn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.libelf.elf_getscn.restype = (ctypes.c_void_p)
        self.traits = elf64_traits(self, arch_os_traits.elf_machine, self.libelf) if arch_os_traits.nbits == 64 else elf32_traits(self, arch_os_traits.elf_machine, self.libelf)
        self.shstrtab = elfstrtab()
        self.sectionidx = dict()
        # It should not be necessary to customize the alignment values.
        self.codealign = 16
        self.dataalign = 16
    def open(self, fd):
        self.fd = fd
        self.e = self.libelf.elf_begin(fd, elfdef.C_WRITE, None)
        return self.e != 0
    def newehdr(self):
        return self.traits.newehdr(self.e)
    def getehdr(self):
        return self.traits.getehdr(self.e)
    def newphdr(self, cnt):
        return self.traits.newphdr(self.e, cnt)
    def getshdr(self, scn):
        return self.traits.getshdr(scn)
    def newscn(self, name, type, flags, buf, align = None):
        scn = self.libelf.elf_newscn(self.e)
        shdr = self.getshdr(scn)
        shdr.contents.name = self.shstrtab.push(name)
        shdr.contents.type = type
        shdr.contents.flags = flags
        data = self.newdata(scn)
        data.contents.size = len(buf)
        data.contents.buf = ctypes.cast(ctypes.create_string_buffer(buf.data(), data.contents.size), ctypes.POINTER(ctypes.c_byte))
        data.contents.type = elfdef.ELF_T_BYTE
        data.contents.version = elfdef.EV_CURRENT
        data.contents.off = 0
        data.contents.align = align if align else self.codealign if (flags & elfdef.SHF_EXECINSTR) != 0 else self.dataalign
        self.sectionidx[name] = self.libelf.elf_ndxscn(scn)
        return scn, shdr, data
    def getscn(self, ndx):
        return self.libelf.elf_getscn(self.e, ndx)
    def ndxscn(self, scn):
        return self.libelf.elf_ndxscn(scn)
    def newdata(self, scn):
        return self.libelf.elf_newdata(scn)
    def getdata(self, scn, data):
        return self.libelf.elf_getdata(scn, data)
    def update(self, cmd):
        return self.libelf.elf_update(self.e, cmd)
    def end(self):
        return self.libelf.elf_end(self.e)

    def update_symbols(self, symbols):
        for s in symbols:
            secname = symbols[s].section
            if secname:
                scnidx = self.sectionidx[secname]
                scn = self.getscn(scnidx)
                shdr = self.getshdr(scn)
                symbols[s].addr += shdr.contents.addr

    def apply_relocations(self, reltab, symbols):
        for r in reltab:
            defval = symbols[r.symref].addr
            refscnidx = self.sectionidx[r.section]
            refscn = self.getscn(refscnidx)
            refshdr = self.getshdr(refscn)
            refdata = self.getdata(refscn, None)

            off = r.offset
            while off >= refdata.contents.size:
                off -= refdata.contents.size
                refdata = self.getdata(refscn, refdata)

            enc = 'little' if self.getehdr().contents.ident[elfdef.EI_DATA] == elfdef.ELFDATA2LSB else 'big'

            buf = ctypes.string_at(refdata.contents.buf, refdata.contents.size)
            match r.reltype:
                case RelType.abs4:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + defval).to_bytes(4, enc) + buf[off+4:]
                case RelType.rvhi:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + (defval & 0xfffff000)).to_bytes(4, enc) + buf[off+4:]
                case RelType.rvlo:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + ((defval & 0xfff) << 20)).to_bytes(4, enc) + buf[off+4:]
                case RelType.rvlo2:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + ((defval & 0xfe0) << 20) + ((defval & 0x1f) << 7)).to_bytes(4, enc) + buf[off+4:]
                case RelType.armmovtabs:
                    assert off + 4 <= refdata.contents.size
                    immhi = ((defval >> 12) & 0xf0000) | ((defval >> 16) & 0xfff)
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + immhi).to_bytes(4, enc) + buf[off+4:]
                case RelType.armmovwabs:
                    assert off + 4 <= refdata.contents.size
                    immlo = ((defval << 4) & 0xf0000) | (defval & 0xfff)
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + immlo).to_bytes(4, enc) + buf[off+4:]
                case RelType.aarch64lo16abs:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + ((defval & 0xffff) << 5)).to_bytes(4, enc) + buf[off+4:]
                case RelType.aarch64hi16abs:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + ((defval >> 11) & 0x1fffe0)).to_bytes(4, enc) + buf[off+4:]
                case RelType.rel4a:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (defval - (refshdr.contents.addr + r.offset + 4)).to_bytes(4, enc) + buf[off+4:]
                case RelType.rvjal:
                    assert off + 4 <= refdata.contents.size
                    disp = defval - (refshdr.contents.addr + r.offset)
                    jaldisp = ((disp & 0x100000) << 11) | ((disp & 0x7fe) << 20) | ((disp & 0x800) << 9) | (disp & 0xff00)
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) + jaldisp).to_bytes(4, enc) + buf[off+4:]
                case RelType.armb24:
                    assert off + 4 <= refdata.contents.size
                    disp = defval - (refshdr.contents.addr + r.offset + 8)
                    bdisp = (disp >> 2) & 0xffffff
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) | bdisp).to_bytes(4, enc) + buf[off+4:]
                case RelType.aarch64bc19:
                    assert off + 4 <= refdata.contents.size
                    disp = defval - (refshdr.contents.addr + r.offset)
                    bdisp = (disp >> 2) & 0x7ffff
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) | (bdisp << 5)).to_bytes(4, enc) + buf[off+4:]
                case RelType.aarch64b26:
                    assert off + 4 <= refdata.contents.size
                    disp = defval - (refshdr.contents.addr + r.offset)
                    bdisp = (disp >> 2) & 0x3ffffff
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], enc) | bdisp).to_bytes(4, enc) + buf[off+4:]
                case _:
                    raise ValueError('invalid relocation type')
            refdata.contents.buf = ctypes.cast(ctypes.create_string_buffer(buf, refdata.contents.size), ctypes.POINTER(ctypes.c_byte))

    def firstlastaddr(self, names, loadaddr):
        offset = -1
        addr = -1
        lastfileoffset = -1
        lastmemaddr = -1
        for name in names:
            if name in self.sectionidx:
                shdr = self.getshdr(self.getscn(self.sectionidx[name]))
                shdr.contents.addr = loadaddr + shdr.contents.offset
                offset = shdr.contents.offset if offset == -1 else min(offset, shdr.contents.offset)
                if shdr.contents.type == elfdef.SHT_PROGBITS:
                    lastfileoffset = max(lastfileoffset, shdr.contents.offset + shdr.contents.size)
                addr = shdr.contents.addr if addr == -1 else min(addr, shdr.contents.addr)
                lastmemaddr = max(lastmemaddr, shdr.contents.addr + shdr.contents.size)
            elif name == 'Ehdr':
                offset = 0
                lastfileoffset = max(lastfileoffset, ctypes.sizeof(self.traits.phdr_type))
                addr = loadaddr
                lastmemaddr = max(lastmemaddr, ctypes.sizeof(self.traits.phdr_type))
        return offset, addr, lastfileoffset - offset, lastmemaddr - addr


known_arch_os = {
    'Linux': {
        'x86_64': linux_x86_64_traits,
        'i[3456]86': linux_i386_traits,
        'rv32*': linux_rv32_traits,
        'rv64*': linux_rv64_traits,
        'armv[78]*': linux_arm_traits,
        'aarch64': linux_aarch64_traits,
    },
    'FreeBSD': {
        'amd64': freebsd_x86_64_traits,
    },
}


class Config(object):
    def __init__(self, system, processor):
        self.ps = resource.getpagesize()
        self.encoding = locale.getpreferredencoding()
        self.arch_os_traits = Config.determine_config(system, processor)
        self.loadaddr = self.arch_os_traits.get_loadaddr() if hasattr(self.arch_os_traits, 'get_loadaddr') else 0x40000

    def create_elf(self, fname, named=False):
        self.fname = fname

        if not named and hasattr(os, 'memfd_create'):
            fd = os.memfd_create(fname, os.MFD_CLOEXEC)
        elif not named and hasattr(os, 'O_TMPFILE'):
            fd = os.open('.', os.O_RDWR|os.O_CLOEXEC|os.O_TMPFILE, 0o777)
        else:
            fd = os.open(fname, os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_CLOEXEC, 0o777)

        self.e = elf(self.arch_os_traits)
        if not self.e.open(fd):
            raise RuntimeError("cannot open elf")

        ehdr = self.e.newehdr()
        ehdr.contents.ident[elfdef.EI_CLASS] = self.e.traits.elfclass
        ehdr.contents.ident[elfdef.EI_DATA] = self.arch_os_traits.get_endian()
        ehdr.contents.ident[elfdef.EI_OSABI] = elfdef.ELFOSABI_NONE
        ehdr.contents.type = elfdef.ET_EXEC
        ehdr.contents.machine = self.e.traits.machine

        return self.e

    def execute(self, args):
        if os.execve in os.supports_fd:
            try:
                os.execve(self.e.fd, [ self.fname ] + args, os.environ)
            except OSError as e:
                print(f'while executing: {e.args[1]}')
                exit(99)
        raise RuntimeError(f'platform {platform.system()} does not support execve on file descriptor')

    @staticmethod
    def determine_config(system, processor):
        system = system or platform.system()
        processor = processor or platform.processor()
        try:
            archs = known_arch_os[system]
            for a in archs:
                if fnmatch.fnmatch(processor, a):
                    return archs[a]()
        except KeyError:
            pass
        raise RuntimeError(f'unsupported OS/architecture {system}/{processor}')

    def known_syscall(self, name):
        return hasattr(self.arch_os_traits, 'SYS_' + name)


class Program(Config):
    entry = 'main'

    def __init__(self, system = None, processor = None):
        super().__init__(system, processor)
        self.id = 0
        self.symbols = dict()
        self.functions = dict()
        self.relocations = list()
        self.codebuf = bytebuf()
        self.rodatabuf = bytebuf()
        self.databuf = bytebuf()

    def gen_id(self, prefix = ''):
        res = '.L' + prefix + str(self.id)
        self.id += 1
        return res

    class ArgReg(object):
        def __init__(self, program, is_syscall):
            self.program = program
            self.is_syscall = is_syscall
            self.n_int = 0
            self.n_fp = 0
        def next(self, is_int: bool) -> Register:
            if self.is_syscall:
                assert is_int
                reg = self.program.arch_os_traits.get_syscall_arg_reg(self.n_int)
                self.n_int += 1
            elif is_int:
                reg = self.program.arch_os_traits.get_function_int_arg_reg(self.n_int)
                self.n_int += 1
            else:
                reg = self.program.arch_os_traits.get_function_fp_arg_reg(self.n_fp)
                self.n_fp += 1
            return reg

    def gen_load_val(self, reg, a):
        match a:
            case ast.Constant(val):
                self.codebuf += self.arch_os_traits.gen_loadimm(reg, val)
            case Symbol(_):
                for code, add, rel in self.arch_os_traits.gen_loadmem(reg, self.symbols[a.name].size):
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
            case StackSlot(_, offset):
                self.code += self.arch_os_traits.gen_frame_load(reg, offset)
            case _:
                raise RuntimeError(f'unhandled parameter type {type(a)}')

    def gen_load_ref(self, reg, a):
        match a:
            case Symbol(_):
                for code, add, rel in self.arch_os_traits.gen_loadref(reg, 0):
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
            case _:
                raise RuntimeError(f'unhandled parameter type {type(a)}')

    def gen_save_val(self, a, resexpr):
        if type(resexpr) == ast.Constant and hasattr(self.arch_os_traits, 'gen_saveimm'):
            res = self.arch_os_traits.gen_saveimm(resexpr, self.symbols[a.name].size)
            if res:
                for code, add, rel in res:
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
                return
        reg = self.force_reg(resexpr)
        match a:
            case Symbol(_):
                for code, add, rel in self.arch_os_traits.gen_savemem(reg, self.symbols[a.name].size):
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
            case _:
                raise RuntimeError(f'invalid store address {a}')
        self.arch_os_traits.release_reg(reg)

    def gen_aug_save_val(self, a, op, value):
        if type(value) == ast.Constant and hasattr(self.arch_os_traits, 'gen_aug_saveimm'):
            res = self.arch_os_traits.gen_aug_saveimm(op, value, self.symbols[a.name].size)
            if res:
                for code, add, rel in res:
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
                return
        if hasattr(self.arch_os_traits, 'gen_aug_savemem'):
            oldcode = len(self.codebuf)
            reg = self.force_reg(value)
            res = self.arch_os_traits.gen_aug_savemem(op, reg, self.symbols[a.name].size)
            if res:
                for code, add, rel in res:
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
                return
            self.release_reg(reg)
            self.codebuf = self.codebuf[:oldcode]
        reg = self.arch_os_traits.get_unused_reg(a.stype)
        self.gen_load_val(reg, a)
        self.gen_binop(reg, value, op)
        self.gen_save_val(a, reg)

    def gen_binop(self, resreg, rreg, op):
        # XYZ could implement subtraction with constant
        resreg = self.force_reg(resreg)
        rreg = self.force_reg(rreg)
        res = self.arch_os_traits.gen_binop(resreg, rreg, op)
        self.codebuf += res
        self.arch_os_traits.release_reg(rreg)
        return resreg

    def gen_unop(self, operand, op):
        operand = self.force_reg(operand)
        res = self.arch_os_traits.gen_unop(operand, op)
        self.codebuf += res
        return operand

    def gen_compare(self, l, r, op, condjmpctx):
        l = self.force_reg(l)
        r = self.force_reg(r)
        res, reg = self.arch_os_traits.gen_compare(l, r, op, condjmpctx)
        self.codebuf += res
        return Flags(op, reg)

    def gen_store_flag(self, op, reg=None):
        res, reg = self.arch_os_traits.gen_store_flag(op, reg)
        self.codebuf += res
        return reg

    def gen_condjump(self, test, exp, lab):
        """Jump to LAB if TEST is EXP."""
        test = self.compile_expr(test, True)
        match test:
            case Flags(_, _):
                for res, rel in self.arch_os_traits.gen_condjump(len(self.codebuf), test, exp, lab):
                    self.codebuf += res
                    if rel:
                        self.relocations.append(rel)
            case Register():
                test = self.gen_compare(test, ast.Constant(value=0), ast.NotEq())
                self.gen_condjump(test, exp, lab)
            case _:
                raise RuntimeError(f'unhandled condjump test {test}')

    def gen_jump(self, lab):
        for res, rel in self.arch_os_traits.gen_jump(len(self.codebuf), lab):
            self.codebuf += res
            if rel:
                self.relocations.append(rel)
        self.current_fct.last_fallthrough = False

    def gen_return(self):
        res = self.arch_os_traits.gen_destroy_stackframe()
        res += self.arch_os_traits.gen_return()
        self.codebuf += res
        self.current_fct.last_fallthrough = False

    def gen_call(self, lab):
        for res, rel in self.arch_os_traits.gen_call(len(self.codebuf), lab):
            self.codebuf += res
            if rel:
                self.relocations.append(rel)

    def gen_create_stackframe(self):
        res = self.arch_os_traits.gen_create_stackframe()
        self.codebuf += res

    def gen_destroy_stackframe(self):
        res = self.arch_os_traits.gen_destroy_stackframe()
        self.codebuf += res

    def gen_frame_store(self, reg):
        assert type(reg) == Register
        res, size = self.arch_os_traits.gen_frame_store(reg)
        self.codebuf += res
        self.current_fct.frame_size += size
        return self.current_fct.frame_size

    def gen_frame_load(self, reg, offset):
        res = self.arch_os_traits.gen_frame_load(reg, offset)
        self.codebuf += res

    def gen_syscall(self, nr, *args):
        self.codebuf += self.arch_os_traits.gen_syscall(getattr(self.arch_os_traits, 'SYS_' + nr))

    def get_endian_str(self):
        return 'little' if self.arch_os_traits.get_endian() == elfdef.ELFDATA2LSB else 'big'

    def elfgen(self, fname, named=False):
        if not self.entry in self.symbols:
            raise RuntimeError(f'no definition of »{self.entry}«')

        e = self.create_elf(fname, named)

        @enum.unique
        class phdrs(enum.IntEnum):
            code = 0
            data = 1

        @dataclass
        class Segment:
            idx: phdrs
            sections: list
            flags: int

        # At a minimum there is a .text section and an executable segment.
        segments = [
            Segment(phdrs.code, [ 'Ehdr', b'.text' ], elfdef.PF_R | elfdef.PF_X)
        ]
        need_rodata = len(self.rodatabuf) > 0
        if need_rodata:
            segments[phdrs.code].sections.append(b'.rodata')
        need_data = len(self.databuf) > 0
        if need_data:
            segments.append(Segment(phdrs.data, [ b'.data' ], elfdef.PF_R | elfdef.PF_W))

        phdr = e.newphdr(len(segments))

        codescn, codeshdr, codedata = e.newscn(b'.text', elfdef.SHT_PROGBITS, elfdef.SHF_ALLOC | elfdef.SHF_EXECINSTR, self.codebuf)

        if need_rodata:
            rodatascn, rodatashdr, rodatadata = e.newscn(b'.rodata', elfdef.SHT_PROGBITS, elfdef.SHF_ALLOC, self.rodatabuf)

        if need_data:
            datascn, datashdr, datadata = e.newscn(b'.data', elfdef.SHT_PROGBITS, elfdef.SHF_ALLOC | elfdef.SHF_WRITE, self.databuf)

        shstrscn, shstrshdr, shstrdata = e.newscn(b'.shstrtab', elfdef.SHT_STRTAB, 0, e.shstrtab, 1)

        size = e.update(elfdef.ELF_C_NULL)
        print(f'size={size}')

        lastvaddr = self.loadaddr
        for s in segments:
            lastvaddr = (lastvaddr + self.ps - 1) & ~(self.ps - 1)
            offset, addr, filesz, memsz = e.firstlastaddr(s.sections, lastvaddr)
            assert((offset & (self.ps - 1)) == (addr & (self.ps - 1)))
            phdr.contents[s.idx].type = elfdef.PT_LOAD
            phdr.contents[s.idx].flags = s.flags
            phdr.contents[s.idx].offset = offset
            phdr.contents[s.idx].vaddr = addr
            phdr.contents[s.idx].paddr = phdr.contents[s.idx].vaddr
            phdr.contents[s.idx].filesz = filesz
            phdr.contents[s.idx].memsz = memsz
            phdr.contents[s.idx].align = self.ps
            lastvaddr = phdr.contents[s.idx].vaddr + phdr.contents[s.idx].memsz

        e.update_symbols(self.symbols)

        e.apply_relocations(self.relocations, self.symbols)

        ehdr = e.getehdr()
        ehdr.contents.shstrndx = e.ndxscn(shstrscn)
        ehdr.contents.entry = self.symbols['main'].addr if 'main' in self.symbols else codeshdr.contents.addr

        size = e.update(elfdef.ELF_C_WRITE_MMAP)
        print(f'size={size}')

        status = e.end()
        print(f'status={status}')

        return self

    def clear_reg_use(self):
        parmregs = list()
        for v in self.current_fct.known:
            if type(self.current_fct.known[v]) == Register:
                parmregs.append(self.current_fct.known[v])
        self.arch_os_traits.clear_used(parmregs)

    class Function(object):
        def __init__(self, program, name, args, returntype):
            self.name = name
            self.paramreg = dict()
            self.paramname = list()
            self.last_fallthrough = True
            self.frame_size = 0
            argreg = Program.ArgReg(program, False)
            for a in args:
                match a:
                    case ast.arg(pname,ast.Name(ann)):
                        t = get_type(ann)
                        is_int = type_is_int(t)
                        reg = argreg.next(is_int)
                        self.paramreg[pname] = reg
                        self.paramname.append(pname)
                        program.arch_os_traits.mark_used(reg)
                    case _:
                        raise RuntimeError(f'unsupported argument {a}')
            self.returntype = returntype

    def define_variable(self, var, ann, value, arrsize=None):
        size = get_type_size(ann)
        addr = len(self.databuf)
        if addr % size != 0:
            npad = size * ((addr + size - 1) // size) - addr
            self.databuf += b'\x00' * npad
            addr += npad
        if arrsize:
            match value:
                case ast.List(elts):
                    for idx in range(arrsize):
                        match elts[idx % len(elts)]:
                            case ast.Constant(v) if type(v) == int:
                                self.databuf += v.to_bytes(size, self.get_endian_str())
                            case _:
                                raise RuntimeError('invalid variable value')
                case None:
                    self.databuf += b'\x00' * (size * arrsize)
                case _:
                    raise RuntimeError('invalid variable value')
        else:
            match value:
                case ast.Constant(v) if type(v) == int:
                    self.databuf += v.to_bytes(size, self.get_endian_str())
                case ast.Constant(v) if size == 1 and type(v) == str:
                    arrsize = len(v) + 1
                    self.databuf += bytearray(v, 'UTF-8') + b'\x00'
                case None:
                    self.databuf += b'\x00' * size
                case _:
                    raise RuntimeError('invalid variable value')
        self.symbols[var] = Symbol(var, size * (arrsize if arrsize else 1), ann, b'.data', addr)

    def store_cstring(self, s):
        offset = len(self.rodatabuf)
        self.rodatabuf += bytes(s, self.encoding) + b'\x00'
        id = self.gen_id('str')
        self.symbols[id] = Symbol(id, len(self.rodatabuf) - offset, RegType.ptr, b'.rodata', offset)
        return id

    def get_function_res_reg(self, type):
        return self.arch_os_traits.get_function_res_reg(type_is_int(type))

    def force_this_reg(self, expr, reg):
        match expr:
            case ast.Constant(_):
                self.gen_load_val(reg, expr)
            case Register(is_int, n):
                if reg.is_int != is_int:
                    raise RuntimeError(f'conversion of return value not implemented')
                if reg.n != n:
                    res = self.arch_os_traits.gen_move_reg(reg, expr)
                    self.codebuf += res
            case Flags(op, freg):
                if not freg:
                    self.gen_store_flag(op, reg)
                elif not reg.is_int:
                    raise RuntimeError(f'conversion of return value not implemented')
                elif reg.n != freg.n:
                    res = self.arch_os_traits.gen_move_reg(reg, freg)
                    self.codebuf += res
            case _:
                raise RuntimeError(f'cannot force {expr} into register {reg}')

    def force_reg(self, expr):
        match expr:
            case ast.Constant(_):
                reg = self.arch_os_traits.get_unused_reg(get_type(expr))
                self.gen_load_val(reg, expr)
                return reg
            case Register():
                # Already in a register
                return expr
            case Flags(op, reg):
                if not reg:
                    reg = self.gen_store_flag(op)
                return reg
            case _:
                raise RuntimeError(f'cannot force {expr} into register')

    @staticmethod
    def fold_binop(l, r, op):
        match op:
            case ast.Add():
                return ast.Constant(value=(l.value + r.value))
            case ast.Sub():
                return ast.Constant(value=(l.value - r.value))
            case ast.BitAnd():
                return ast.Constant(value=(l.value & r.value))
            case ast.BitOr():
                return ast.Constant(value=(l.value | r.value))
            case ast.BitXor():
                return ast.Constant(value=(l.value ^ r.value))
            case _:
                raise RuntimeError(f'unsupport binop {op}')

    @staticmethod
    def fold_unop(operand, op):
        match op:
            case ast.USub():
                return ast.Constant(value=-operand.value)
            case _:
                raise RuntimeError(f'unsupported unaryop')

    @staticmethod
    def fold_compare(l, r, op):
        match op:
            case ast.Eq():
                return ast.Constant(value=(l.value == r.value))
            case _:
                raise RuntimeError(f'unsupport compare {op}')

    def compile_expr(self, e, condjmpctx=False):
        match e:
            case ast.Constant(value):
                return e
            case ast.Name(id):
                if id in self.current_fct.known:
                    if type(self.current_fct.known[id]) == Register:
                        reg = self.current_fct.known[id]
                    else:
                        reg = self.arch_os_traits.get_unused_reg(RegType.ptr if self.current_fct.known[id].is_int else RegType.float64)
                        self.gen_frame_load(reg, self.current_fct.known[id].offset)
                else:
                    reg = self.arch_os_traits.get_unused_reg(self.symbols[id].stype)
                    self.gen_load_val(reg, self.symbols[id])
                return reg
            case ast.BinOp(l, op, r):
                l = self.compile_expr(l)
                r = self.compile_expr(r)
                if type(l) == ast.Constant and type(r) == ast.Constant:
                    return self.fold_binop(l, r, op)
                return self.gen_binop(l, r, op)
            case ast.UnaryOp(op, operand):
                operand = self.compile_expr(operand)
                if type(operand) == ast.Constant:
                    return self.fold_unop(operand, op)
                return self.gen_unop(operand, op)
            case ast.Compare(l,[op],[r]):
                if type(l) == ast.Constant and type(r) == ast.Constant:
                    return self.fold_compare(l, r, op)
                l = self.compile_expr(l)
                r = self.compile_expr(r)
                return self.gen_compare(l, r, op, condjmpctx)
            case ast.Call(ast.Name(name,_),args,[]):
                return self.compile_call(name, args)
            case _:
                raise RuntimeError(f'unhandled expression type {e}')

    def compile_call(self, name, args):
        is_syscall = self.known_syscall(name)
        if not is_syscall:
            called = self.functions[name]
        else:
            argreg = Program.ArgReg(self, is_syscall)

        # XYZ Don't save for syscalls if not necessary
        for v in self.current_fct.known:
            if type(self.current_fct.known[v]) == Register:
                offset = self.gen_frame_store(self.current_fct.known[v])
                self.current_fct.known[v] = StackSlot(self.current_fct.known[v].is_int, offset)

        for idx, a in enumerate(args):
            if is_syscall:
                preg = argreg.next(True)
            else:
                pname = called.paramname[idx]
                preg = called.paramreg[pname]
            match a:
                case ast.Constant(s) if type(s) == int:
                    self.gen_load_val(preg, a)
                case ast.Constant(s) if type(s) == str:
                    id = self.store_cstring(s)
                    self.gen_load_ref(preg, self.symbols[id])
                case ast.Name(id,_):
                    if id in self.current_fct.known:
                        self.gen_load_val(preg, self.current_fct.known[id])
                    else:
                        self.gen_load_val(preg, self.symbols[id])
                case _:
                    raise RuntimeError(f'unhandled function parameter type {a}')
        if is_syscall:
            self.gen_syscall(name, *args)
            resreg = self.arch_os_traits.get_syscall_res_reg()
        else:
            self.gen_call(name)
            if called.returntype == RegType.none:
                resreg = None
                print(f'function {name} is void')
            else:
                resreg = self.arch_os_traits.get_function_res_reg(type_is_int(called.returntype))

        # Return register carrying results.
        return resreg

    def compile_stmts(self, stmts):
        for e in stmts:
            self.clear_reg_use()
            self.current_fct.last_fallthrough = True
            match e:
                case ast.Expr(ast.Call(ast.Name(name,_),args,[])):
                    self.compile_call(name, args)
                case ast.Assign([ ast.Name(target,_) ], expr):
                    if not target in self.symbols:
                        raise RuntimeError('assignment to unknown variable {target}')
                    expr = self.compile_expr(expr)
                    self.gen_save_val(self.symbols[target], expr)
                case ast.AugAssign(ast.Name(target), op, expr):
                    if not target in self.symbols:
                        raise RuntimeError('assignment to unknown variable {target}')
                    expr = self.compile_expr(expr)
                    self.gen_aug_save_val(self.symbols[target], op, expr)
                case ast.If(test, ifbody, orelse):
                    endlabel = self.gen_id('lab')
                    elselabel = self.gen_id('lab') if orelse else endlabel
                    self.gen_condjump(test, False, elselabel)
                    self.compile_stmts(ifbody)
                    if orelse:
                        self.gen_jump(endlabel)
                        self.symbols[elselabel] = Symbol(id, 0, RegType.ptr, b'.text', len(self.codebuf))
                        self.compile_stmts(orelse)
                    self.symbols[endlabel] = Symbol(id, 0, RegType.ptr, b'.text', len(self.codebuf))
                case ast.Return(expr):
                    if self.current_fct.returntype == RegType.none:
                        if expr:
                            raise RuntimeError(f'function {self.current_fct.name} defined to have no return type')
                    else:
                        if not expr:
                            raise RuntimeError(f'function {self.current_fct.name} defined to return {self.current_fct.returntype}')
                        expr = self.compile_expr(expr)
                        self.force_this_reg(expr, self.get_function_res_reg(self.current_fct.returntype))
                    self.gen_return()
                case _:
                    raise RuntimeError(f'unhandled function call {e}')

    def compile_body(self, name, args, body, returns):
        match returns:
            case ast.Name(t):
                returntype = RegType[t]
            case None:
                returntype = RegType.none
            case _:
                raise RuntimeError(f'unhandled return type {returns}')
        self.current_fct = self.functions[name]
        self.current_fct.known = copy.deepcopy(self.current_fct.paramreg)
        self.gen_create_stackframe()
        self.compile_stmts(body)
        if self.current_fct.last_fallthrough:
            self.gen_return()

    def compile(self, source):
        tree = ast.parse(source)

        print(ast.dump(tree, indent=2))

        for b in tree.body:
            match b:
                case ast.FunctionDef(name,ast.arguments([],args,kwo,[],[]),_,_,returns):
                    if name in self.functions:
                        print(f'duplicate definition of function {name}')
                    self.functions[name] = Program.Function(self, name, args, get_type(returns.id) if returns else RegType.none)
                case ast.Assign([ast.Name(target, _)],value):
                    self.define_variable(target, get_type(value), value)
                case ast.AnnAssign(ast.Name(target, _),ast.Name(ann,_),value,_):
                    self.define_variable(target, get_type(ann), value)
                case ast.AnnAssign(ast.Name(target, _),ast.Subscript(ast.Name(ann,_),ast.Constant(arrsize),_),value,_) if type(arrsize) == int:
                    self.define_variable(target, get_type(ann), value, arrsize)
                case _:
                    raise RuntimeError(f'unhandled AST node {b}')

        for b in tree.body:
            match b:
                case ast.FunctionDef(name,ast.arguments([],args,kwo,[],[]),body,_,returns) if not kwo:
                    self.symbols[name] = Symbol(name, 0, RegType.ptr, b'.text', len(self.codebuf))
                    self.compile_body(name, args, body, returns)
                    self.symbols[name].size = len(self.codebuf) - self.symbols[name].addr
                # No need for further checks for valid values, it is done in the first loop

        return self


def main(fname):
    """Create and run binary.  Use FNAME as the file name."""
    source = r'''
def main():
    write(1, 'Hello World\n', 12)
    write(1, 'Good Bye\n', 9)
    status = status - 1 + ((other | (16 ^ 32)) & 4) + (other ^ 8)
    other = status == 0
    status = status + (1 ^ other)
    if other != 1:
        status = 1
    else:
        other += 1
        other += status - 1
    status = f(status)
    exit(status)
def f(a:int32) -> int32:
    write(1, 'in f\n', 5)
    return a != 0
status:int32 = 1
other:int32 = 8
uninit:int32
arr:int8[100] = [ 1,2,3 ]
s:int8 = 'hello world 2\n'
'''

    import argparse
    parser = argparse.ArgumentParser(description='in-memory execution JIT')
    parser.add_argument('--named', action='store_true')
    parser.add_argument('-p', '--processor')
    parser.add_argument('-s', '--system')
    parser.add_argument('remaining', nargs='*')
    parsed = parser.parse_args()

    Program(parsed.system, parsed.processor).compile(source).elfgen(fname, parsed.named).execute(parsed.remaining)


main(b'test')
exit(42)
