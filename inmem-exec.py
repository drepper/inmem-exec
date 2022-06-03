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
from dataclasses import dataclass


@enum.unique
class RelType(enum.Enum):
    none = 0
    abs4 = 1
    rvhi = 2
    rvlo = 3
    armmovwabs = 4
    armmovtabs = 5
    aarch64lo16abs = 6
    aarch64hi16abs = 7


@dataclass
class Symbol:
    name: str
    size: int
    section: bytes
    addr: int


@dataclass
class Relocation:
    symref: str
    section: bytes
    offset: int
    reltype: RelType


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


class x86_64_encoding:
    nbits = 64           # processor bits
    elf_machine = elfdef.EM_X86_64

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

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        rex = 0x41 if reg >= 8 else 0
        if (val < -2147483648 or val > 2147483647) if signed else val > 4294967295:
            rex |= 0x48
            valwidth = 8
        else:
            valwidth = 4
        res = (rex.to_bytes(1, 'little') if rex else b'') + (0xb8 + (reg & 0b111)).to_bytes(1, 'little') + val.to_bytes(valwidth, 'little')
        return res

    @staticmethod
    def gen_loadmem(reg, width):
        rex = 0x44 if reg >= 8 else 0
        if width > 4:
            rex |= 0x48
        res = (rex.to_bytes(1, 'little') if rex else b'') + b'\x8b' + (0x04 + ((reg & 0b111) << 3)).to_bytes(1, 'little') + b'\x25' + b'\x00\x00\x00\x00'
        return [ (res, (4 if rex else 3), RelType.abs4) ]

    @staticmethod
    def gen_loadref(reg, offset):
        # We always assume a small memory model, references are 4 bytes
        rex = 0x41 if reg >= 8 else 0
        res = (rex.to_bytes(1, 'little') if rex else b'') + (0xb8 + (reg & 0b111)).to_bytes(1, 'little') + offset.to_bytes(4, 'little')
        return [ (res, (2 if rex else 1), RelType.abs4) ]


class i386_encoding:
    nbits = 32           # processor bits
    elf_machine = elfdef.EM_386

    rAX = 0b000
    rCX = 0b001
    rDX = 0b010
    rBX = 0b011
    rSP = 0b100
    rBP = 0b101
    rSI = 0b110
    rDI = 0b111

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        res = (0xb8 + reg).to_bytes(1, 'little') + val.to_bytes(4, 'little')
        return res

    @staticmethod
    def gen_loadmem(reg, width):
        res = b'\x8b' + (0x05 + (reg << 3)).to_bytes(1, 'little') + b'\x00\x00\x00\x00'
        return [ (res, 2, RelType.abs4) ]

    @staticmethod
    def gen_loadref(reg, offset):
        # We always assume a small memory model, references are 4 bytes
        res = (0xb8 + reg).to_bytes(1, 'little') + offset.to_bytes(4, 'little')
        return [ (res, 1, RelType.abs4) ]


class rv32_encoding:
    nbits = 32           # processor bits
    elf_machine = elfdef.EM_RISCV

    rA0 = 0b01010
    rA1 = 0b01011
    rA2 = 0b01100
    rA3 = 0b01101
    rA4 = 0b01110
    rA5 = 0b01111
    rA6 = 0b10000
    rA7 = 0b10001

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        if val >= -2048 and val < 2048:
            word = ((val & 0xfff) << 20) | (reg << 7) | 0b0010011
            res = word.to_bytes(4, 'little')
        else:
            word1 = (val & 0xfffff000) | (reg << 7) | 0b0110111
            word2 = ((val & 0xfff) << 20) | (reg << 15) | (reg << 7) | 0b0010011
            res = word1.to_bytes(4, 'little') + word2.to_bytes(4, 'little')
        return res

    @staticmethod
    def gen_loadmem(reg, width, signed = False):
        word1 = (reg << 7) | 0b0110111
        res1 = word1.to_bytes(4, 'little')
        logwidth = math.frexp(width)[1] - 1
        word2 = (reg << 15) | ((logwidth | (0 if signed or width == 4 else 0b100)) << 12) | (reg << 7) | 0b0000011
        res2 = word2.to_bytes(4, 'little')
        return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo) ]

    @staticmethod
    def gen_loadref(reg, offset):
        word1 = (reg << 7) | 0b0110111
        res1 = word1.to_bytes(4, 'little')
        word2 = (reg << 15) | (reg << 7) | 0b0010011
        res2 = word2.to_bytes(4, 'little')
        return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo) ]


class rv64_encoding:
    nbits = 64           # processor bits
    elf_machine = elfdef.EM_RISCV

    rA0 = 0b01010
    rA1 = 0b01011
    rA2 = 0b01100
    rA3 = 0b01101
    rA4 = 0b01110
    rA5 = 0b01111
    rA6 = 0b10000
    rA7 = 0b10001

    @staticmethod
    def gen_loadimm(reg, val, width = 0, signed = False):
        if val >= -2048 and val < 2048:
            word = ((val & 0xfff) << 20) | (reg << 7) | 0b0010011
            res = word.to_bytes(4, 'little')
        else:
            word1 = (val & 0xfffff000) | (reg << 7) | 0b0110111
            word2 = ((val & 0xfff) << 20) | (reg << 15) | (reg << 7) | 0b0010011
            res = word1.to_bytes(4, 'little') + word2.to_bytes(4, 'little')
        return res

    @staticmethod
    def gen_loadmem(reg, width, signed = False):
        word1 = (reg << 7) | 0b0110111
        res1 = word1.to_bytes(4, 'little')
        logwidth = math.frexp(width)[1] - 1
        word2 = (reg << 15) | ((logwidth | (0 if signed or width == 8 else 0b100)) << 12) | (reg << 7) | 0b0000011
        res2 = word2.to_bytes(4, 'little')
        return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo) ]

    @staticmethod
    def gen_loadref(reg, offset):
        # We always assume a small memory model, references are 4 bytes
        word1 = (reg << 7) | 0b0110111
        res1 = word1.to_bytes(4, 'little')
        word2 = (reg << 15) | (reg << 7) | 0b0010011
        res2 = word2.to_bytes(4, 'little')
        return [ (res1, 0, RelType.rvhi), (res2, 0, RelType.rvlo) ]


class arm_encoding:
    nbits = 32           # processor bits
    elf_machine = elfdef.EM_ARM
    endian = 'little'

    r0 = 0b0000
    r1 = 0b0001
    r2 = 0b0010
    r3 = 0b0011
    r4 = 0b0100
    r5 = 0b0101
    r6 = 0b0110
    r7 = 0b0111

    @classmethod
    def gen_loadimm(cls, reg, val, width = 0, signed = False):
        if val >= 0:
            if val < 4096:
                res = (0xe3a00000 | (reg << 12) | val).to_bytes(4, cls.endian)
            else:
                res = (0xe3000000 | ((val & 0xf000) << 4) | (reg << 12) | (val & 0xfff)).to_bytes(4, cls.endian)
                if val >= 65536:
                    res += (0xe3400000 | ((val >> 12) & 0xf0000) | ((val >> 16) & 0xfff)).to_bytes(4, cls.endian)
        else:
            if val >= -0x101:
                res = (0xe3e00000 | ~val).to_bytes(4, cls.endian)
            else:
                res = (0xe3000000 | ((val & 0xf000) << 4) | (val & 0xfff)).to_bytes(4, cls.endian)
                res += (0xe3400000 | ((val >> 12) & 0xf0000) | ((val >> 16) & 0xfff)).to_bytes(4, cls.endian)
        return res

    @classmethod
    def gen_loadmem(cls, reg, width, signed = False):
        res1 = (0xe3000000 | (reg << 12)).to_bytes(4, cls.endian)
        res2 = (0xe3400000 | (reg << 12)).to_bytes(4, cls.endian)
        res3 = (0xe5900000 | (reg << 16) | (reg << 12)).to_bytes(4, cls.endian)
        return [ (res1, 0, RelType.armmovwabs), (res2, 0, RelType.armmovtabs), (res3, 0, RelType.none) ]

    @classmethod
    def gen_loadref(cls, reg, offset):
        res1 = (0xe3000000 | (reg << 12)).to_bytes(4, cls.endian)
        res2 = (0xe3400000 | (reg << 12)).to_bytes(4, cls.endian)
        return [ (res1, 0, RelType.armmovwabs), (res2, 0, RelType.armmovtabs) ]


class aarch64_encoding:
    nbits = 64           # processor bits
    elf_machine = elfdef.EM_AARCH64
    endian = 'little'

    x0 = 0b00000
    x1 = 0b00001
    x2 = 0b00010
    x3 = 0b00011
    x4 = 0b00100
    x5 = 0b00101
    x6 = 0b00110
    x7 = 0b00111
    x8 = 0b01000

    @classmethod
    def gen_loadimm(cls, reg, val, width = 0, signed = False):
        if val >= 0 and val < 65536:
            res = (0xd2800000 | (val << 5) | reg).to_bytes(4, cls.endian)
        elif val < 0 and -val >= 0x10000:
            res = (0x92800000 | ((-val - 1) << 5) | reg).to_bytes(4, cls.endian)
        elif -val == 0x10001:
            res = (0x92a00020 | reg).to_bytes(4, cls.endian)
        elif val < 0 and -val <= 0xffffffff:
            res = (0x92800000 | (((-val & 0xffff) - 1) << 5) | reg).to_bytes(4, cls.endian)
            res += (0xf2a00000 | ((val >> 11) & 0x1fffe0) | reg).to_bytes(4, cls.endian)
        elif val >= 0 and val <= 0xffffffff:
            res = (0xd2800000 | ((val & 0xffff) << 5) | reg).to_bytes(4, cls.endian)
            res += (0xf2a00000 | ((val >> 11) & 0x1fffe0) | reg).to_bytes(4, cls.endian)
        return res

    @classmethod
    def gen_loadmem(cls, reg, width, signed = False):
        res1 = (0xd2800000 | reg).to_bytes(4, cls.endian)
        res2 = (0xf2a00000 | reg).to_bytes(4, cls.endian)
        res3 = ((0xf9400000 if width == 8 else 0xb9400000) | (reg << 5) | reg).to_bytes(4, cls.endian)
        return [ (res1, 0, RelType.aarch64lo16abs), (res2, 0, RelType.aarch64hi16abs), (res3, 0, RelType.none) ]

    @classmethod
    def gen_loadref(cls, reg, offset):
        res1 = (0xd2800000 | reg).to_bytes(4, cls.endian)
        res2 = (0xf2a00000 | reg).to_bytes(4, cls.endian)
        return [ (res1, 0, RelType.aarch64lo16abs), (res2, 0, RelType.aarch64hi16abs) ]


# OS+CPU traits
class linux_x86_64_traits(x86_64_encoding):
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
        return cls.syscall_arg_regs[nr]

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.rAX, nr)
        res += b'\x0f\x05'                          # syscall
        return res


class linux_i386_traits(i386_encoding):
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
        return cls.syscall_arg_regs[nr]

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.rAX, nr)
        res += b'\xcd\x80'                          # int $0x80
        return res


class linux_rv32_traits(rv32_encoding):
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
        return cls.syscall_arg_regs[nr]

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.rA7, nr)
        res += b'\x73\x00\x00\x00'       # ecall
        return res


class linux_rv64_traits(rv64_encoding):
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
        return cls.syscall_arg_regs[nr]

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.rA7, nr)
        res += b'\x73\x00\x00\x00'       # ecall
        return res


class linux_arm_traits(arm_encoding):
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
        return cls.syscall_arg_regs[nr]

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.r7, nr)
        res += (0xef000000).to_bytes(4, cls.endian)  # swi #0
        return res


class linux_aarch64_traits(aarch64_encoding):
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
        return cls.syscall_arg_regs[nr]

    @classmethod
    def gen_syscall(cls, nr):
        res = cls.gen_loadimm(cls.x8, nr)
        res += (0xd4000001).to_bytes(4, cls.endian)  # svc #0
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
    def __init__(self, machine, bits):
        self.libelf = ctypes.cdll.LoadLibrary('/$LIB/libelf.so.1')
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
        self.traits = elf64_traits(self, machine, self.libelf) if bits == 64 else elf32_traits(self, machine, self.libelf)
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
            refdata = self.getdata(refscn, None)

            off = r.offset
            while off >= refdata.contents.size:
                off -= refdata.contents.size
                refdata = self.getdata(refscn, refdata)

            buf = ctypes.string_at(refdata.contents.buf, refdata.contents.size)
            match r.reltype:
                case RelType.abs4:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + defval).to_bytes(4, 'little') + buf[off+4:]
                case RelType.rvhi:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + (defval & 0xfffff000)).to_bytes(4, 'little') + buf[off+4:]
                case RelType.rvlo:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + ((defval & 0xfff) << 20)).to_bytes(4, 'little') + buf[off+4:]
                case RelType.armmovtabs:
                    assert off + 4 <= refdata.contents.size
                    immhi = ((defval >> 12) & 0xf0000) | ((defval >> 16) & 0xfff)
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + immhi).to_bytes(4, 'little') + buf[off+4:]
                case RelType.armmovwabs:
                    assert off + 4 <= refdata.contents.size
                    immlo = ((defval << 4) & 0xf0000) | (defval & 0xfff)
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + immlo).to_bytes(4, 'little') + buf[off+4:]
                case RelType.aarch64lo16abs:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + ((defval & 0xffff) << 5)).to_bytes(4, 'little') + buf[off+4:]
                case RelType.aarch64hi16abs:
                    assert off + 4 <= refdata.contents.size
                    buf = buf[:off] + (int.from_bytes(buf[off:off+4], 'little') + ((defval >> 11) & 0x1fffe0)).to_bytes(4, 'little') + buf[off+4:]
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
    }
}


class Config(object):
    def __init__(self, system, processor):
        self.ps = resource.getpagesize()
        self.encoding = locale.getpreferredencoding()
        self.arch_os_traits = Config.determine_config(system, processor)
        self.loadaddr = self.arch_os_traits.get_loadaddr() if hasattr(self.arch_os_traits, 'get_loadaddr') else 0x40000

    def create_elf(self, fname):
        self.fname = fname

        if hasattr(os, 'memfd_create'):
            fd = os.memfd_create(fname, os.MFD_CLOEXEC)
        else:
            fd = os.open(fname, os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_CLOEXEC, 0o777)

        self.e = elf(self.arch_os_traits.elf_machine, self.arch_os_traits.nbits)
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
            except OSError:
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
                    return archs[a]
        except KeyError:
            pass
        raise RuntimeError(f'unsupported OS/architecture {system}/{processor}')

    def known_syscall(self, name):
        return hasattr(self.arch_os_traits, 'SYS_' + name)


class Program(Config):
    def __init__(self, system = None, processor = None):
        super().__init__(system, processor)
        self.id = 0
        self.symbols = dict()
        self.relocations = list()
        self.codebuf = bytebuf()
        self.rodatabuf = bytebuf()
        self.databuf = bytebuf()

    def gen_id(self, prefix = ''):
        res = '.L' + prefix + str(self.id)
        self.id += 1
        return res

    def gen_load_arg(self, is_syscall, n, a):
        reg = self.arch_os_traits.get_syscall_arg_reg(n) if is_syscall else self.arch_os_traits.get_function_arg_reg(n)
        match a:
            case int(val):
                self.codebuf += self.arch_os_traits.gen_loadimm(reg, val)
            case Symbol(_):
                for code, add, rel in self.arch_os_traits.gen_loadmem(reg, self.symbols[a.name].size):
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
            case _:
                raise RuntimeError(f'unhandled parameter type {type(a)}')

    def gen_load_ref(self, is_syscall, n, a):
        reg = self.arch_os_traits.get_syscall_arg_reg(n) if is_syscall else self.arch_os_traits.get_function_arg_reg(n)
        match a:
            case Symbol(_):
                for code, add, rel in self.arch_os_traits.gen_loadref(reg, 0):
                    add += len(self.codebuf)
                    self.codebuf += code
                    if rel != RelType.none:
                        self.relocations.append(Relocation(a.name, b'.text', add, rel))
            case _:
                raise RuntimeError(f'unhandled parameter type {type(a)}')

    def gen_syscall(self, nr, *args):
        self.codebuf += self.arch_os_traits.gen_syscall(getattr(self.arch_os_traits, 'SYS_' + nr))

    def get_endian_str(self):
        return 'little' if self.arch_os_traits.get_endian() == elfdef.ELFDATA2LSB else 'big'

    def elfgen(self, fname):
        e = self.create_elf(fname)

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

        e.update(elfdef.ELF_C_NULL)

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

        e.update(elfdef.ELF_C_WRITE_MMAP)

        e.end()

        return self


def get_type(value):
    match value:
        case ast.Constant(value):
            if type(value) == int:
                return 'int'
            if type(value) == str:
                return 'str'
    raise RuntimeError('invalid value type')


def define_variable(program, var, ann, value):
    match ann:
        case 'int':
            size = 4
        case 'long' | 'ptr':
            size = program.arch_os_traits.nbits / 8
        case _:
            raise RuntimeError('invalid annotation')
    addr = len(program.databuf)
    if addr % size != 0:
        npad = size * ((addr + size - 1) // size) - addr
        program.databuf += b'\x00' * npad
        addr += npad
    program.symbols[var] = Symbol(var, size, b'.data', addr)
    match value:
        case ast.Constant(v) if type(v) == int:
            program.databuf += v.to_bytes(size, program.get_endian_str())
        case _:
            raise RuntimeError('invalid variable value')


def store_cstring(program, s):
    offset = len(program.rodatabuf)
    program.rodatabuf += bytes(s, program.encoding) + b'\x00'
    id = program.gen_id('str')
    program.symbols[id] = Symbol(id, len(program.rodatabuf) - offset, b'.rodata', offset)
    return id


def compile_body(body, program):
    for e in body:
        match e:
            case ast.Expr(ast.Call(ast.Name(name,_),args,[])):
                is_syscall = program.known_syscall(name)

                for idx, a in enumerate(args):
                    match a:
                        case ast.Constant(s) if type(s) == int:
                            program.gen_load_arg(is_syscall, idx, s)
                        case ast.Constant(s) if type(s) == str:
                            id = store_cstring(program, s)
                            program.gen_load_ref(is_syscall, idx, program.symbols[id])
                        case ast.Name(id,_):
                            program.gen_load_arg(is_syscall, idx, program.symbols[id])
                        case _:
                            raise RuntimeError(f'unhandled function parameter type {a}')
                if is_syscall:
                    program.gen_syscall(name, *args)
                else:
                    # XYZ generate code
                    print(f'function {name} with {len(args)} arguments')
            case _:
                raise RuntimeError(f'unhandled function call {e}')


def compile(source, system = None, processor = None):
    program = Program(system, processor)
    tree = ast.parse(source)

    # print(ast.dump(tree, indent=2))

    for b in tree.body:
        match b:
            case ast.FunctionDef(name,_,_,_):
                pass
            case ast.Assign([ast.Name(target, _)],value):
                define_variable(program, target, get_type(value), value)
            case ast.AnnAssign(ast.Name(target, _),ast.Name(ann,_),value,_):
                define_variable(program, target, ann, value)
            case _:
                raise RuntimeError(f'unhandled AST node {b}')

    for b in tree.body:
        match b:
            case ast.FunctionDef(name,_,_,_):
                program.symbols[name] = Symbol(name, 0, b'.text', len(program.codebuf))
                # XYZ handle arguments
                compile_body(b.body, program)
            # No need for further checks for valid values, it is done in the first loop

    return program


def main(fname, args):
    """Create and run binary.  Use FNAME as the file name and the optional list ARGS as arguments."""
    source = r'''
def main():
    write(1, 'Hello World\n', 12)
    write(1, 'Good Bye\n', 9)
    exit(status)
status:int = 0
'''

    system = None
    processor = None
    if args:
        processor = args[0]
        args = args[1:]
    if args:
        system = processor
        processor = args[0]
        args = args[1:]

    compile(source, system = system, processor = processor).elfgen(fname).execute(args)


main(b'test', sys.argv[1:])
exit(42)
