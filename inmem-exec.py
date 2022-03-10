import ctypes
import enum
import os
import platform
import sys

libc = ctypes.CDLL(None)

# OS traits
MFD_CLOEXEC = 1
AT_EMPTY_PATH = 0x1000

# OS+CPU traits
SYS_execveat = 322
SYS_memfd_create = 319


class elfstrtab(object):
    def __init__(self):
        self.s = b''
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
    def __init__(self, b):
        self.b = b
    def data(self):
        return self.b
    def __len__(self):
        return len(self.b)


class elf_data(ctypes.Structure):
    _fields_ = [
        ('buf', ctypes.c_char_p),
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


class elf32_traits(object):
    Word = ctypes.c_int32
    Xword = ctypes.c_int32
    Addr = ctypes.c_int32

    def __init__(self):
        self.e = e
        self.libelf = libelf
    def newehdr(self):
        return elf32_ehdr.from_address(self.libelf.elf32_newehdr(self.e))
    def newphdr(self, cnt):
        return self.libelf.elf32_newphdr(self.e, cnt)
    def getshdr(self, scn):
        return elf32_shdr.from_address(self.libelf.elf32_getshdr(scn))


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

class x86_64_traits(object):
    @enum.unique
    class reloc(enum.Enum):
        abs4 = 1
    def __init__(self):
        pass
    def applyrelocations(self, reltab, symbols):
        for symname, scnname, off, typ in reltab:


class elf64_traits(object):
    Word = ctypes.c_int32
    Xword = ctypes.c_int64
    Addr = ctypes.c_int64

    def __init__(self, e, libelf, machine):
        self.libelf = libelf
        self.libelf.elf_begin.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        self.libelf.elf_begin.restype = (ctypes.c_void_p)
        self.libelf.elf64_newehdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_newehdr.restype = (ctypes.POINTER(elf64_ehdr))
        self.libelf.elf64_newphdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_newphdr.restype = (ctypes.POINTER(elf64_phdr))
        self.libelf.elf64_getshdr.argtypes = [ctypes.c_void_p]
        self.libelf.elf64_getshdr.restype = (ctypes.POINTER(elf64_shdr))
        self.elfclass = e.ELFCLASS64
        self.machine = e.get_machine(64)
        match self.machine:
            case 'x86_64':
                self.machtraits = x86_64_traits()
            case _:
                raise "invalid machine"
    def newehdr(self, e):
        return self.libelf.elf64_newehdr(e)
    def newphdr(self, e, cnt):
        return self.libelf.elf64_newphdr(e, cnt)
    def getshdr(self, scn):
        return self.libelf.elf64_getshdr(scn)
    def applyrelocations(self, reltab, symbols):
        return self.machtraits.applyrelocations(reltab, symbols)

class elf(object):
    EV_CURRENT = 1
    ET_EXEC = 2
    C_WRITE = 3
    ELFMAG = b'\177ELF'
    SELFMAG = 4
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
    EM_ARM = 40
    EM_X86_64 = 62
    SHT_PROGBITS = 1
    SHT_STRTAB = 3
    SHF_ALLOC = 2
    SHF_EXECINSTR = 4
    ELF_T_BYTE = 0
    ELF_C_NULL = 0
    ELF_C_WRITE_MMAP = 10

    def __init__(self, bits):
        self.libelf = ctypes.cdll.LoadLibrary('/$LIB/libelf.so.1')
        if self.libelf.elf_version(self.EV_CURRENT) != self.EV_CURRENT:
            raise "invalid libelf version"
        self.libelf.elf_newscn.argtypes = [ctypes.c_void_p]
        self.libelf.elf_newscn.restype = (ctypes.c_void_p)
        self.libelf.elf_newdata.argtypes = [ctypes.c_void_p]
        self.libelf.elf_newdata.restype = (ctypes.POINTER(elf_data))
        self.libelf.elf_update.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.libelf.elf_update.restype = (ctypes.c_uint64)
        self.libelf.elf_end.argtypes = [ctypes.c_void_p]
        self.libelf.elf_end.restype = (ctypes.c_int)
        self.libelf.elf_ndxscn.argtypes = [ctypes.c_void_p]
        self.libelf.elf_ndxscn.restype = (ctypes.c_size_t)
        self.traits = elf64_traits(self, self.libelf) if bits == 64 else elf32_traits(self, self.libelf)
        self.shstrtab = elfstrtab()
        self.sectionidx = dict()
    def open(self, fd):
        self.fd = fd
        self.e = self.libelf.elf_begin(fd, self.C_WRITE, None)
        return self.e != 0
    def newehdr(self):
        return self.traits.newehdr(self.e)
    def newphdr(self, cnt):
        return self.traits.newphdr(self.e, cnt)
    def getshdr(self, scn):
        return self.traits.getshdr(scn)
    def newscn(self, name, type, flags, buf, align):
        scn = self.libelf.elf_newscn(self.e)
        shdr = self.getshdr(scn)
        shdr.contents.name = self.shstrtab.push(name)
        shdr.contents.type = type
        shdr.contents.flags = flags
        data = self.newdata(scn)
        data.contents.buf = ctypes.cast(ctypes.create_string_buffer(buf.data()), ctypes.c_char_p)
        data.contents.type = self.ELF_T_BYTE
        data.contents.version = self.EV_CURRENT
        data.contents.size = len(buf)
        data.contents.off = 0
        data.contents.align = align
        self.sectionidx[name] = self.libelf.elf_ndxscn(scn)
        return scn, shdr, data
    def newdata(self, scn):
        return self.libelf.elf_newdata(scn)
    def update(self, cmd):
        return self.libelf.elf_update(self.e, cmd)
    def end(self):
        return self.libelf.elf_end(self.e)
    @staticmethod
    def get_machine(bits):
        match platform.machine():
            case 'x86_64':
                return elf.EM_X86_64
            case 'armv7l':
                return elf.EM_ARM
            case _:
                raise "unknown platform"
    def applyrelocations(self, reltab):
        self.traits.applyrelocations(reltab)

def gen(fname):
    e = elf(64)

    # fd = libc.syscall(SYS_memfd_create, fname, MFD_CLOEXEC)
    fd = os.open('ttt', os.O_RDWR | os.O_CREAT, 0o666)
    if not e.open(fd):
        raise "cannot open elf"

    ehdr = e.newehdr()
    ehdr.contents.ident[:e.SELFMAG] = e.ELFMAG
    ehdr.contents.ident[e.EI_CLASS] = e.traits.elfclass
    ehdr.contents.ident[e.EI_DATA] = e.ELFDATA2LSB if sys.byteorder == 'little'  else e.ELFDATA2MSB
    ehdr.contents.ident[e.EI_VERSION] = e.EV_CURRENT
    ehdr.contents.ident[e.EI_OSABI] = e.ELFOSABI_NONE
    ehdr.contents.ident[e.EI_ABIVERSION] = 0
    ehdr.contents.type = e.ET_EXEC
    ehdr.contents.machine = e.traits.machine
    ehdr.contents.version = e.EV_CURRENT

    @enum.unique
    class phdrs(enum.Enum):
        code = 1

    phdr = e.newphdr(len(phdrs))

    codebuf = bytebuf(bytes([ 0xb8, 0x01, 0x00, 0x00, 0x00, #                   mov    $SYS_write,%eax
                              0xbf, 0x01, 0x00, 0x00, 0x00, #                   mov    $0x1,%edi
                              0x48, 0x8d, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00, # lea    0x0,%rsi
                              0xba, 0x0c, 0x00, 0x00, 0x00, #                   mov    $0xc,%edx
                              0x0f, 0x05, #                                     syscall
                              0xb8, 0xe7, 0x00, 0x00, 0x00, #                   mov    $SYS_exit_group,%eax
                              0xbf, 0x00, 0x00, 0x00, 0x00, #                   mov    $0x0,%edi
                              0x0f, 0x05 #                                      syscall
    ]))
    codescn, codeshdr, codedata = e.newscn(b'.text', e.SHT_PROGBITS, e.SHF_ALLOC|e.SHF_EXECINSTR, codebuf, 16)

    rodatabuf = bytebuf(b'hello world\n')
    rodatascn, rodatashdr, rodatadata = e.newscn(b'.rodata', e.SHT_PROGBITS, e.SHF_ALLOC, rodatabuf, 16);

    shstrscn, shstrshdr, shstrdata = e.newscn(b'.shstrtab', e.SHT_STRTAB, 0, e.shstrtab, 1)

    size = e.update(e.ELF_C_NULL)

    loadaddr = 0x40000
    codeshdr.contents.addr = loadaddr + codeshdr.contents.offset
    rodatashdr.contents.addr = loadaddr + rodatashdr.contents.offset

    symbols = {
        'hello': [ '.rodata', 0 ]
    }
    relocations = [
        [ 'hello', '.text', 14, x86_64_traits.reloc.abs4 ]
    ]
    elf.applyrelocations(relocations, symbols)

    os.ftruncate(fd, size)



    e.update(e.ELF_C_WRITE_MMAP)

    e.end()

    return e

def main(fname, *args):
    """Create and run binary.  Use FNAME as the file name and the optional list ARGS as arguments."""
    e = gen(fname)
    argv = (ctypes.c_char_p * (2 + len(args)))(fname, *args, ctypes.c_char_p())
    env = (ctypes.c_char_p * 1)(ctypes.c_char_p())
    libc.syscall(SYS_execveat, e.fd, b'', argv, env, AT_EMPTY_PATH)

if __name__ == '__main__':
    main(b'test')
    exit(42)
