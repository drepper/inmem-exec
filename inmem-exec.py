import collections
import ctypes
import enum
import os
import platform
import resource
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
    def __init__(self, b):
        self.b = b
    def data(self):
        return self.b
    def __len__(self):
        return len(self.b)


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
    def applyrelocations(self, e, reltab, symbols):
        for symname, scnname, off, typ in reltab:
            sym = symbols[symname]

            defscnidx = e.sectionidx[sym[0]]
            defscn = e.getscn(defscnidx)
            defshdr = e.getshdr(defscn)
            defval = defshdr.contents.addr + sym[1]

            refscnidx = e.sectionidx[scnname]
            refscn = e.getscn(refscnidx)
            refdata = e.getdata(refscn, None)
            while off >= refdata.contents.size:
                off -= refdata.contents.size
                refdata = e.getdata(refscn, refdata)
            match typ:
                case self.reloc.abs4:
                    assert off + 4 <= refdata.contents.size
                    buf = ctypes.string_at(refdata.contents.buf, refdata.contents.size)
                    buf = buf[:off] + bytes([defval & 0xff, (defval >> 8) & 0xff, (defval >> 16) & 0xff, (defval >> 24) & 0xff]) + buf[off+4:]
                    refdata.contents.buf = ctypes.cast(ctypes.create_string_buffer(buf, refdata.contents.size), ctypes.POINTER(ctypes.c_byte))
                case _:
                    raise ValueError('invalid relocation type')

class elfdef(object):
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
    PT_LOAD = 1
    PF_R = 4
    PF_W = 2
    PF_X = 1

machtraits_64 = {
    elfdef.EM_X86_64: x86_64_traits
}

class elf64_traits(object):
    Word = ctypes.c_int32
    Xword = ctypes.c_int64
    Addr = ctypes.c_int64

    def __init__(self, e, libelf):
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
        self.machtraits = machtraits_64[self.machine]()
        self.phdr_type = elf64_phdr
    def newehdr(self, e):
        return self.libelf.elf64_newehdr(e)
    def newphdr(self, e, cnt):
        return ctypes.cast(self.libelf.elf64_newphdr(e, cnt), ctypes.POINTER(elf64_phdr * cnt))
    def getshdr(self, scn):
        return self.libelf.elf64_getshdr(scn)
    def applyrelocations(self, e, reltab, symbols):
        return self.machtraits.applyrelocations(e, reltab, symbols)

class elf(elfdef):
    def __init__(self, bits):
        self.libelf = ctypes.cdll.LoadLibrary('/$LIB/libelf.so.1')
        if self.libelf.elf_version(self.EV_CURRENT) != self.EV_CURRENT:
            raise RuntimeError("invalid libelf version")
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
        data.contents.size = len(buf)
        data.contents.buf = ctypes.cast(ctypes.create_string_buffer(buf.data(), data.contents.size), ctypes.POINTER(ctypes.c_byte))
        data.contents.type = self.ELF_T_BYTE
        data.contents.version = self.EV_CURRENT
        data.contents.off = 0
        data.contents.align = align
        self.sectionidx[name] = self.libelf.elf_ndxscn(scn)
        return scn, shdr, data
    def getscn(self, ndx):
        return self.libelf.elf_getscn(self.e, ndx)
    def newdata(self, scn):
        return self.libelf.elf_newdata(scn)
    def getdata(self, scn, data):
        return self.libelf.elf_getdata(scn, data)
    def update(self, cmd):
        return self.libelf.elf_update(self.e, cmd)
    def end(self):
        return self.libelf.elf_end(self.e)
    def applyrelocations(self, reltab, symbols):
        self.traits.applyrelocations(self, reltab, symbols)
    def firstlastaddr(self, names):
        offset = 0
        addr = -1
        filesz = 0
        memsz = 0
        for name in names:
            if name in self.sectionidx:
                shdr = self.getshdr(self.getscn(self.sectionidx[name]))
                offset = min(offset, shdr.contents.offset)
                addr = shdr.contents.addr if addr == -1 else min(addr, shdr.contents.addr)
                memsz = ((memsz + shdr.contents.addralign - 1) & ~(shdr.contents.addralign - 1)) + shdr.contents.size
                if shdr.contents.type == self.SHT_PROGBITS:
                    filesz = memsz
            elif name == 'Ehdr':
                offset = 0
                memsz = ctypes.sizeof(self.traits.phdr_type)
                filesz = memsz
        return offset, addr, filesz, memsz
    @staticmethod
    def get_machine(bits):
        match platform.machine():
            case 'x86_64':
                return elf.EM_X86_64
            case 'armv7l':
                return elf.EM_ARM
            case _:
                raise RuntimeError("unknown platform")

def gen(fname):
    e = elf(64)

    # fd = libc.syscall(SYS_memfd_create, fname, MFD_CLOEXEC)
    fd = os.open('test', os.O_RDWR|os.O_CREAT|os.O_TRUNC, 0o777)
    if not e.open(fd):
        raise RuntimeError("cannot open elf")

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
    class phdrs(enum.IntEnum):
        code = 0
        data = 1

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
    codescn, codeshdr, codedata = e.newscn(b'.text', e.SHT_PROGBITS, e.SHF_ALLOC | e.SHF_EXECINSTR, codebuf, 16)

    rodatabuf = bytebuf(b'hello world\n')
    rodatascn, rodatashdr, rodatadata = e.newscn(b'.rodata', e.SHT_PROGBITS, e.SHF_ALLOC, rodatabuf, 16);

    databuf = bytebuf(b'\x00\x00\x00\x00')
    datascn, datashdr, datadata = e.newscn(b'.data', e.SHT_PROGBITS, e.SHF_ALLOC, databuf, 16);

    shstrscn, shstrshdr, shstrdata = e.newscn(b'.shstrtab', e.SHT_STRTAB, 0, e.shstrtab, 1)

    size = e.update(e.ELF_C_NULL)

    loadaddr = 0x40000
    codeshdr.contents.addr = loadaddr + codeshdr.contents.offset
    rodatashdr.contents.addr = loadaddr + rodatashdr.contents.offset

    Segment = collections.namedtuple('Segment', 'idx sections flags')
    segments = [
        Segment(phdrs.code, [ 'Ehdr', b'.text', b'.rodata' ], e.PF_R | e.PF_X),
        # Segment(phdrs.data, [ b'.data' ], e.PF_R | e.PF_W)
    ]

    for s in segments:
        offset, addr, filesz, memsz = e.firstlastaddr(s.sections)
        print(offset,addr,filesz,memsz)
        phdr.contents[s.idx].type = e.PT_LOAD
        phdr.contents[s.idx].flags = s.flags
        phdr.contents[s.idx].offset = offset & (resource.getpagesize() - 1)
        phdr.contents[s.idx].vaddr = loadaddr
        phdr.contents[s.idx].paddr = phdr.contents[s.idx].vaddr
        phdr.contents[s.idx].filesz = filesz
        phdr.contents[s.idx].memsz = memsz
        phdr.contents[s.idx].align = resource.getpagesize()

    symbols = {
        'hello': [ b'.rodata', 0 ]
    }
    relocations = [
        [ 'hello', b'.text', 14, x86_64_traits.reloc.abs4 ]
    ]
    e.applyrelocations(relocations, symbols)

    ehdr.contents.shstrndx = e.libelf.elf_ndxscn(shstrscn)

    ehdr.contents.entry = codeshdr.contents.addr

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
