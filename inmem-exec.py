import ctypes

libc = ctypes.CDLL(None)
libelf = ctypes.cdll.LoadLibrary('/$LIB/libelf.so.1')

# OS traits
EV_CURRENT = 1
MFD_CLOEXEC = 1
AT_EMPTY_PATH = 0x1000

# OS+CPU traits
SYS_execveat = 322
SYS_memfd_create = 319


def gen(fname):
    fd = libc.syscall(SYS_memfd_create, fname, MFD_CLOEXEC)
    return fd

def main(fname, *args):
    """Create and run binary.  Use FNAME as the file name and the optional list ARGS as arguments."""
    libelf.elf_version(EV_CURRENT)
    fd = gen(fname)
    argv = (ctypes.c_char_p * (2 + len(args)))(fname, *args, ctypes.c_char_p())
    env = (ctypes.c_char_p * 1)(ctypes.c_char_p())
    libc.syscall(SYS_execveat, fd, b'', argv, env, AT_EMPTY_PATH)

if __name__ == '__main__':
    main(b'test')
    exit(42)
