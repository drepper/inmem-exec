#include <cassert>
#include <fcntl.h>
#include <iostream>
#include <libelf.h>
#include <memory>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <sys/mman.h>

template<size_t>
struct traits;

template<> struct traits<32> {
  static constexpr int elfclass = ELFCLASS32;
  using Word = Elf32_Word;
  using Xword = Elf32_Xword;
  using Addr = Elf32_Addr;
  static constexpr int machine = EM_386;
  static auto newehdr(Elf* elf) { return elf32_newehdr(elf); }
  static auto newphdr(Elf* elf, size_t cnt) { return elf32_newphdr(elf, cnt); }
  static auto getshdr(Elf_Scn* scn) { return elf32_getshdr(scn); }
};

template<> struct traits<64> {
  static constexpr int elfclass = ELFCLASS64;
  using Word = Elf64_Word;
  using Xword = Elf64_Xword;
  using Addr = Elf64_Addr;
  static constexpr int machine = EM_X86_64;
  static auto newehdr(Elf* elf) { return elf64_newehdr(elf); }
  static auto newphdr(Elf* elf, size_t cnt) { return elf64_newphdr(elf, cnt); }
  static auto getshdr(Elf_Scn* scn) { return elf64_getshdr(scn); }
};

std::array<unsigned char,37> codebuf {
 0xb8, 0x01, 0x00, 0x00, 0x00, //                   mov    $SYS_write,%eax
 0xbf, 0x01, 0x00, 0x00, 0x00, //                   mov    $0x1,%edi
 0x48, 0x8d, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00, // lea    0x0,%rsi
 0xba, 0x0c, 0x00, 0x00, 0x00, //                   mov    $0xc,%edx
 0x0f, 0x05, //                                     syscall
 0xb8, 0xe7, 0x00, 0x00, 0x00, //                   mov    $SYS_exit_group,%eax
 0xbf, 0x00, 0x00, 0x00, 0x00, //                   mov    $0x0,%edi
 0x0f, 0x05 //                                      syscall
};

std::array<char,12> rodatabuf {
  'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '\n'
};

std::unordered_map<std::string,std::tuple<std::string,size_t>> symbols {
  { "hello", { ".rodata", 0 } }
};

enum struct reloc_type {
  abs4
};

std::vector<std::tuple<std::string,std::string,size_t,reloc_type>> relocations {
  { "hello", ".text", 14, reloc_type::abs4 }
};

std::unordered_map<std::string,size_t> sectionidx;

struct shstrtab_type {
  auto data() { return mem.data(); }
  auto size() const { return mem.size(); }
  auto push(const std::string& name) {
    auto res = mem.size();
    std::copy(std::begin(name), std::end(name), std::back_inserter(mem));
    mem.push_back('\0');
    return res;
  }
 private:
  std::vector<char> mem { '\0' };
} shstrbuf;

template<typename Traits, typename Buf>
auto newscn(Elf* elf, const std::string& name, typename Traits::Word type, typename Traits::Xword flags, Buf& buf, size_t align)
{
  auto scn = elf_newscn(elf);
  auto shdr = Traits::getshdr(scn);
  shdr->sh_name = shstrbuf.push(name);
  shdr->sh_type = type;
  shdr->sh_flags = flags;
  auto data = elf_newdata(scn);
  data->d_buf = buf.data();
  data->d_type = ELF_T_BYTE;
  data->d_version = EV_CURRENT;
  data->d_size = buf.size();
  data->d_off = 0;
  data->d_align = align;
  sectionidx[name] = elf_ndxscn(scn);
  return std::make_tuple(scn, shdr, data);
}

template<typename Traits>
void apply_relocations(Elf* elf)
{
  for (auto [symname, scnname, off, type] : relocations) {
    const auto& sym = symbols[symname];

    auto defscnidx = sectionidx[std::get<std::string>(sym)];
    auto defscn = elf_getscn(elf, defscnidx);
    auto defshdr = Traits::getshdr(defscn);
    auto defval = defshdr->sh_addr + std::get<size_t>(sym);

    auto refscnidx = sectionidx[scnname];
    auto refscn = elf_getscn(elf, refscnidx);
    auto refdata = elf_getdata(refscn, nullptr);
    while (off >= refdata->d_size) {
      off -= refdata->d_size;
      refdata = elf_getdata(refscn, refdata);
    }
    switch (type) {
    case reloc_type::abs4:
      {
        assert(off + 4 <= refdata->d_size);
        auto buf = (unsigned char*) refdata->d_buf;
        buf[off] = defval & 0xff;
        buf[off + 1] = (defval >> 8) & 0xff;
        buf[off + 2] = (defval >> 16) & 0xff;
        buf[off + 3] = (defval >> 24) & 0xff;
      }
      break;
    default:
      __builtin_unreachable();
    }
  }
}

template<size_t N>
void genelf(int fd)
{
  using E = traits<N>;

  elf_version(EV_CURRENT);

  Elf* elf = elf_begin(fd, ELF_C_WRITE, nullptr);

  auto ehdr = E::newehdr(elf);
  std::copy_n(ELFMAG, SELFMAG, ehdr->e_ident);
  ehdr->e_ident[EI_CLASS] = E::elfclass;
  ehdr->e_ident[EI_DATA] = std::endian::native == std::endian::little ? ELFDATA2LSB : ELFDATA2MSB;
  ehdr->e_ident[EI_VERSION] = EV_CURRENT;
  ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
  ehdr->e_ident[EI_ABIVERSION] = 0;
  ehdr->e_type = ET_EXEC;
  ehdr->e_machine = E::machine;
  ehdr->e_version = EV_CURRENT;

  enum struct phdridx : size_t {
    code,
    // Keep it last
    num
  };

  auto phdr = E::newphdr(elf, std::underlying_type_t<phdridx>(phdridx::num));

  auto [codescn, codeshdr, codedata] = newscn<E>(elf, ".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, codebuf, 16);

  auto [rodatascn, rodatashdr, rodatadata] = newscn<E>(elf, ".rodata", SHT_PROGBITS, SHF_ALLOC, rodatabuf, 16);

  // Keep as last added section.
  auto [shstrscn, shstrshdr, shstrdata] = newscn<E>(elf, ".shstrtab", SHT_STRTAB, 0, shstrbuf, 1);

  auto size = elf_update(elf, ELF_C_NULL);

  const typename E::Addr loadaddr = 0x40000;

  codeshdr->sh_addr = loadaddr + codeshdr->sh_offset;
  rodatashdr->sh_addr = loadaddr + rodatashdr->sh_offset;

  apply_relocations<E>(elf);

  ehdr->e_shstrndx = elf_ndxscn(shstrscn);

  ehdr->e_entry = codeshdr->sh_addr;

  const auto codeidx = std::underlying_type_t<phdridx>(phdridx::code);
  phdr[codeidx].p_type = PT_LOAD;
  phdr[codeidx].p_flags = PF_R|PF_X;
  phdr[codeidx].p_offset = 0;
  phdr[codeidx].p_vaddr = loadaddr;
  phdr[codeidx].p_paddr = phdr[codeidx].p_vaddr;
  phdr[codeidx].p_filesz = rodatashdr->sh_offset + rodatashdr->sh_size;
  phdr[codeidx].p_memsz = phdr[codeidx].p_filesz;
  phdr[codeidx].p_align = sysconf(_SC_PAGESIZE);

  elf_update(elf, ELF_C_WRITE_MMAP);

  elf_end(elf);
}

int main(int argc, char* argv[])
{
  char* newargv[] {
    (char*) "test",
    nullptr
  };
  int fd = memfd_create(newargv[0], MFD_CLOEXEC);

  genelf<64>(fd);

  fexecve(fd, newargv, environ);
  // We should never get here.
  return 1;
}
