#ifndef EYNOS_LINKER_H
#define EYNOS_LINKER_H

#include <stdint.h>
#include <stddef.h>

// Minimal ELF32 definitions for writing ET_EXEC for EYN-OS userland.

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf32_Word;

#define EI_NIDENT 16

#define EI_MAG0    0
#define EI_MAG1    1
#define EI_MAG2    2
#define EI_MAG3    3
#define EI_CLASS   4
#define EI_DATA    5
#define EI_VERSION 6

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS32 1
#define ELFDATA2LSB 1
#define EV_CURRENT 1

#define ET_EXEC 2
#define EM_386  3

#define PT_LOAD 1

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3

#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

#define STB_LOCAL  0
#define STB_GLOBAL 1

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC   2
#define STT_FILE   4

#define SHN_UNDEF 0

#define ELF32_ST_INFO(b,t)  (((b) << 4) + ((t) & 0xf))

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

typedef struct {
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
} Elf32_Phdr;

typedef struct {
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off  sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct {
  Elf32_Word    st_name;
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half    st_shndx;
} Elf32_Sym;

// Minimal config: 2 segments (.text RX, .rodata/.data R)
// Symbols are optional (for now keep small and bounded).

#define EYNOS_LINK_MAX_SYMBOLS 64
#define EYNOS_LINK_MAX_STRTAB  512

typedef struct {
  char name[64];
  uint32_t value;
  uint32_t size;
  uint8_t binding;
  uint8_t type;
  uint16_t section;
} eynos_link_symbol_t;

typedef struct {
  const uint8_t *data;
  uint32_t size;
} eynos_link_section_t;

typedef struct {
  const char *input_name;
  uint32_t text_vaddr;
  uint32_t rodata_vaddr;
  uint32_t entry_vaddr;

  eynos_link_section_t text;
  eynos_link_section_t rodata;

  eynos_link_symbol_t symbols[EYNOS_LINK_MAX_SYMBOLS];
  int symbol_count;
} eynos_link_config_t;

void eynos_link_config_init(eynos_link_config_t *cfg);
int eynos_link_add_symbol(eynos_link_config_t *cfg, const char *name, uint32_t value,
                          uint32_t size, uint8_t binding, uint8_t type, uint16_t section);

int eynos_link_write_uelf(const eynos_link_config_t *cfg, const char *output_path);

#endif
