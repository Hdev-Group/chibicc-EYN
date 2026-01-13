#include "eynos_linker.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PAGE_SIZE 0x1000u

static uint32_t align_up_u32(uint32_t v, uint32_t a) {
  if (!a) return v;
  return (v + a - 1u) & ~(a - 1u);
}

void eynos_link_config_init(eynos_link_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->text_vaddr = 0x00400000u;
  cfg->rodata_vaddr = 0x00401000u;
  cfg->entry_vaddr = 0x00400000u;
}

int eynos_link_add_symbol(eynos_link_config_t *cfg, const char *name, uint32_t value,
                          uint32_t size, uint8_t binding, uint8_t type, uint16_t section) {
  if (!cfg || !name) return -1;
  if (cfg->symbol_count >= EYNOS_LINK_MAX_SYMBOLS) return -1;

  eynos_link_symbol_t *sym = &cfg->symbols[cfg->symbol_count++];
  memset(sym, 0, sizeof(*sym));
  strncpy(sym->name, name, sizeof(sym->name) - 1);
  sym->value = value;
  sym->size = size;
  sym->binding = binding;
  sym->type = type;
  sym->section = section;
  return 0;
}

static int build_strtab(const eynos_link_config_t *cfg, char *strtab, int max_size) {
  int pos = 0;
  strtab[pos++] = '\0';

  for (int i = 0; i < cfg->symbol_count; i++) {
    int len = (int)strlen(cfg->symbols[i].name);
    if (pos + len + 1 > max_size) return -1;
    memcpy(strtab + pos, cfg->symbols[i].name, (size_t)len + 1);
    pos += len + 1;
  }

  return pos;
}

static int find_strtab_offset(const char *strtab, int strtab_size, const char *name) {
  int pos = 1;
  while (pos < strtab_size) {
    if (strcmp(strtab + pos, name) == 0)
      return pos;
    pos += (int)strlen(strtab + pos) + 1;
  }
  return 0;
}

// Section header string table contents:
// "\0.symtab\0.strtab\0.shstrtab\0.text\0.rodata\0"
static const char shstrtab_data[] = "\0.symtab\0.strtab\0.shstrtab\0.text\0.rodata";
#define SHSTRTAB_SIZE 41
#define SHSTRTAB_OFF_SYMTAB   0x01
#define SHSTRTAB_OFF_STRTAB   0x09
#define SHSTRTAB_OFF_SHSTRTAB 0x11
#define SHSTRTAB_OFF_TEXT     0x1b
#define SHSTRTAB_OFF_RODATA   0x21

static int write_zeros(FILE *f, uint32_t count) {
  static uint8_t zero[64];
  memset(zero, 0, sizeof(zero));

  while (count) {
    uint32_t chunk = count;
    if (chunk > (uint32_t)sizeof(zero)) chunk = (uint32_t)sizeof(zero);
    if (fwrite(zero, 1, chunk, f) != chunk) return -1;
    count -= chunk;
  }
  return 0;
}

int eynos_link_write_uelf(const eynos_link_config_t *cfg, const char *output_path) {
  if (!cfg || !output_path || !output_path[0]) return -1;
  if (!cfg->text.data || cfg->text.size == 0) return -1;

  char strtab[EYNOS_LINK_MAX_STRTAB];
  int strtab_size = build_strtab(cfg, strtab, (int)sizeof(strtab));
  if (strtab_size < 0) return -1;

  const uint32_t text_offset = PAGE_SIZE;
  const uint32_t text_size = cfg->text.size;

  // Place rodata after text, aligned to page boundary.
  const uint32_t rodata_offset = align_up_u32(text_offset + text_size, PAGE_SIZE);
  const uint32_t rodata_size = cfg->rodata.size;

  const uint32_t symtab_size = (uint32_t)(cfg->symbol_count + 1) * (uint32_t)sizeof(Elf32_Sym);
  uint32_t symtab_offset = align_up_u32(rodata_offset + rodata_size, 4);
  const uint32_t strtab_offset = symtab_offset + symtab_size;
  const uint32_t shstrtab_offset = strtab_offset + (uint32_t)strtab_size;
  const uint32_t shdr_offset = align_up_u32(shstrtab_offset + SHSTRTAB_SIZE, 8);

  Elf32_Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS32;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_type = ET_EXEC;
  ehdr.e_machine = EM_386;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_entry = cfg->entry_vaddr;
  ehdr.e_phoff = (Elf32_Off)sizeof(Elf32_Ehdr);
  ehdr.e_shoff = (Elf32_Off)shdr_offset;
  ehdr.e_ehsize = (Elf32_Half)sizeof(Elf32_Ehdr);
  ehdr.e_phentsize = (Elf32_Half)sizeof(Elf32_Phdr);
  ehdr.e_phnum = 2;
  ehdr.e_shentsize = (Elf32_Half)sizeof(Elf32_Shdr);
  ehdr.e_shnum = 6;
  ehdr.e_shstrndx = 5;

  Elf32_Phdr phdr[2];
  memset(phdr, 0, sizeof(phdr));

  phdr[0].p_type = PT_LOAD;
  phdr[0].p_offset = (Elf32_Off)text_offset;
  phdr[0].p_vaddr = (Elf32_Addr)cfg->text_vaddr;
  phdr[0].p_paddr = (Elf32_Addr)cfg->text_vaddr;
  phdr[0].p_filesz = (Elf32_Word)text_size;
  phdr[0].p_memsz  = (Elf32_Word)text_size;
  phdr[0].p_flags = PF_R | PF_X;
  phdr[0].p_align = PAGE_SIZE;

  phdr[1].p_type = PT_LOAD;
  phdr[1].p_offset = (Elf32_Off)rodata_offset;
  phdr[1].p_vaddr = (Elf32_Addr)cfg->rodata_vaddr;
  phdr[1].p_paddr = (Elf32_Addr)cfg->rodata_vaddr;
  phdr[1].p_filesz = (Elf32_Word)rodata_size;
  phdr[1].p_memsz  = (Elf32_Word)rodata_size;
  phdr[1].p_flags = PF_R;
  phdr[1].p_align = PAGE_SIZE;

  Elf32_Shdr shdr[6];
  memset(shdr, 0, sizeof(shdr));

  // [1] .text
  shdr[1].sh_name = SHSTRTAB_OFF_TEXT;
  shdr[1].sh_type = SHT_PROGBITS;
  shdr[1].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  shdr[1].sh_addr = (Elf32_Addr)cfg->text_vaddr;
  shdr[1].sh_offset = (Elf32_Off)text_offset;
  shdr[1].sh_size = (Elf32_Word)text_size;
  shdr[1].sh_addralign = PAGE_SIZE;

  // [2] .rodata
  shdr[2].sh_name = SHSTRTAB_OFF_RODATA;
  shdr[2].sh_type = SHT_PROGBITS;
  shdr[2].sh_flags = SHF_ALLOC;
  shdr[2].sh_addr = (Elf32_Addr)cfg->rodata_vaddr;
  shdr[2].sh_offset = (Elf32_Off)rodata_offset;
  shdr[2].sh_size = (Elf32_Word)rodata_size;
  shdr[2].sh_addralign = PAGE_SIZE;

  // [3] .symtab
  shdr[3].sh_name = SHSTRTAB_OFF_SYMTAB;
  shdr[3].sh_type = SHT_SYMTAB;
  shdr[3].sh_offset = (Elf32_Off)symtab_offset;
  shdr[3].sh_size = (Elf32_Word)symtab_size;
  shdr[3].sh_link = 4;
  shdr[3].sh_addralign = 4;
  shdr[3].sh_entsize = (Elf32_Word)sizeof(Elf32_Sym);

  int local_count = 1;
  for (int i = 0; i < cfg->symbol_count; i++)
    if (cfg->symbols[i].binding == STB_LOCAL)
      local_count++;
  shdr[3].sh_info = (Elf32_Word)local_count;

  // [4] .strtab
  shdr[4].sh_name = SHSTRTAB_OFF_STRTAB;
  shdr[4].sh_type = SHT_STRTAB;
  shdr[4].sh_offset = (Elf32_Off)strtab_offset;
  shdr[4].sh_size = (Elf32_Word)strtab_size;
  shdr[4].sh_addralign = 1;

  // [5] .shstrtab
  shdr[5].sh_name = SHSTRTAB_OFF_SHSTRTAB;
  shdr[5].sh_type = SHT_STRTAB;
  shdr[5].sh_offset = (Elf32_Off)shstrtab_offset;
  shdr[5].sh_size = SHSTRTAB_SIZE;
  shdr[5].sh_addralign = 1;

  // Build symbol table (locals first, then globals)
  Elf32_Sym syms[EYNOS_LINK_MAX_SYMBOLS + 1];
  memset(syms, 0, sizeof(syms));

  int sym_idx = 1;
  for (int i = 0; i < cfg->symbol_count; i++) {
    if (cfg->symbols[i].binding != STB_LOCAL) continue;
    syms[sym_idx].st_name = (Elf32_Word)find_strtab_offset(strtab, strtab_size, cfg->symbols[i].name);
    syms[sym_idx].st_value = (Elf32_Addr)cfg->symbols[i].value;
    syms[sym_idx].st_size = (Elf32_Word)cfg->symbols[i].size;
    syms[sym_idx].st_info = (unsigned char)ELF32_ST_INFO(cfg->symbols[i].binding, cfg->symbols[i].type);
    syms[sym_idx].st_shndx = (Elf32_Half)cfg->symbols[i].section;
    sym_idx++;
  }
  for (int i = 0; i < cfg->symbol_count; i++) {
    if (cfg->symbols[i].binding == STB_LOCAL) continue;
    syms[sym_idx].st_name = (Elf32_Word)find_strtab_offset(strtab, strtab_size, cfg->symbols[i].name);
    syms[sym_idx].st_value = (Elf32_Addr)cfg->symbols[i].value;
    syms[sym_idx].st_size = (Elf32_Word)cfg->symbols[i].size;
    syms[sym_idx].st_info = (unsigned char)ELF32_ST_INFO(cfg->symbols[i].binding, cfg->symbols[i].type);
    syms[sym_idx].st_shndx = (Elf32_Half)cfg->symbols[i].section;
    sym_idx++;
  }

  FILE *f = fopen(output_path, "wb");
  if (!f) return -1;

  if (fwrite(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) { fclose(f); return -1; }
  if (fwrite(phdr, 1, sizeof(phdr), f) != sizeof(phdr)) { fclose(f); return -1; }

  uint32_t cur = (uint32_t)(sizeof(ehdr) + sizeof(phdr));

  if (cur > text_offset) { fclose(f); return -1; }
  if (write_zeros(f, text_offset - cur) != 0) { fclose(f); return -1; }
  cur = text_offset;

  if (fwrite(cfg->text.data, 1, text_size, f) != text_size) { fclose(f); return -1; }
  cur += text_size;

  if (cur > rodata_offset) { fclose(f); return -1; }
  if (write_zeros(f, rodata_offset - cur) != 0) { fclose(f); return -1; }
  cur = rodata_offset;

  if (rodata_size && cfg->rodata.data) {
    if (fwrite(cfg->rodata.data, 1, rodata_size, f) != rodata_size) { fclose(f); return -1; }
    cur += rodata_size;
  }

  if (cur > symtab_offset) { fclose(f); return -1; }
  if (write_zeros(f, symtab_offset - cur) != 0) { fclose(f); return -1; }
  cur = symtab_offset;

  if (fwrite(syms, 1, symtab_size, f) != symtab_size) { fclose(f); return -1; }
  cur += symtab_size;

  if (fwrite(strtab, 1, (size_t)strtab_size, f) != (size_t)strtab_size) { fclose(f); return -1; }
  cur += (uint32_t)strtab_size;

  if (fwrite(shstrtab_data, 1, SHSTRTAB_SIZE, f) != SHSTRTAB_SIZE) { fclose(f); return -1; }
  cur += SHSTRTAB_SIZE;

  if (cur > shdr_offset) { fclose(f); return -1; }
  if (write_zeros(f, shdr_offset - cur) != 0) { fclose(f); return -1; }

  if (fwrite(shdr, 1, sizeof(shdr), f) != sizeof(shdr)) { fclose(f); return -1; }

  if (fclose(f) != 0) return -1;
  return 0;
}
