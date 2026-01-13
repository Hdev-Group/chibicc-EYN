#include "chibicc.h"

#ifdef CHIBICC_EYNOS_USERLAND

#include "eynos_linker.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This file implements chibicc's EYN-OS userland `--as` path.
// It:
//   1) reads a GAS/AT&T style .s file (as emitted by chibicc i386 backend)
//   2) translates it to an Intel-ish syntax supported by the existing EYN-OS assembler core
//   3) assembles to .text and .data buffers
//   4) writes a .uelf (ELF32 ET_EXEC) in-process
//
// NOTE: No external linker/assembler subprocesses; no temp files.

// ------------------------
// Small dynamic string buf
// ------------------------

typedef struct {
  char *data;
  size_t len;
  size_t cap;
} sbuf_t;

static void sbuf_init(sbuf_t *b) {
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
}

static void sbuf_free(sbuf_t *b) {
  free(b->data);
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
}

static void sbuf_reserve(sbuf_t *b, size_t extra) {
  size_t need = b->len + extra + 1;
  if (need <= b->cap) return;
  size_t newcap = b->cap ? b->cap : 256;
  while (newcap < need) newcap *= 2;
  char *p = realloc(b->data, newcap);
  if (!p) error("out of memory");
  b->data = p;
  b->cap = newcap;
}

static void sbuf_putc(sbuf_t *b, char c) {
  sbuf_reserve(b, 1);
  b->data[b->len++] = c;
  b->data[b->len] = 0;
}

static void sbuf_puts(sbuf_t *b, const char *s) {
  size_t n = strlen(s);
  sbuf_reserve(b, n);
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = 0;
}

static void sbuf_putsn(sbuf_t *b, const char *s, size_t n) {
  sbuf_reserve(b, n);
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = 0;
}

// ------------------------
// File IO helpers
// ------------------------

static char *read_entire_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    error("failed to open %s: %s", path, strerror(errno));

  // Userland stdio intentionally does not provide fseek/ftell/SEEK_*.
  // Stream the file into a growable buffer.
  size_t cap = 0;
  size_t len = 0;
  char *buf = NULL;

  for (;;) {
    char tmp[4096];
    size_t nread = fread(tmp, 1, sizeof(tmp), f);
    if (nread == 0)
      break;

    if (len + nread + 1 > cap) {
      size_t new_cap = cap ? cap : 4096;
      while (new_cap < len + nread + 1)
        new_cap *= 2;

      char *new_buf = realloc(buf, new_cap);
      if (!new_buf) {
        fclose(f);
        error("out of memory");
      }
      buf = new_buf;
      cap = new_cap;
    }

    memcpy(buf + len, tmp, nread);
    len += nread;
  }

  fclose(f);

  if (!buf) {
    buf = calloc(1, 1);
    if (!buf)
      error("out of memory");
    if (out_len)
      *out_len = 0;
    return buf;
  }

  buf[len] = 0;
  if (out_len)
    *out_len = len;
  return buf;
}

// ------------------------
// GAS/AT&T -> Intel-ish translation
// ------------------------

static int is_space_no_nl(char c) {
  return c == ' ' || c == '\t' || c == '\r';
}

static void trim_right(char *s) {
  size_t n = strlen(s);
  while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) {
    s[n - 1] = 0;
    n--;
  }
}

static int starts_with(const char *s, const char *pfx) {
  return strncmp(s, pfx, strlen(pfx)) == 0;
}

static void skip_spaces(const char **ps) {
  const char *s = *ps;
  while (*s && is_space_no_nl(*s)) s++;
  *ps = s;
}

static void emit_newline(sbuf_t *out) {
  sbuf_putc(out, '\n');
}

static void emit_section(sbuf_t *out, const char *name) {
  sbuf_puts(out, "section ");
  sbuf_puts(out, name);
  emit_newline(out);
}

static void emit_directive_passthru(sbuf_t *out, const char *line) {
  sbuf_puts(out, line);
  emit_newline(out);
}

static int is_suffixed_atandt_mnemonic(const char *mn) {
  // Detect real AT&T size suffix forms (movl/addl/..., not mnemonics that
  // merely end with 'l' like "call" or "imul").
  if (!mn) return 0;
  size_t n = strlen(mn);
  if (n < 2) return 0;

  if (mn[0] == 'j' || starts_with(mn, "set"))
    return 0;

  char last = mn[n - 1];
  if (!(last == 'b' || last == 'w' || last == 'l'))
    return 0;

  char base[32];
  if (n - 1 >= sizeof(base))
    return 0;
  memcpy(base, mn, n - 1);
  base[n - 1] = 0;

  // Minimal whitelist for chibicc/GAS output.
  return !strcmp(base, "mov") || !strcmp(base, "lea") ||
         !strcmp(base, "add") || !strcmp(base, "sub") || !strcmp(base, "and") ||
         !strcmp(base, "or") || !strcmp(base, "xor") || !strcmp(base, "cmp") ||
         !strcmp(base, "test") || !strcmp(base, "push") || !strcmp(base, "pop") ||
         !strcmp(base, "imul") || !strcmp(base, "idiv") || !strcmp(base, "div") ||
         !strcmp(base, "neg") || !strcmp(base, "not") || !strcmp(base, "inc") ||
         !strcmp(base, "dec") || !strcmp(base, "shl") || !strcmp(base, "shr") ||
         !strcmp(base, "sar") || !strcmp(base, "sal");
}

static void normalize_mnemonic(char *mn) {
  // Strip common AT&T suffixes. Keep special mnemonics handled elsewhere.
  size_t n = strlen(mn);
  if (!n) return;

  // Don't strip condition codes (e.g. jl/jle/jg) or setcc (e.g. setl/sete).
  // These are real mnemonics and not size suffixes.
  if (mn[0] == 'j' || starts_with(mn, "set"))
    return;

  if (is_suffixed_atandt_mnemonic(mn))
    mn[n - 1] = 0;
}

static int size_hint_from_suffix(char suffix) {
  if (suffix == 'b') return 8;
  if (suffix == 'w') return 16;
  if (suffix == 'l') return 32;
  return 0;
}

static int is_bare_symbol_operand(const char *op_in) {
  if (!op_in) return 0;
  const char *p = op_in;
  while (*p && is_space_no_nl(*p)) p++;
  while (*p == '*') p++;
  // Registers and immediates are explicitly prefixed in AT&T.
  if (*p == '%' || *p == '$') return 0;
  // Anything with '(' is already a memory addressing form.
  if (strchr(p, '(')) return 0;
  // Numbers are immediates.
  if (*p == '-' || *p == '+' || isdigit((unsigned char)*p)) return 0;
  // Labels/symbols (including .L...)
  return (isalpha((unsigned char)*p) || *p == '_' || *p == '.');
}

static void atandt_reg_to_intel(char *s) {
  // remove leading '%'
  if (s[0] == '%')
    memmove(s, s + 1, strlen(s));
}

static void atandt_imm_to_intel(char *s) {
  // remove leading '$'
  if (s[0] == '$')
    memmove(s, s + 1, strlen(s));
}

static void strip_indirect_star(char *s) {
  while (s[0] == '*')
    memmove(s, s + 1, strlen(s));
}

static void translate_mem_operand(sbuf_t *out, const char *op_in) {
  // Translate forms like:
  //   disp(base)
  //   (base)
  //   disp(base,index,scale)
  //   (base,index,scale)
  //   symbol
  //   symbol+4
  // into: [base+index*scale+disp] or [symbol+disp]

  // If there is no '(' treat as label/immediate already.
  const char *lpar = strchr(op_in, '(');
  if (!lpar) {
    sbuf_puts(out, "[");
    sbuf_puts(out, op_in);
    sbuf_puts(out, "]");
    return;
  }

  char disp[64] = {0};
  size_t disp_len = (size_t)(lpar - op_in);
  if (disp_len >= sizeof(disp)) disp_len = sizeof(disp) - 1;
  memcpy(disp, op_in, disp_len);
  disp[disp_len] = 0;
  // trim
  while (disp[0] && is_space_no_nl(disp[0])) memmove(disp, disp + 1, strlen(disp));
  trim_right(disp);

  const char *rpar = strchr(lpar, ')');
  if (!rpar) {
    // fallback
    sbuf_puts(out, "[");
    sbuf_puts(out, op_in);
    sbuf_puts(out, "]");
    return;
  }

  char inside[128] = {0};
  size_t in_len = (size_t)(rpar - (lpar + 1));
  if (in_len >= sizeof(inside)) in_len = sizeof(inside) - 1;
  memcpy(inside, lpar + 1, in_len);
  inside[in_len] = 0;

  // inside is "base" or "base,index,scale" and each can have %
  char *base = inside;
  char *index = NULL;
  char *scale = NULL;

  char *c1 = strchr(inside, ',');
  if (c1) {
    *c1++ = 0;
    index = c1;
    char *c2 = strchr(c1, ',');
    if (c2) {
      *c2++ = 0;
      scale = c2;
    }
  }

  // strip whitespace
  while (base && *base && is_space_no_nl(*base)) base++;
  if (index) { while (*index && is_space_no_nl(*index)) index++; }
  if (scale) { while (*scale && is_space_no_nl(*scale)) scale++; }

  // strip %
  if (base) atandt_reg_to_intel(base);
  if (index) atandt_reg_to_intel(index);

  // x86-64 style RIP-relative addressing (e.g. foo(%rip)) occasionally leaks
  // into input. In our 32-bit ET_EXEC world we don't support PC-relative
  // addressing, so treat it as an absolute reference to the symbol+disp.
  if (base && !strcmp(base, "rip"))
    base[0] = 0;

  sbuf_putc(out, '[');
  int need_plus = 0;

  if (base && base[0]) {
    sbuf_puts(out, base);
    need_plus = 1;
  }

  if (index && index[0]) {
    if (need_plus) sbuf_putc(out, '+');
    sbuf_puts(out, index);
    if (scale && scale[0] && strcmp(scale, "1") != 0) {
      sbuf_putc(out, '*');
      sbuf_puts(out, scale);
    }
    need_plus = 1;
  }

  if (disp[0]) {
    // disp can be like -4, 4, symbol, symbol+4
    // If already has sign at start, just append.
    if (disp[0] == '-' || disp[0] == '+') {
      sbuf_puts(out, disp);
    } else {
      if (need_plus) sbuf_putc(out, '+');
      sbuf_puts(out, disp);
    }
  }

  sbuf_putc(out, ']');
}

static void split_operands(const char *s, char *op0, size_t op0sz, char *op1, size_t op1sz) {
  op0[0] = 0;
  op1[0] = 0;

  // naive split by first comma not in quotes
  int in_str = 0;
  const char *p = s;
  const char *comma = NULL;
  for (; *p; p++) {
    if (*p == '"') in_str = !in_str;
    if (!in_str && *p == ',') { comma = p; break; }
  }

  if (!comma) {
    strncpy(op0, s, op0sz - 1);
    op0[op0sz - 1] = 0;
    trim_right(op0);
    // trim left
    while (op0[0] && is_space_no_nl(op0[0])) memmove(op0, op0 + 1, strlen(op0));
    return;
  }

  size_t n0 = (size_t)(comma - s);
  if (n0 >= op0sz) n0 = op0sz - 1;
  memcpy(op0, s, n0);
  op0[n0] = 0;

  const char *rhs = comma + 1;
  while (*rhs && is_space_no_nl(*rhs)) rhs++;
  strncpy(op1, rhs, op1sz - 1);
  op1[op1sz - 1] = 0;

  // trim
  trim_right(op0);
  trim_right(op1);
  while (op0[0] && is_space_no_nl(op0[0])) memmove(op0, op0 + 1, strlen(op0));
}

// Forward declarations (helpers are defined later in this TU)
static int eynas_get_reg_encoding(const char *reg);
static int eynas_is_reg8(const char *r);

static bool eynas_is_jcc_mnemonic(const char *mn) {
  // Conditional branches supported by this minimal assembler.
  // Intentionally excludes "jmp" (unconditional).
  return !strcmp(mn, "je")  || !strcmp(mn, "jne") ||
         !strcmp(mn, "jl")  || !strcmp(mn, "jle") ||
         !strcmp(mn, "jg")  || !strcmp(mn, "jge") ||
         !strcmp(mn, "ja")  || !strcmp(mn, "jae") ||
         !strcmp(mn, "jb")  || !strcmp(mn, "jbe") ||
         !strcmp(mn, "js")  || !strcmp(mn, "jns") ||
         !strcmp(mn, "jo")  || !strcmp(mn, "jno");
}

static void emit_operand_intel(sbuf_t *out, const char *op_in, int size_hint_bits) {
  // size_hint_bits: 0,8,16,32 used for memory operands when needed.

  char tmp[256];
  strncpy(tmp, op_in, sizeof(tmp) - 1);
  tmp[sizeof(tmp) - 1] = 0;
  trim_right(tmp);
  while (tmp[0] && is_space_no_nl(tmp[0])) memmove(tmp, tmp + 1, strlen(tmp));

  strip_indirect_star(tmp);

  // immediates and registers
  if (tmp[0] == '$')
    atandt_imm_to_intel(tmp);

  if (tmp[0] == '%')
    atandt_reg_to_intel(tmp);

  // memory operands: something with '(' or a bare symbol used as mem in some contexts
  if (strchr(tmp, '(')) {
    if (size_hint_bits == 8) sbuf_puts(out, "byte ");
    if (size_hint_bits == 16) sbuf_puts(out, "word ");
    if (size_hint_bits == 32) sbuf_puts(out, "dword ");
    translate_mem_operand(out, tmp);
    return;
  }

  // if caller requests a size hint and operand looks like memory already (e.g. label)
  if (size_hint_bits && (isalpha((unsigned char)tmp[0]) || tmp[0] == '_' || tmp[0] == '.') &&
      eynas_get_reg_encoding(tmp) < 0 && !eynas_is_reg8(tmp)) {
    // Heuristic: when used in movzx/movsx source, treat as memory.
    if (size_hint_bits == 8) sbuf_puts(out, "byte ");
    if (size_hint_bits == 16) sbuf_puts(out, "word ");
    if (size_hint_bits == 32) sbuf_puts(out, "dword ");
    sbuf_putc(out, '[');
    sbuf_puts(out, tmp);
    sbuf_putc(out, ']');
    return;
  }

  sbuf_puts(out, tmp);
}

static void emit_binop_swapped(sbuf_t *out, const char *mnemonic, const char *op_atandt) {
  // AT&T is src,dst, Intel is dst,src
  char a0[256], a1[256];
  split_operands(op_atandt, a0, sizeof(a0), a1, sizeof(a1));

  sbuf_puts(out, mnemonic);
  sbuf_putc(out, ' ');
  emit_operand_intel(out, a1, 0);
  if (a0[0]) {
    sbuf_puts(out, ", ");
    emit_operand_intel(out, a0, 0);
  }
  emit_newline(out);
}

static void translate_line(sbuf_t *out, const char *line) {
  // Strip trailing newline already.
  const char *s = line;
  while (*s && is_space_no_nl(*s)) s++;

  if (*s == 0) {
    emit_newline(out);
    return;
  }

  // Comments: GAS uses '#' also, but chibicc emits none typically.
  // Keep anything after '#' as comment, but EYN assembler uses ';' or '#'.

  // Labels (including GAS local labels like .L...): keep as-is.
  // Important: label lines may start with '.' so we must detect them *before*
  // directive handling.
  {
    const char *colon = strchr(s, ':');
    if (colon) {
      const char *p = s;
      while (p < colon && (isalnum((unsigned char)*p) || *p == '_' || *p == '.'))
        p++;

      if (p == colon && (colon[1] == 0 || is_space_no_nl(colon[1]) || colon[1] == '\t')) {
        emit_directive_passthru(out, s);
        return;
      }
    }
  }

  // Directives
  if (*s == '.') {
    if (starts_with(s, ".text")) { emit_section(out, ".text"); return; }
    if (starts_with(s, ".data")) { emit_section(out, ".data"); return; }
    if (starts_with(s, ".section")) {
      // .section .rodata
      const char *p = s + strlen(".section");
      skip_spaces(&p);
      if (*p) {
        sbuf_puts(out, "section ");
        sbuf_puts(out, p);
        emit_newline(out);
      } else {
        emit_newline(out);
      }
      return;
    }

    // Normalize common directives to ones supported by the Intel-ish assembler.
    if (starts_with(s, ".globl") || starts_with(s, ".global")) {
      const char *p = s;
      // consume .globl/.global
      while (*p && !is_space_no_nl(*p)) p++;
      skip_spaces(&p);
      sbuf_puts(out, "global ");
      sbuf_puts(out, p);
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".ascii") || starts_with(s, ".asciz")) {
      // Map to db. For .asciz, append ,0
      const int is_z = starts_with(s, ".asciz");
      const char *p = s;
      while (*p && !is_space_no_nl(*p)) p++;
      skip_spaces(&p);
      sbuf_puts(out, "db ");
      sbuf_puts(out, p);
      if (is_z)
        sbuf_puts(out, ", 0");
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".byte")) {
      const char *p = s + strlen(".byte");
      skip_spaces(&p);
      sbuf_puts(out, "db ");
      sbuf_puts(out, p);
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".long")) {
      const char *p = s + strlen(".long");
      skip_spaces(&p);
      sbuf_puts(out, "dd ");
      sbuf_puts(out, p);
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".value") || starts_with(s, ".word")) {
      const char *p = s;
      while (*p && !is_space_no_nl(*p)) p++;
      skip_spaces(&p);
      sbuf_puts(out, "dw ");
      sbuf_puts(out, p);
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".zero")) {
      const char *p = s + strlen(".zero");
      skip_spaces(&p);
      sbuf_puts(out, "resb ");
      sbuf_puts(out, p);
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".align")) {
      const char *p = s + strlen(".align");
      skip_spaces(&p);
      sbuf_puts(out, "align ");
      sbuf_puts(out, p);
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".intel_syntax")) {
      // no-op
      emit_newline(out);
      return;
    }

    if (starts_with(s, ".file") || starts_with(s, ".type") || starts_with(s, ".size") ||
        starts_with(s, ".ident") || starts_with(s, ".p2align") || starts_with(s, ".local") ||
        starts_with(s, ".comm") || starts_with(s, ".section")) {
      // ignore these for now
      emit_newline(out);
      return;
    }

    // Unknown directive: ignore for now
    emit_newline(out);
    return;
  }

  // Instructions / prefixes.
  // Split mnemonic and rest.
  char mn[32] = {0};
  const char *p = s;
  int mi = 0;
  while (*p && !is_space_no_nl(*p)) {
    if (mi < (int)sizeof(mn) - 1)
      mn[mi++] = *p;
    p++;
  }
  mn[mi] = 0;
  skip_spaces(&p);

  // Handle AT&T string op suffix forms.
  if (!strcmp(mn, "movzbl")) {
    // movzbl src, dst  => movzx dst, byte src
    char a0[256], a1[256];
    split_operands(p, a0, sizeof(a0), a1, sizeof(a1));
    sbuf_puts(out, "movzx ");
    emit_operand_intel(out, a1, 0);
    sbuf_puts(out, ", ");
    emit_operand_intel(out, a0, 8);
    emit_newline(out);
    return;
  }
  if (!strcmp(mn, "movzwl")) {
    char a0[256], a1[256];
    split_operands(p, a0, sizeof(a0), a1, sizeof(a1));
    sbuf_puts(out, "movzx ");
    emit_operand_intel(out, a1, 0);
    sbuf_puts(out, ", ");
    emit_operand_intel(out, a0, 16);
    emit_newline(out);
    return;
  }
  if (!strcmp(mn, "movsbl")) {
    char a0[256], a1[256];
    split_operands(p, a0, sizeof(a0), a1, sizeof(a1));
    sbuf_puts(out, "movsx ");
    emit_operand_intel(out, a1, 0);
    sbuf_puts(out, ", ");
    emit_operand_intel(out, a0, 8);
    emit_newline(out);
    return;
  }
  if (!strcmp(mn, "movswl")) {
    char a0[256], a1[256];
    split_operands(p, a0, sizeof(a0), a1, sizeof(a1));
    sbuf_puts(out, "movsx ");
    emit_operand_intel(out, a1, 0);
    sbuf_puts(out, ", ");
    emit_operand_intel(out, a0, 16);
    emit_newline(out);
    return;
  }

  // Convert rep/repne prefixes: EYN assembler models them as mnemonics.
  if (!strcmp(mn, "rep") || !strcmp(mn, "repne") || !strcmp(mn, "repe") || !strcmp(mn, "repnz") || !strcmp(mn, "repz")) {
    sbuf_puts(out, mn);
    if (*p) {
      sbuf_putc(out, ' ');
      sbuf_puts(out, p);
    }
    emit_newline(out);
    return;
  }

  // Track the original size suffix for common instructions, so we can
  // emit byte/word/dword prefixes for memory operands.
  char size_suffix = 0;
  size_t mnlen = strlen(mn);
  if (mnlen && !(mn[0] == 'j') && !starts_with(mn, "set")) {
    char last = mn[mnlen - 1];
    if ((last == 'b' || last == 'w' || last == 'l') && is_suffixed_atandt_mnemonic(mn))
      size_suffix = last;
  }

  // Strip common suffix
  normalize_mnemonic(mn);
  int size_hint_bits = size_hint_from_suffix(size_suffix);

  // Swap operands for common AT&T binops and cmp/test.
  if (!strcmp(mn, "mov") || !strcmp(mn, "lea")) {
    char a0[256], a1[256];
    split_operands(p, a0, sizeof(a0), a1, sizeof(a1));
    sbuf_puts(out, mn);
    sbuf_putc(out, ' ');

    int hint_a1 = 0;
    int hint_a0 = 0;

    // For mov{b,w,l}, apply size hint to any memory operand so the assembler
    // can choose the correct encoding (especially for "mov [mem], imm").
    if (size_hint_bits) {
      if (strchr(a1, '(') || is_bare_symbol_operand(a1)) hint_a1 = size_hint_bits;
      if (strchr(a0, '(') || is_bare_symbol_operand(a0)) hint_a0 = size_hint_bits;
    }

    // For mov/lea, a bare symbol without '$' is a memory reference in AT&T.
    // Force it into [sym] form by passing a size hint (default dword).
    if (is_bare_symbol_operand(a1) && !hint_a1) hint_a1 = 32;
    if (is_bare_symbol_operand(a0) && !hint_a0) hint_a0 = 32;

    emit_operand_intel(out, a1, hint_a1);
    if (a0[0]) {
      sbuf_puts(out, ", ");
      emit_operand_intel(out, a0, hint_a0);
    }
    emit_newline(out);
    return;
  }

  if (!strcmp(mn, "add") || !strcmp(mn, "sub") || !strcmp(mn, "and") || !strcmp(mn, "or") ||
      !strcmp(mn, "xor") || !strcmp(mn, "cmp") || !strcmp(mn, "test")) {
    emit_binop_swapped(out, mn, p);
    return;
  }

  if (!strcmp(mn, "imul")) {
    // chibicc often emits: imull $imm, %reg  or imull %src, %dst
    // We can treat it as swapped like other binops.
    emit_binop_swapped(out, mn, p);
    return;
  }

  if (!strcmp(mn, "push") || !strcmp(mn, "pop") || !strcmp(mn, "call") || !strcmp(mn, "jmp") ||
      !strcmp(mn, "idiv") || !strcmp(mn, "div") || !strcmp(mn, "neg") || !strcmp(mn, "not") ||
      !strcmp(mn, "inc") || !strcmp(mn, "dec")) {
    sbuf_puts(out, mn);
    if (*p) {
      sbuf_putc(out, ' ');
      emit_operand_intel(out, p, 0);
    }
    emit_newline(out);
    return;
  }

  // jcc and setcc pass-through (after suffix strip it should be identical)
  if (mn[0] == 'j' || starts_with(mn, "set")) {
    sbuf_puts(out, mn);
    if (*p) {
      sbuf_putc(out, ' ');
      // target label, remove '*'
      char tmp[256];
      strncpy(tmp, p, sizeof(tmp) - 1);
      tmp[sizeof(tmp) - 1] = 0;
      trim_right(tmp);
      while (tmp[0] && is_space_no_nl(tmp[0])) memmove(tmp, tmp + 1, strlen(tmp));
      strip_indirect_star(tmp);
      if (tmp[0] == '*') strip_indirect_star(tmp);
      if (tmp[0] == '%') atandt_reg_to_intel(tmp);
      sbuf_puts(out, tmp);
    }
    emit_newline(out);
    return;
  }

  // Fallback: emit mnemonic and raw operands after removing %/$/* where reasonable.
  sbuf_puts(out, mn);
  if (*p) {
    sbuf_putc(out, ' ');
    // naive: just strip % and $ in a copy
    char tmp[512];
    size_t n = strlen(p);
    if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
    memcpy(tmp, p, n);
    tmp[n] = 0;
    for (size_t i = 0; tmp[i]; i++) {
      if (tmp[i] == '%') memmove(tmp + i, tmp + i + 1, strlen(tmp + i));
      if (tmp[i] == '$') memmove(tmp + i, tmp + i + 1, strlen(tmp + i));
    }
    sbuf_puts(out, tmp);
  }
  emit_newline(out);
}

static char *translate_gas_to_intel(const char *src) {
  sbuf_t out;
  sbuf_init(&out);

  const char *p = src;
  while (*p) {
    const char *line_start = p;
    while (*p && *p != '\n') p++;
    size_t line_len = (size_t)(p - line_start);

    char *line = calloc(1, line_len + 1);
    if (!line) error("out of memory");
    memcpy(line, line_start, line_len);
    line[line_len] = 0;

    // Strip trailing comments starting with '#'
    // (Keep '#' inside string literals best-effort: very rare in chibicc output.)
    int in_str = 0;
    for (size_t i = 0; line[i]; i++) {
      if (line[i] == '"') in_str = !in_str;
      if (!in_str && line[i] == '#') { line[i] = 0; break; }
    }

    trim_right(line);
    translate_line(&out, line);
    free(line);

    if (*p == '\n') p++;
  }

  return out.data;
}

// ------------------------
// Minimal Intel-ish assembler (ported, namespaced)
// ------------------------

typedef enum {
  EYNAS_SECTION_NONE = 0,
  EYNAS_SECTION_TEXT,
  EYNAS_SECTION_DATA,
} eynas_section_t;

typedef enum {
  EYNAS_OPERAND_NONE = 0,
  EYNAS_OPERAND_REGISTER,
  EYNAS_OPERAND_IMMEDIATE,
  EYNAS_OPERAND_LABEL,
  EYNAS_OPERAND_MEMORY,
} eynas_operand_type_t;

typedef struct {
  eynas_operand_type_t type;
  char value[64];
  int size_hint; // bits: 0/8/16/32
} eynas_operand_t;

typedef struct eynas_instruction {
  char mnemonic[16];
  eynas_operand_t operands[2];
  eynas_section_t section;
  int line_num;
  struct eynas_instruction *next;
} eynas_instruction_t;

typedef struct eynas_label {
  char name[64];
  eynas_section_t section;
  int offset;
  int address;
  int line_num;
  struct eynas_label *next;
} eynas_label_t;

typedef struct eynas_datadef {
  char directive[8];
  char value[128];
  eynas_section_t section;
  int line_num;
  struct eynas_datadef *next;
} eynas_datadef_t;

typedef struct {
  eynas_instruction_t *instructions;
  eynas_label_t *labels;
  eynas_datadef_t *data_defs;
} eynas_ast_t;

typedef struct eynas_sym {
  char name[64];
  eynas_section_t section;
  int address;
  struct eynas_sym *next;
} eynas_sym_t;

typedef struct {
  eynas_sym_t *head;
} eynas_symtab_t;

typedef enum {
  EYNAS_TOK_LABEL,
  EYNAS_TOK_MNEMONIC,
  EYNAS_TOK_REGISTER,
  EYNAS_TOK_IMMEDIATE,
  EYNAS_TOK_MEMORY,
  EYNAS_TOK_SIZE,
  EYNAS_TOK_SECTION,
  EYNAS_TOK_DIRECTIVE,
  EYNAS_TOK_COMMA,
  EYNAS_TOK_NEWLINE,
  EYNAS_TOK_EOF,
  EYNAS_TOK_UNKNOWN,
} eynas_tok_type_t;

typedef struct {
  eynas_tok_type_t type;
  char text[64];
} eynas_token_t;

typedef struct {
  const char *src;
  size_t pos;
  int has_pushback;
  eynas_token_t pushback;
} eynas_lexer_t;

// Instruction set table (subset is ok; encoder uses mnemonics+forms)

typedef enum {
  INST_CAT_DATA_MOVEMENT,
  INST_CAT_ARITHMETIC,
  INST_CAT_LOGICAL,
  INST_CAT_CONTROL_FLOW,
  INST_CAT_STRING,
  INST_CAT_SYSTEM,
  INST_CAT_FPU,
  INST_CAT_MMX,
  INST_CAT_SSE,
} eynas_inst_cat_t;

typedef struct {
  const char *mnemonic;
  uint8_t opcode;
  uint8_t modrm_required;
  uint8_t immediate_required;
  uint8_t displacement_required;
  eynas_inst_cat_t category;
  const char *description;
} eynas_instinfo_t;

// Keep the tables exactly as the kernel assembler expects for supported subset.
// For now include the full set by including the existing implementation logic inline.

// Register encodings
static const char *eynas_reg_names[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
static const char *eynas_reg8_names[] = {"al","cl","dl","bl","ah","ch","dh","bh"};
static const char *eynas_seg_reg_names[] = {"es","cs","ss","ds","fs","gs"};

// Forward declarations for instruction table lookup.
static int eynas_is_valid_register(const char *name);
static int eynas_is_valid_instruction(const char *name);

// Minimal instruction tables: include those used by chibicc output.
static const eynas_instinfo_t eynas_data_movement_insts[] = {
  {"mov", 0x88, 1, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"mov", 0xB8, 0, 1, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"lea", 0x8D, 1, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"push", 0x50, 0, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"push", 0x68, 0, 1, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"push", 0xFF, 1, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"pop", 0x58, 0, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"pop", 0x8F, 1, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"movsx", 0x0F, 1, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {"movzx", 0x0F, 1, 0, 0, INST_CAT_DATA_MOVEMENT, NULL},
  {NULL,0,0,0,0,0,NULL}
};

static const eynas_instinfo_t eynas_arith_insts[] = {
  {"add", 0x00, 1, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"add", 0x80, 1, 1, 0, INST_CAT_ARITHMETIC, NULL},
  {"sub", 0x28, 1, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"sub", 0x80, 1, 1, 0, INST_CAT_ARITHMETIC, NULL},
  {"inc", 0x40, 0, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"dec", 0x48, 0, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"imul", 0xF6, 1, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"imul", 0x69, 1, 1, 0, INST_CAT_ARITHMETIC, NULL},
  {"idiv", 0xF6, 1, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"cmp", 0x38, 1, 0, 0, INST_CAT_ARITHMETIC, NULL},
  {"cmp", 0x80, 1, 1, 0, INST_CAT_ARITHMETIC, NULL},
  {NULL,0,0,0,0,0,NULL}
};

static const eynas_instinfo_t eynas_logic_insts[] = {
  {"and", 0x20, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"and", 0x80, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"or", 0x08, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"or", 0x80, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"xor", 0x30, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"xor", 0x80, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"not", 0xF6, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"test", 0x84, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"test", 0xF6, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"shl", 0xD0, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"shl", 0xC0, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"shr", 0xD0, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"shr", 0xC0, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"sar", 0xD0, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"sar", 0xC0, 1, 1, 0, INST_CAT_LOGICAL, NULL},
  {"sete", 0x0F, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {"setne", 0x0F, 1, 0, 0, INST_CAT_LOGICAL, NULL},
  {NULL,0,0,0,0,0,NULL}
};

static const eynas_instinfo_t eynas_cf_insts[] = {
  {"jmp", 0xE9, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jmp", 0xEB, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jmp", 0xFF, 1, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"call", 0xE8, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"call", 0xFF, 1, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"ret", 0xC3, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"leave", 0xC9, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"je", 0x74, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jne", 0x75, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jl", 0x7C, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jle", 0x7E, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jg", 0x7F, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jge", 0x7D, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"ja", 0x77, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jae", 0x73, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jb", 0x72, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jbe", 0x76, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"js", 0x78, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jns", 0x79, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jo", 0x70, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {"jno", 0x71, 0, 0, 0, INST_CAT_CONTROL_FLOW, NULL},
  {NULL,0,0,0,0,0,NULL}
};

static const eynas_instinfo_t eynas_string_insts[] = {
  {"rep", 0xF3, 0, 0, 0, INST_CAT_STRING, NULL},
  {"repne", 0xF2, 0, 0, 0, INST_CAT_STRING, NULL},
  {"stosb", 0xAA, 0, 0, 0, INST_CAT_STRING, NULL},
  {"stosd", 0xAB, 0, 0, 0, INST_CAT_STRING, NULL},
  {"movsb", 0xA4, 0, 0, 0, INST_CAT_STRING, NULL},
  {"movsd", 0xA5, 0, 0, 0, INST_CAT_STRING, NULL},
  {NULL,0,0,0,0,0,NULL}
};

static const eynas_instinfo_t eynas_system_insts[] = {
  {"int", 0xCD, 0, 1, 0, INST_CAT_SYSTEM, NULL},
  {NULL,0,0,0,0,0,NULL}
};

static const eynas_instinfo_t *eynas_find_inst(const char *mnemonic) {
  const eynas_instinfo_t *tables[] = {
    eynas_data_movement_insts,
    eynas_arith_insts,
    eynas_logic_insts,
    eynas_cf_insts,
    eynas_string_insts,
    eynas_system_insts,
  };

  // Exact match first.
  for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
    for (const eynas_instinfo_t *p = tables[t]; p->mnemonic; p++) {
      if (!strcmp(p->mnemonic, mnemonic))
        return p;
    }
  }

  // Accept common AT&T size-suffixed mnemonics (pushl/movl/etc) as aliases.
  // This is a safety net in case translation didn't normalize them.
  size_t n = strlen(mnemonic);
  if (n > 2) {
    char last = mnemonic[n - 1];
    if (last == 'b' || last == 'w' || last == 'l') {
      char base[32];
      if (n >= sizeof(base)) n = sizeof(base) - 1;
      memcpy(base, mnemonic, n);
      base[n] = 0;
      base[n - 1] = 0;
      for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        for (const eynas_instinfo_t *p = tables[t]; p->mnemonic; p++) {
          if (!strcmp(p->mnemonic, base))
            return p;
        }
      }
    }
  }

  return NULL;
}

static int eynas_get_reg_encoding(const char *reg) {
  // Be permissive about 64-bit register spellings so we don't mis-tokenize
  // them as labels when assembling in 32-bit mode.
  // This is primarily to tolerate accidental %rbp/%rsp/%rax etc.
  if (!strcmp(reg, "rax")) reg = "eax";
  else if (!strcmp(reg, "rcx")) reg = "ecx";
  else if (!strcmp(reg, "rdx")) reg = "edx";
  else if (!strcmp(reg, "rbx")) reg = "ebx";
  else if (!strcmp(reg, "rsp")) reg = "esp";
  else if (!strcmp(reg, "rbp")) reg = "ebp";
  else if (!strcmp(reg, "rsi")) reg = "esi";
  else if (!strcmp(reg, "rdi")) reg = "edi";

  for (int i = 0; i < 8; i++)
    if (!strcmp(reg, eynas_reg_names[i]))
      return i;
  return -1;
}

static int eynas_get_reg8_encoding(const char *reg) {
  for (int i = 0; i < 8; i++)
    if (!strcmp(reg, eynas_reg8_names[i]))
      return i;
  return -1;
}

static int eynas_is_valid_register(const char *name) {
  if (eynas_get_reg_encoding(name) >= 0) return 1;
  if (eynas_get_reg8_encoding(name) >= 0) return 1;
  for (int i = 0; i < 6; i++)
    if (!strcmp(name, eynas_seg_reg_names[i]))
      return 1;
  return 0;
}

static int eynas_is_valid_instruction(const char *name) {
  return eynas_find_inst(name) != NULL;
}

static void eynas_lexer_init(eynas_lexer_t *lx, const char *src) {
  lx->src = src;
  lx->pos = 0;
  lx->has_pushback = 0;
}

static void eynas_lexer_unget(eynas_lexer_t *lx, eynas_token_t tok) {
  lx->has_pushback = 1;
  lx->pushback = tok;
}

static eynas_token_t eynas_next_token(eynas_lexer_t *lx) {
  if (lx->has_pushback) {
    lx->has_pushback = 0;
    return lx->pushback;
  }

  eynas_token_t tok;
  memset(&tok, 0, sizeof(tok));
  tok.type = EYNAS_TOK_EOF;

  const char *src = lx->src;
  size_t len = strlen(src);
  size_t pos = lx->pos;

  while (pos < len && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r'))
    pos++;

  if (pos < len && (src[pos] == ';' || src[pos] == '#')) {
    while (pos < len && src[pos] != '\n') pos++;
  }

  if (pos < len && src[pos] == '\n') {
    tok.type = EYNAS_TOK_NEWLINE;
    tok.text[0] = '\n';
    tok.text[1] = 0;
    lx->pos = pos + 1;
    return tok;
  }

  if (pos >= len || src[pos] == 0) {
    lx->pos = pos;
    return tok;
  }

  if (src[pos] == ',') {
    tok.type = EYNAS_TOK_COMMA;
    tok.text[0] = ',';
    tok.text[1] = 0;
    lx->pos = pos + 1;
    return tok;
  }

  if (src[pos] == '"') {
    size_t start = pos;
    pos++;
    while (pos < len && src[pos] != '"') {
      if (src[pos] == '\\' && pos + 1 < len)
        pos += 2;
      else
        pos++;
    }
    if (pos < len && src[pos] == '"') pos++;
    size_t slen = pos - start;
    if (slen >= sizeof(tok.text)) slen = sizeof(tok.text) - 1;
    memcpy(tok.text, src + start, slen);
    tok.text[slen] = 0;
    tok.type = EYNAS_TOK_IMMEDIATE;
    lx->pos = pos;
    return tok;
  }

  if (src[pos] == '[') {
    size_t start = pos;
    pos++;
    while (pos < len && src[pos] != ']') pos++;
    if (pos < len && src[pos] == ']') pos++;
    size_t mlen = pos - start;
    if (mlen >= sizeof(tok.text)) mlen = sizeof(tok.text) - 1;
    memcpy(tok.text, src + start, mlen);
    tok.text[mlen] = 0;
    tok.type = EYNAS_TOK_MEMORY;
    lx->pos = pos;
    return tok;
  }

  if (isalpha((unsigned char)src[pos]) || src[pos] == '_' || src[pos] == '.') {
    size_t start = pos;
    while (pos < len && (isalnum((unsigned char)src[pos]) || src[pos] == '.' || src[pos] == '_'))
      pos++;
    size_t id_len = pos - start;
    if (id_len >= sizeof(tok.text)) id_len = sizeof(tok.text) - 1;
    memcpy(tok.text, src + start, id_len);
    tok.text[id_len] = 0;

    if (!strcmp(tok.text, "byte") || !strcmp(tok.text, "word") || !strcmp(tok.text, "dword")) {
      tok.type = EYNAS_TOK_SIZE;
      lx->pos = pos;
      return tok;
    }

    if (src[pos] == ':') {
      tok.type = EYNAS_TOK_LABEL;
      lx->pos = pos + 1;
      return tok;
    }

    if (!strcmp(tok.text, "section") || !strcmp(tok.text, ".section")) {
      tok.type = EYNAS_TOK_SECTION;
      lx->pos = pos;
      return tok;
    }

    if (!strcmp(tok.text, "db") || !strcmp(tok.text, "dw") || !strcmp(tok.text, "dd") ||
        !strcmp(tok.text, "resb") || !strcmp(tok.text, "resw") || !strcmp(tok.text, "resd") ||
        !strcmp(tok.text, "align") || !strcmp(tok.text, "global")) {
      tok.type = EYNAS_TOK_DIRECTIVE;
      lx->pos = pos;
      return tok;
    }

    if (eynas_is_valid_register(tok.text)) {
      tok.type = EYNAS_TOK_REGISTER;
      lx->pos = pos;
      return tok;
    }

    if (eynas_is_valid_instruction(tok.text)) {
      tok.type = EYNAS_TOK_MNEMONIC;
      lx->pos = pos;
      return tok;
    }

    tok.type = EYNAS_TOK_UNKNOWN;
    lx->pos = pos;
    return tok;
  }

  // numeric immediate (decimal/hex)
  if (isdigit((unsigned char)src[pos]) || (src[pos] == '-' && isdigit((unsigned char)src[pos + 1])) ||
      (src[pos] == '+' && isdigit((unsigned char)src[pos + 1]))) {
    size_t start = pos;
    pos++;
    while (pos < len && (isalnum((unsigned char)src[pos]) || src[pos] == 'x' || src[pos] == 'X'))
      pos++;
    size_t nlen = pos - start;
    if (nlen >= sizeof(tok.text)) nlen = sizeof(tok.text) - 1;
    memcpy(tok.text, src + start, nlen);
    tok.text[nlen] = 0;
    tok.type = EYNAS_TOK_IMMEDIATE;
    lx->pos = pos;
    return tok;
  }

  // Unknown single char: skip
  tok.type = EYNAS_TOK_UNKNOWN;
  tok.text[0] = src[pos];
  tok.text[1] = 0;
  lx->pos = pos + 1;
  return tok;
}

static eynas_ast_t *eynas_parse(const char *src, const char *input_path);
static void eynas_free_ast(eynas_ast_t *ast);

static void eynas_symtab_init(eynas_symtab_t *t) { t->head = NULL; }

static void eynas_symtab_add(eynas_symtab_t *t, const char *name, eynas_section_t sec, int addr) {
  eynas_sym_t *e = calloc(1, sizeof(*e));
  if (!e) error("out of memory");
  strncpy(e->name, name, sizeof(e->name) - 1);
  e->section = sec;
  e->address = addr;
  e->next = t->head;
  t->head = e;
}

static int eynas_symtab_lookup(eynas_symtab_t *t, const char *name, eynas_section_t sec) {
  for (eynas_sym_t *e = t->head; e; e = e->next)
    if (e->section == sec && !strcmp(e->name, name))
      return e->address;
  // allow cross-section lookup
  for (eynas_sym_t *e = t->head; e; e = e->next)
    if (!strcmp(e->name, name))
      return e->address;
  return -1;
}

static void eynas_symtab_free(eynas_symtab_t *t) {
  eynas_sym_t *e = t->head;
  while (e) {
    eynas_sym_t *n = e->next;
    free(e);
    e = n;
  }
  t->head = NULL;
}

static int eynas_parse_int(const char *s) {
  if (!s || !s[0]) return 0;
  int base = 10;
  if (strlen(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    base = 16;

  // userland stdlib provides strtoul but not strtol
  int sign = 1;
  if (*s == '+')
    s++;
  else if (*s == '-') {
    sign = -1;
    s++;
  }

  unsigned long v = strtoul(s, NULL, base);
  return (int)(sign * (int)v);
}

static void eynas_ast_add_inst(eynas_ast_t *ast, eynas_instruction_t *inst) {
  inst->next = NULL;
  if (!ast->instructions) {
    ast->instructions = inst;
    return;
  }
  eynas_instruction_t *p = ast->instructions;
  while (p->next) p = p->next;
  p->next = inst;
}

static void eynas_ast_add_label(eynas_ast_t *ast, eynas_label_t *lab) {
  lab->next = NULL;
  if (!ast->labels) {
    ast->labels = lab;
    return;
  }
  eynas_label_t *p = ast->labels;
  while (p->next) p = p->next;
  p->next = lab;
}

static void eynas_ast_add_data(eynas_ast_t *ast, eynas_datadef_t *d) {
  d->next = NULL;
  if (!ast->data_defs) {
    ast->data_defs = d;
    return;
  }
  eynas_datadef_t *p = ast->data_defs;
  while (p->next) p = p->next;
  p->next = d;
}

static void eynas_build_symtab(eynas_ast_t *ast, eynas_symtab_t *tab) {
  eynas_symtab_init(tab);
  for (eynas_label_t *l = ast->labels; l; l = l->next)
    eynas_symtab_add(tab, l->name, l->section, l->address);
}

// --------- Encoder helpers

static int eynas_is_reg8(const char *r) { return eynas_get_reg8_encoding(r) >= 0; }

static void eynas_parse_mem(const char *mem, int *out_has_base, int *out_base,
                            int *out_has_index, int *out_index, int *out_scale,
                            int *out_disp, char *out_label, size_t out_label_sz) {
  // mem like: [eax+ecx*4+8] or [label+4] or [ebp-8]
  // We only support base+index*scale+disp OR label+disp.
  *out_has_base = 0;
  *out_base = 0;
  *out_has_index = 0;
  *out_index = 0;
  *out_scale = 1;
  *out_disp = 0;
  if (out_label && out_label_sz) out_label[0] = 0;

  const char *p = mem;
  if (*p == '[') p++;
  char buf[128];
  size_t n = 0;
  while (*p && *p != ']' && n < sizeof(buf) - 1) {
    buf[n++] = *p++;
  }
  buf[n] = 0;

  // remove spaces
  char buf2[128];
  size_t j = 0;
  for (size_t i = 0; buf[i] && j < sizeof(buf2) - 1; i++)
    if (buf[i] != ' ' && buf[i] != '\t')
      buf2[j++] = buf[i];
  buf2[j] = 0;

  // If starts with alpha/_/.
  if (isalpha((unsigned char)buf2[0]) || buf2[0] == '_' || buf2[0] == '.') {
    // Could be either a label or a register (e.g. [esp+4]).
    // Determine the first token and treat it as a register if it matches.
    size_t k = 0;
    while (buf2[k] && buf2[k] != '+' && buf2[k] != '-') k++;

    char first_tok[64];
    size_t ft = k;
    if (ft >= sizeof(first_tok)) ft = sizeof(first_tok) - 1;
    memcpy(first_tok, buf2, ft);
    first_tok[ft] = 0;

    int is_reg = 0;
    char *star = strchr(first_tok, '*');
    if (star) {
      *star = 0;
      if (eynas_get_reg_encoding(first_tok) >= 0)
        is_reg = 1;
    } else {
      if (eynas_get_reg_encoding(first_tok) >= 0)
        is_reg = 1;
    }

    if (!is_reg) {
      // label until + or -
      if (out_label && out_label_sz) {
        size_t ln = k;
        if (ln >= out_label_sz) ln = out_label_sz - 1;
        memcpy(out_label, buf2, ln);
        out_label[ln] = 0;

        // Tolerate GAS relocation suffixes (x86-64 PIC emits e.g. foo@GOTPCREL).
        // Our tiny assembler/linker doesn't support those relocations; treat it
        // as a reference to the base symbol name.
        char *at = strchr(out_label, '@');
        if (at)
          *at = 0;
      }
      if (buf2[k])
        *out_disp = eynas_parse_int(buf2 + k);
      return;
    }
  }

  // Parse base/index/scale/disp.
  // Split by + and - keeping sign for disp.
  // Very small parser: look for patterns reg, reg*scale, immediate.

  const char *q = buf2;
  int sign = +1;
  while (*q) {
    if (*q == '+') { sign = +1; q++; continue; }
    if (*q == '-') { sign = -1; q++; continue; }

    // token until next +/-
    char tok[64];
    size_t tlen = 0;
    while (q[tlen] && q[tlen] != '+' && q[tlen] != '-' && tlen < sizeof(tok) - 1)
      tlen++;
    memcpy(tok, q, tlen);
    tok[tlen] = 0;
    q += tlen;

    char *star = strchr(tok, '*');
    if (star) {
      *star++ = 0;
      int idx = eynas_get_reg_encoding(tok);
      if (idx >= 0) {
        *out_has_index = 1;
        *out_index = idx;
        *out_scale = eynas_parse_int(star);
        if (*out_scale == 0) *out_scale = 1;
      }
      continue;
    }

    int reg = eynas_get_reg_encoding(tok);
    if (reg >= 0) {
      if (!*out_has_base) {
        *out_has_base = 1;
        *out_base = reg;
      } else if (!*out_has_index) {
        *out_has_index = 1;
        *out_index = reg;
        *out_scale = 1;
      }
      continue;
    }

    // immediate
    *out_disp += sign * eynas_parse_int(tok);
  }
}

static void eynas_emit_u8(uint8_t **buf, size_t *len, size_t *cap, uint8_t v) {
  if (*len + 1 > *cap) {
    size_t nc = *cap ? *cap * 2 : 256;
    while (*len + 1 > nc) nc *= 2;
    uint8_t *p = realloc(*buf, nc);
    if (!p) error("out of memory");
    *buf = p;
    *cap = nc;
  }
  (*buf)[(*len)++] = v;
}

static void eynas_emit_u32(uint8_t **buf, size_t *len, size_t *cap, uint32_t v) {
  eynas_emit_u8(buf, len, cap, (uint8_t)(v & 0xff));
  eynas_emit_u8(buf, len, cap, (uint8_t)((v >> 8) & 0xff));
  eynas_emit_u8(buf, len, cap, (uint8_t)((v >> 16) & 0xff));
  eynas_emit_u8(buf, len, cap, (uint8_t)((v >> 24) & 0xff));
}

static void eynas_emit_u16(uint8_t **buf, size_t *len, size_t *cap, uint16_t v) {
  eynas_emit_u8(buf, len, cap, (uint8_t)(v & 0xff));
  eynas_emit_u8(buf, len, cap, (uint8_t)((v >> 8) & 0xff));
}

static void eynas_emit_modrm(uint8_t **buf, size_t *len, size_t *cap, uint8_t mod, uint8_t reg, uint8_t rm) {
  uint8_t v = (uint8_t)((mod << 6) | ((reg & 7) << 3) | (rm & 7));
  eynas_emit_u8(buf, len, cap, v);
}

static void eynas_emit_sib(uint8_t **buf, size_t *len, size_t *cap, uint8_t scale, uint8_t index, uint8_t base) {
  uint8_t s = 0;
  if (scale == 1) s = 0;
  else if (scale == 2) s = 1;
  else if (scale == 4) s = 2;
  else if (scale == 8) s = 3;
  uint8_t v = (uint8_t)((s << 6) | ((index & 7) << 3) | (base & 7));
  eynas_emit_u8(buf, len, cap, v);
}

static int eynas_parse_imm32(const char *s, uint32_t *out) {
  if (!s || !s[0]) return -1;
  int sign = 1;
  if (*s == '+')
    s++;
  else if (*s == '-') {
    sign = -1;
    s++;
  }

  int base = 10;
  if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) base = 16;

  char *end = NULL;
  unsigned long u = strtoul(s, &end, base);
  if (end == s) return -1;

  int32_t v = (int32_t)u;
  if (sign < 0)
    v = (int32_t)(-v);
  *out = (uint32_t)v;
  return 0;
}

static void eynas_encode_inst(const eynas_instinfo_t *info, const eynas_instruction_t *inst,
                             eynas_symtab_t *symtab,
                             uint8_t **code, size_t *code_len, size_t *code_cap,
                             int cur_addr, const char *input_path) {
  (void)input_path;

  const char *path = input_path ? input_path : "<as>";

  const char *type_name(eynas_operand_type_t t) {
    switch (t) {
      case EYNAS_OPERAND_NONE: return "none";
      case EYNAS_OPERAND_REGISTER: return "reg";
      case EYNAS_OPERAND_IMMEDIATE: return "imm";
      case EYNAS_OPERAND_LABEL: return "label";
      case EYNAS_OPERAND_MEMORY: return "mem";
    }
    return "?";
  }

  // This encoder is intentionally minimal and only supports the operand forms
  // produced by the translator for chibicc i386 output.

  const eynas_operand_t *a = &inst->operands[0];
  const eynas_operand_t *b = &inst->operands[1];

  // Prefix mnemonics (rep/repne)
  if (!strcmp(info->mnemonic, "rep") || !strcmp(info->mnemonic, "repne")) {
    eynas_emit_u8(code, code_len, code_cap, info->opcode);
    return;
  }

  if (!strcmp(info->mnemonic, "stosb")) {
    eynas_emit_u8(code, code_len, code_cap, 0xAA);
    return;
  }

  if (!strcmp(info->mnemonic, "stosd")) {
    eynas_emit_u8(code, code_len, code_cap, 0xAB);
    return;
  }

  if (!strcmp(info->mnemonic, "ret")) {
    eynas_emit_u8(code, code_len, code_cap, 0xC3);
    return;
  }

  if (!strcmp(info->mnemonic, "leave")) {
    eynas_emit_u8(code, code_len, code_cap, 0xC9);
    return;
  }

  // int imm8
  if (!strcmp(info->mnemonic, "int")) {
    if (a->type != EYNAS_OPERAND_IMMEDIATE)
      error("int expects immediate");
    uint32_t imm = 0;
    if (eynas_parse_imm32(a->value, &imm) != 0)
      error("int: invalid immediate: %s", a->value);
    if (imm > 0xFFu)
      error("int: immediate out of range: %s", a->value);
    eynas_emit_u8(code, code_len, code_cap, 0xCD);
    eynas_emit_u8(code, code_len, code_cap, (uint8_t)imm);
    return;
  }

  // call/jmp rel32 labels
  if ((!strcmp(info->mnemonic, "call") || !strcmp(info->mnemonic, "jmp")) && a->type == EYNAS_OPERAND_LABEL) {
    int target = eynas_symtab_lookup(symtab, a->value, EYNAS_SECTION_TEXT);
    if (target < 0)
      error("%s: unknown label: %s", input_path ? input_path : "<as>", a->value);
    int rel = target - (cur_addr + 5);
    eynas_emit_u8(code, code_len, code_cap, info->opcode);
    eynas_emit_u32(code, code_len, code_cap, (uint32_t)rel);
    return;
  }

  // jcc (always encode near/rel32 form)
  // This avoids needing multi-pass branch relaxation.
  if (eynas_is_jcc_mnemonic(info->mnemonic)) {
    if (a->type != EYNAS_OPERAND_LABEL)
      error("conditional jump expects label");
    int target = eynas_symtab_lookup(symtab, a->value, EYNAS_SECTION_TEXT);
    if (target < 0)
      error("unknown label: %s", a->value);
    // Short Jcc is 0x70+cc with rel8. Near Jcc is 0x0F 0x80+cc with rel32.
    uint8_t cc = (uint8_t)(info->opcode & 0x0F);
    int rel = target - (cur_addr + 6);
    eynas_emit_u8(code, code_len, code_cap, 0x0F);
    eynas_emit_u8(code, code_len, code_cap, (uint8_t)(0x80u + cc));
    eynas_emit_u32(code, code_len, code_cap, (uint32_t)rel);
    return;
  }

  // mov reg, imm32
  if (!strcmp(info->mnemonic, "mov") && a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_IMMEDIATE) {
    // reg8, imm8
    if (eynas_is_reg8(a->value)) {
      int r8 = eynas_get_reg8_encoding(a->value);
      uint32_t imm = 0;
      if (eynas_parse_imm32(b->value, &imm) != 0)
        error("mov: invalid immediate: %s", b->value);
      if (imm > 0xFFu)
        error("mov %s, imm8 out of range: %s", a->value, b->value);
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)(0xB0 + r8));
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)imm);
      return;
    }

    int reg = eynas_get_reg_encoding(a->value);
    uint32_t imm = 0;
    if (eynas_parse_imm32(b->value, &imm) != 0) {
      // allow label immediate
      int addr = eynas_symtab_lookup(symtab, b->value, EYNAS_SECTION_TEXT);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, b->value, EYNAS_SECTION_DATA);
      if (addr < 0)
        error("unknown immediate: %s", b->value);
      imm = (uint32_t)addr;
    }

    eynas_emit_u8(code, code_len, code_cap, (uint8_t)(0xB8 + reg));
    eynas_emit_u32(code, code_len, code_cap, imm);
    return;
  }

  // mov reg, label (treat label as imm32 address)
  if (!strcmp(info->mnemonic, "mov") && a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_LABEL) {
    int reg = eynas_get_reg_encoding(a->value);
    int addr = eynas_symtab_lookup(symtab, b->value, EYNAS_SECTION_TEXT);
    if (addr < 0) addr = eynas_symtab_lookup(symtab, b->value, EYNAS_SECTION_DATA);
    if (addr < 0)
      error("unknown label: %s", b->value);

    eynas_emit_u8(code, code_len, code_cap, (uint8_t)(0xB8 + reg));
    eynas_emit_u32(code, code_len, code_cap, (uint32_t)addr);
    return;
  }

  // push reg
  if (!strcmp(info->mnemonic, "push") && a->type == EYNAS_OPERAND_REGISTER) {
    int reg = eynas_get_reg_encoding(a->value);
    eynas_emit_u8(code, code_len, code_cap, (uint8_t)(0x50 + reg));
    return;
  }

  // push label (treat as push imm32 address)
  if (!strcmp(info->mnemonic, "push") && a->type == EYNAS_OPERAND_LABEL) {
    int addr = eynas_symtab_lookup(symtab, a->value, EYNAS_SECTION_TEXT);
    if (addr < 0) addr = eynas_symtab_lookup(symtab, a->value, EYNAS_SECTION_DATA);
    if (addr < 0)
      error("unknown label: %s", a->value);
    eynas_emit_u8(code, code_len, code_cap, 0x68);
    eynas_emit_u32(code, code_len, code_cap, (uint32_t)addr);
    return;
  }

  // pop reg
  if (!strcmp(info->mnemonic, "pop") && a->type == EYNAS_OPERAND_REGISTER) {
    int reg = eynas_get_reg_encoding(a->value);
    eynas_emit_u8(code, code_len, code_cap, (uint8_t)(0x58 + reg));
    return;
  }

  // inc/dec r32/r16 and r/m (minimal forms used by our injected runtime and chibicc output)
  if ((!strcmp(info->mnemonic, "inc") || !strcmp(info->mnemonic, "dec")) && a->type == EYNAS_OPERAND_REGISTER) {
    int reg = eynas_get_reg_encoding(a->value);
    if (a->size_hint == 16)
      eynas_emit_u8(code, code_len, code_cap, 0x66);
    // inc r32: 0x40+rd, dec r32: 0x48+rd
    eynas_emit_u8(code, code_len, code_cap, (uint8_t)((!strcmp(info->mnemonic, "inc") ? 0x40 : 0x48) + reg));
    return;
  }

  if ((!strcmp(info->mnemonic, "inc") || !strcmp(info->mnemonic, "dec")) && a->type == EYNAS_OPERAND_MEMORY) {
    int has_base, base, has_index, index, scale, disp;
    char label[64];
    eynas_parse_mem(a->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

    int hint = a->size_hint ? a->size_hint : 32;
    uint8_t ext = (uint8_t)(!strcmp(info->mnemonic, "inc") ? 0 : 1);

    if (hint == 16)
      eynas_emit_u8(code, code_len, code_cap, 0x66);

    // inc/dec r/m8: FE /0 or /1
    // inc/dec r/m16|32: FF /0 or /1
    eynas_emit_u8(code, code_len, code_cap, (uint8_t)(hint == 8 ? 0xFE : 0xFF));

    if (label[0]) {
      int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
      if (addr < 0) error("unknown label in mem: %s", label);
      // absolute disp32: mod=00 rm=101
      eynas_emit_modrm(code, code_len, code_cap, 0, ext, 5);
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
      return;
    }

    uint8_t rm = (uint8_t)base;
    uint8_t mod = 0;
    if (disp == 0 && base != 5) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;

    if (has_index || base == 4) {
      eynas_emit_modrm(code, code_len, code_cap, mod, ext, 4);
      uint8_t sib_index = has_index ? (uint8_t)index : 4;
      uint8_t sib_base = (uint8_t)base;
      eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
    } else {
      eynas_emit_modrm(code, code_len, code_cap, mod, ext, rm);
    }

    if (mod == 1)
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
    else if (mod == 2 || (mod == 0 && base == 5))
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);

    return;
  }

  // shl/sal/shr/sar r/m, imm8|1|cl  (Group 2)
  if ((!strcmp(info->mnemonic, "shl") || !strcmp(info->mnemonic, "sal") ||
       !strcmp(info->mnemonic, "shr") || !strcmp(info->mnemonic, "sar")) &&
      (a->type == EYNAS_OPERAND_REGISTER || a->type == EYNAS_OPERAND_MEMORY)) {
    uint8_t ext = 0;
    if (!strcmp(info->mnemonic, "shl") || !strcmp(info->mnemonic, "sal")) ext = 4;
    else if (!strcmp(info->mnemonic, "shr")) ext = 5;
    else if (!strcmp(info->mnemonic, "sar")) ext = 7;

    int hint = 32;
    if (a->type == EYNAS_OPERAND_REGISTER) {
      if (eynas_is_reg8(a->value))
        hint = 8;
      else
        hint = a->size_hint ? a->size_hint : 32;
    } else {
      hint = a->size_hint ? a->size_hint : 32;
    }

    if (hint == 16)
      eynas_emit_u8(code, code_len, code_cap, 0x66);

    // Determine count selector: 1 (implicit), imm8, or CL.
    int use_cl = 0;
    int use_imm8 = 0;
    uint8_t imm8 = 0;
    int count_is_one = 1;

    if (b->type == EYNAS_OPERAND_REGISTER) {
      if (strcmp(b->value, "cl") != 0)
        error("%s:%d: shift count register must be cl", path, inst->line_num);
      use_cl = 1;
      count_is_one = 0;
    } else if (b->type == EYNAS_OPERAND_IMMEDIATE) {
      uint32_t imm = 0;
      if (eynas_parse_imm32(b->value, &imm) != 0)
        error("%s:%d: invalid shift immediate: %s", path, inst->line_num, b->value);
      imm8 = (uint8_t)imm;
      count_is_one = (imm8 == 1);
      if (!count_is_one) {
        use_imm8 = 1;
      }
    } else if (b->type == EYNAS_OPERAND_NONE) {
      // Treat missing count as 1.
      count_is_one = 1;
    } else {
      error("%s:%d: invalid shift count operand", path, inst->line_num);
    }

    uint8_t opcode = 0;
    if (hint == 8) {
      if (use_cl) opcode = 0xD2;
      else if (use_imm8) opcode = 0xC0;
      else opcode = 0xD0;
    } else {
      if (use_cl) opcode = 0xD3;
      else if (use_imm8) opcode = 0xC1;
      else opcode = 0xD1;
    }
    eynas_emit_u8(code, code_len, code_cap, opcode);

    if (a->type == EYNAS_OPERAND_REGISTER) {
      uint8_t rm = eynas_is_reg8(a->value) ? (uint8_t)eynas_get_reg8_encoding(a->value)
                                           : (uint8_t)eynas_get_reg_encoding(a->value);
      eynas_emit_modrm(code, code_len, code_cap, 3, ext, rm);
    } else {
      int has_base, base, has_index, index, scale, disp;
      char label[64];
      eynas_parse_mem(a->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

      if (label[0]) {
        int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
        if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
        if (addr < 0) error("unknown label in mem: %s", label);
        // absolute disp32: mod=00 rm=101
        eynas_emit_modrm(code, code_len, code_cap, 0, ext, 5);
        eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
      } else {
        uint8_t rm = (uint8_t)base;
        uint8_t mod = 0;
        if (disp == 0 && base != 5) mod = 0;
        else if (disp >= -128 && disp <= 127) mod = 1;
        else mod = 2;

        if (has_index || base == 4) {
          eynas_emit_modrm(code, code_len, code_cap, mod, ext, 4);
          uint8_t sib_index = has_index ? (uint8_t)index : 4;
          uint8_t sib_base = (uint8_t)base;
          eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
        } else {
          eynas_emit_modrm(code, code_len, code_cap, mod, ext, rm);
        }

        if (mod == 1)
          eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
        else if (mod == 2 || (mod == 0 && base == 5))
          eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);
      }
    }

    if (use_imm8)
      eynas_emit_u8(code, code_len, code_cap, imm8);
    (void)count_is_one;
    return;
  }

  // push imm32
  if (!strcmp(info->mnemonic, "push") && a->type == EYNAS_OPERAND_IMMEDIATE) {
    uint32_t imm = 0;
    if (eynas_parse_imm32(a->value, &imm) != 0)
      error("push: invalid immediate: %s", a->value);
    eynas_emit_u8(code, code_len, code_cap, 0x68);
    eynas_emit_u32(code, code_len, code_cap, imm);
    return;
  }

  // push r/m32 (memory)
  if (!strcmp(info->mnemonic, "push") && a->type == EYNAS_OPERAND_MEMORY) {
    int has_base, base, has_index, index, scale, disp;
    char label[64];
    eynas_parse_mem(a->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

    eynas_emit_u8(code, code_len, code_cap, 0xFF);

    if (label[0]) {
      int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
      if (addr < 0) error("unknown label in mem: %s", label);
      // /6, absolute disp32: mod=00 rm=101
      eynas_emit_modrm(code, code_len, code_cap, 0, 6, 5);
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
      return;
    }

    uint8_t rm = (uint8_t)base;
    uint8_t mod = 0;
    if (disp == 0 && base != 5) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;

    if (has_index || base == 4) {
      eynas_emit_modrm(code, code_len, code_cap, mod, 6, 4);
      uint8_t sib_index = has_index ? (uint8_t)index : 4;
      uint8_t sib_base = (uint8_t)base;
      eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
    } else {
      eynas_emit_modrm(code, code_len, code_cap, mod, 6, rm);
    }

    if (mod == 1)
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
    else if (mod == 2 || (mod == 0 && base == 5))
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);

    return;
  }

  // mov reg, reg
  if (!strcmp(info->mnemonic, "mov") && a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_REGISTER) {
    int dst = eynas_get_reg_encoding(a->value);
    int src = eynas_get_reg_encoding(b->value);
    eynas_emit_u8(code, code_len, code_cap, 0x89);
    eynas_emit_modrm(code, code_len, code_cap, 3, src, dst);
    return;
  }

  // mov reg, [mem]
  if (!strcmp(info->mnemonic, "mov") && a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_MEMORY) {
    int dst = eynas_get_reg_encoding(a->value);
    int has_base, base, has_index, index, scale, disp;
    char label[64];
    eynas_parse_mem(b->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

    eynas_emit_u8(code, code_len, code_cap, 0x8B);

    if (label[0]) {
      int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
      if (addr < 0) error("unknown label in mem: %s", label);
      // absolute disp32: mod=00 rm=101
      eynas_emit_modrm(code, code_len, code_cap, 0, dst, 5);
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
      return;
    }

    // With base/index
    uint8_t rm = (uint8_t)base;
    uint8_t mod = 0;
    if (disp == 0 && base != 5) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;

    if (has_index || base == 4) {
      // SIB needed
      eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)dst, 4);
      uint8_t sib_index = has_index ? (uint8_t)index : 4;
      uint8_t sib_base = (uint8_t)base;
      eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
    } else {
      eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)dst, rm);
    }

    if (mod == 1)
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
    else if (mod == 2 || (mod == 0 && base == 5))
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);

    return;
  }

  // mov [mem], reg
  if (!strcmp(info->mnemonic, "mov") && a->type == EYNAS_OPERAND_MEMORY && b->type == EYNAS_OPERAND_REGISTER) {
    int src = eynas_get_reg_encoding(b->value);
    int has_base, base, has_index, index, scale, disp;
    char label[64];
    eynas_parse_mem(a->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

    eynas_emit_u8(code, code_len, code_cap, 0x89);

    if (label[0]) {
      int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
      if (addr < 0) error("unknown label in mem: %s", label);
      eynas_emit_modrm(code, code_len, code_cap, 0, (uint8_t)src, 5);
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
      return;
    }

    uint8_t rm = (uint8_t)base;
    uint8_t mod = 0;
    if (disp == 0 && base != 5) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;

    if (has_index || base == 4) {
      eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)src, 4);
      uint8_t sib_index = has_index ? (uint8_t)index : 4;
      uint8_t sib_base = (uint8_t)base;
      eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
    } else {
      eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)src, rm);
    }

    if (mod == 1)
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
    else if (mod == 2 || (mod == 0 && base == 5))
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);

    return;
  }

  // mov [mem], imm (r/m8|16|32)
  if (!strcmp(info->mnemonic, "mov") && a->type == EYNAS_OPERAND_MEMORY && b->type == EYNAS_OPERAND_IMMEDIATE) {
    int has_base, base, has_index, index, scale, disp;
    char label[64];
    eynas_parse_mem(a->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

    // Decide width from size hint; default to dword.
    int hint = a->size_hint ? a->size_hint : 32;

    uint32_t imm = 0;
    if (eynas_parse_imm32(b->value, &imm) != 0) {
      int addr = eynas_symtab_lookup(symtab, b->value, EYNAS_SECTION_TEXT);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, b->value, EYNAS_SECTION_DATA);
      if (addr < 0)
        error("unknown immediate: %s", b->value);
      imm = (uint32_t)addr;
    }

    if (hint == 16)
      eynas_emit_u8(code, code_len, code_cap, 0x66);

    if (hint == 8) {
      // C6 /0 ib
      eynas_emit_u8(code, code_len, code_cap, 0xC6);
    } else {
      // C7 /0 iw/id
      eynas_emit_u8(code, code_len, code_cap, 0xC7);
    }

    if (label[0]) {
      int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
      if (addr < 0) error("unknown label in mem: %s", label);
      eynas_emit_modrm(code, code_len, code_cap, 0, 0, 5);
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
    } else {
      uint8_t rm = (uint8_t)base;
      uint8_t mod = 0;
      if (disp == 0 && base != 5) mod = 0;
      else if (disp >= -128 && disp <= 127) mod = 1;
      else mod = 2;

      if (has_index || base == 4) {
        eynas_emit_modrm(code, code_len, code_cap, mod, 0, 4);
        uint8_t sib_index = has_index ? (uint8_t)index : 4;
        uint8_t sib_base = (uint8_t)base;
        eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
      } else {
        eynas_emit_modrm(code, code_len, code_cap, mod, 0, rm);
      }

      if (mod == 1)
        eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
      else if (mod == 2 || (mod == 0 && base == 5))
        eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);
    }

    if (hint == 8) {
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)imm);
    } else if (hint == 16) {
      eynas_emit_u16(code, code_len, code_cap, (uint16_t)imm);
    } else {
      eynas_emit_u32(code, code_len, code_cap, imm);
    }
    return;
  }

  // add/sub/xor/and/or/cmp reg, imm8/imm32 or reg, reg
  if ((!strcmp(info->mnemonic, "add") || !strcmp(info->mnemonic, "sub") || !strcmp(info->mnemonic, "xor") ||
       !strcmp(info->mnemonic, "and") || !strcmp(info->mnemonic, "or") || !strcmp(info->mnemonic, "cmp")) &&
      a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_IMMEDIATE) {
    int dst = eynas_get_reg_encoding(a->value);
    uint32_t imm = 0;
    if (eynas_parse_imm32(b->value, &imm) != 0)
      error("invalid immediate");

    uint8_t ext = 0;
    if (!strcmp(info->mnemonic, "add")) ext = 0;
    else if (!strcmp(info->mnemonic, "or")) ext = 1;
    else if (!strcmp(info->mnemonic, "and")) ext = 4;
    else if (!strcmp(info->mnemonic, "sub")) ext = 5;
    else if (!strcmp(info->mnemonic, "xor")) ext = 6;
    else if (!strcmp(info->mnemonic, "cmp")) ext = 7;

    if ((int32_t)imm >= -128 && (int32_t)imm <= 127) {
      eynas_emit_u8(code, code_len, code_cap, 0x83);
      eynas_emit_modrm(code, code_len, code_cap, 3, ext, (uint8_t)dst);
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)imm);
    } else {
      eynas_emit_u8(code, code_len, code_cap, 0x81);
      eynas_emit_modrm(code, code_len, code_cap, 3, ext, (uint8_t)dst);
      eynas_emit_u32(code, code_len, code_cap, imm);
    }
    return;
  }

  if ((!strcmp(info->mnemonic, "add") || !strcmp(info->mnemonic, "sub") || !strcmp(info->mnemonic, "xor") ||
       !strcmp(info->mnemonic, "and") || !strcmp(info->mnemonic, "or") || !strcmp(info->mnemonic, "cmp") ||
       !strcmp(info->mnemonic, "imul")) &&
      a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_REGISTER) {
    int dst = eynas_get_reg_encoding(a->value);
    int src = eynas_get_reg_encoding(b->value);

    uint8_t opcode = 0;
    if (!strcmp(info->mnemonic, "add")) opcode = 0x01;
    else if (!strcmp(info->mnemonic, "sub")) opcode = 0x29;
    else if (!strcmp(info->mnemonic, "xor")) opcode = 0x31;
    else if (!strcmp(info->mnemonic, "and")) opcode = 0x21;
    else if (!strcmp(info->mnemonic, "or")) opcode = 0x09;
    else if (!strcmp(info->mnemonic, "cmp")) opcode = 0x39;
    else if (!strcmp(info->mnemonic, "imul")) {
      // imul r32,r/m32: 0F AF /r
      eynas_emit_u8(code, code_len, code_cap, 0x0F);
      eynas_emit_u8(code, code_len, code_cap, 0xAF);
      eynas_emit_modrm(code, code_len, code_cap, 3, (uint8_t)dst, (uint8_t)src);
      return;
    }

    eynas_emit_u8(code, code_len, code_cap, opcode);
    eynas_emit_modrm(code, code_len, code_cap, 3, (uint8_t)src, (uint8_t)dst);
    return;
  }

  // movzx/movsx reg32, r/m8|r/m16
  if ((!strcmp(info->mnemonic, "movzx") || !strcmp(info->mnemonic, "movsx")) &&
      a->type == EYNAS_OPERAND_REGISTER) {
    int dst = eynas_get_reg_encoding(a->value);

    int is_zx = !strcmp(info->mnemonic, "movzx");

    // Operand b is either register8 or memory with size hint.
    if (b->type == EYNAS_OPERAND_REGISTER && eynas_is_reg8(b->value)) {
      int src8 = eynas_get_reg8_encoding(b->value);
      eynas_emit_u8(code, code_len, code_cap, 0x0F);
      eynas_emit_u8(code, code_len, code_cap, is_zx ? 0xB6 : 0xBE);
      eynas_emit_modrm(code, code_len, code_cap, 3, (uint8_t)dst, (uint8_t)src8);
      return;
    }

    if (b->type == EYNAS_OPERAND_MEMORY) {
      int has_base, base, has_index, index, scale, disp;
      char label[64];
      eynas_parse_mem(b->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

      int hint = b->size_hint;
      uint8_t op2 = 0;
      if (hint == 16)
        op2 = is_zx ? 0xB7 : 0xBF;
      else
        op2 = is_zx ? 0xB6 : 0xBE;

      eynas_emit_u8(code, code_len, code_cap, 0x0F);
      eynas_emit_u8(code, code_len, code_cap, op2);

      if (label[0]) {
        int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
        if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
        if (addr < 0) error("unknown label in mem: %s", label);
        eynas_emit_modrm(code, code_len, code_cap, 0, (uint8_t)dst, 5);
        eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
        return;
      }

      uint8_t rm = (uint8_t)base;
      uint8_t mod = 0;
      if (disp == 0 && base != 5) mod = 0;
      else if (disp >= -128 && disp <= 127) mod = 1;
      else mod = 2;

      if (has_index || base == 4) {
        eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)dst, 4);
        uint8_t sib_index = has_index ? (uint8_t)index : 4;
        uint8_t sib_base = (uint8_t)base;
        eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
      } else {
        eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)dst, rm);
      }

      if (mod == 1)
        eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
      else if (mod == 2 || (mod == 0 && base == 5))
        eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);
      return;
    }
  }

  // setcc r/m8
  if (starts_with(info->mnemonic, "set") && a->type == EYNAS_OPERAND_REGISTER && eynas_is_reg8(a->value)) {
    int dst8 = eynas_get_reg8_encoding(a->value);
    uint8_t cc = 0x94; // sete default
    if (!strcmp(info->mnemonic, "sete")) cc = 0x94;
    else if (!strcmp(info->mnemonic, "setne")) cc = 0x95;

    eynas_emit_u8(code, code_len, code_cap, 0x0F);
    eynas_emit_u8(code, code_len, code_cap, cc);
    eynas_emit_modrm(code, code_len, code_cap, 3, 0, (uint8_t)dst8);
    return;
  }

  // movsb/movsd
  if (!strcmp(info->mnemonic, "movsb")) { eynas_emit_u8(code, code_len, code_cap, 0xA4); return; }
  if (!strcmp(info->mnemonic, "movsd")) { eynas_emit_u8(code, code_len, code_cap, 0xA5); return; }

  // lea reg, [mem]
  if (!strcmp(info->mnemonic, "lea") && a->type == EYNAS_OPERAND_REGISTER && b->type == EYNAS_OPERAND_MEMORY) {
    int dst = eynas_get_reg_encoding(a->value);
    int has_base, base, has_index, index, scale, disp;
    char label[64];
    eynas_parse_mem(b->value, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

    eynas_emit_u8(code, code_len, code_cap, 0x8D);

    if (label[0]) {
      int addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, label, EYNAS_SECTION_TEXT);
      if (addr < 0) error("unknown label in mem: %s", label);
      // absolute disp32: mod=00 rm=101
      eynas_emit_modrm(code, code_len, code_cap, 0, (uint8_t)dst, 5);
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)(addr + disp));
      return;
    }

    uint8_t rm = (uint8_t)base;
    uint8_t mod = 0;
    if (disp == 0 && base != 5) mod = 0;
    else if (disp >= -128 && disp <= 127) mod = 1;
    else mod = 2;

    if (has_index || base == 4) {
      // SIB needed
      eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)dst, 4);
      uint8_t sib_index = has_index ? (uint8_t)index : 4;
      uint8_t sib_base = (uint8_t)base;
      eynas_emit_sib(code, code_len, code_cap, (uint8_t)scale, sib_index, sib_base);
    } else {
      eynas_emit_modrm(code, code_len, code_cap, mod, (uint8_t)dst, rm);
    }

    if (mod == 1)
      eynas_emit_u8(code, code_len, code_cap, (uint8_t)disp);
    else if (mod == 2 || (mod == 0 && base == 5))
      eynas_emit_u32(code, code_len, code_cap, (uint32_t)disp);

    return;
  }

  // cld
  if (!strcmp(info->mnemonic, "cld")) { eynas_emit_u8(code, code_len, code_cap, 0xFC); return; }

  // Fallback
  error("%s:%d: unsupported instruction form: %s (%s:%s hint=%d, %s:%s hint=%d)",
        path,
        inst->line_num,
        inst->mnemonic,
        type_name(inst->operands[0].type), inst->operands[0].value, inst->operands[0].size_hint,
        type_name(inst->operands[1].type), inst->operands[1].value, inst->operands[1].size_hint);
}

static int eynas_est_modrm_sib_disp_bytes(const char *mem) {
  // Estimate the bytes following the opcode for a ModRM-based memory operand:
  // ModRM [+ optional SIB] [+ optional disp8/disp32].
  int has_base = 0, base = 0, has_index = 0, index = 0, scale = 0, disp = 0;
  char label[64];
  label[0] = 0;

  eynas_parse_mem(mem, &has_base, &base, &has_index, &index, &scale, &disp, label, sizeof(label));

  int bytes = 1; // ModRM

  // Any symbolic label in [] is encoded as absolute disp32 (mod=00 rm=101).
  if (label[0]) {
    bytes += 4;
    return bytes;
  }

  // No base: either [disp32] or [index*scale+disp32] (requires SIB).
  if (!has_base) {
    if (has_index) bytes += 1; // SIB
    bytes += 4;                 // disp32
    return bytes;
  }

  // SIB is required when an index is present or base is ESP.
  if (has_index || base == 4)
    bytes += 1;

  // Displacement rules match the encoder's choices.
  if (base == 5 && disp == 0) {
    // [ebp] cannot be encoded as mod=00 rm=101; encoder uses disp32.
    bytes += 4;
    return bytes;
  }

  if (disp == 0) {
    // no disp
  } else if (disp >= -128 && disp <= 127) {
    bytes += 1;
  } else {
    bytes += 4;
  }

  return bytes;
}

static int eynas_est_inst_size(const eynas_instruction_t *inst) {
  // Sizes used for label layout. Keep these consistent with the encoder.
  if (!strcmp(inst->mnemonic, "ret") || !strcmp(inst->mnemonic, "leave") ||
      !strcmp(inst->mnemonic, "cld") || !strcmp(inst->mnemonic, "movsb") || !strcmp(inst->mnemonic, "movsd") ||
      !strcmp(inst->mnemonic, "stosb") || !strcmp(inst->mnemonic, "stosd"))
    return 1;
  if (!strcmp(inst->mnemonic, "rep") || !strcmp(inst->mnemonic, "repne"))
    return 1;

  // setcc r/m8 (we currently emit reg8 forms only)
  if (starts_with(inst->mnemonic, "set") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && eynas_is_reg8(inst->operands[0].value))
    return 3; // 0F 9x /r

  if ((!strcmp(inst->mnemonic, "inc") || !strcmp(inst->mnemonic, "dec")) && inst->operands[0].type == EYNAS_OPERAND_REGISTER) {
    return inst->operands[0].size_hint == 16 ? 2 : 1;
  }

  if ((!strcmp(inst->mnemonic, "inc") || !strcmp(inst->mnemonic, "dec")) && inst->operands[0].type == EYNAS_OPERAND_MEMORY) {
    int hint = inst->operands[0].size_hint ? inst->operands[0].size_hint : 32;
    int prefix = (hint == 16) ? 1 : 0;
    // FE/FF + ModRM/SIB/disp
    return prefix + 1 + eynas_est_modrm_sib_disp_bytes(inst->operands[0].value);
  }

  // shl/sal/shr/sar r/m, imm8|1|cl (Group 2)
  if ((!strcmp(inst->mnemonic, "shl") || !strcmp(inst->mnemonic, "sal") ||
       !strcmp(inst->mnemonic, "shr") || !strcmp(inst->mnemonic, "sar")) &&
      (inst->operands[0].type == EYNAS_OPERAND_REGISTER || inst->operands[0].type == EYNAS_OPERAND_MEMORY)) {
    int hint = 32;
    if (inst->operands[0].type == EYNAS_OPERAND_REGISTER) {
      if (eynas_is_reg8(inst->operands[0].value))
        hint = 8;
      else
        hint = inst->operands[0].size_hint ? inst->operands[0].size_hint : 32;
    } else {
      hint = inst->operands[0].size_hint ? inst->operands[0].size_hint : 32;
    }
    int prefix = (hint == 16) ? 1 : 0;
    int rm_bytes = 0;
    if (inst->operands[0].type == EYNAS_OPERAND_REGISTER)
      rm_bytes = 1; // ModRM only
    else
      rm_bytes = eynas_est_modrm_sib_disp_bytes(inst->operands[0].value);

    int imm_bytes = 0;
    if (inst->operands[1].type == EYNAS_OPERAND_IMMEDIATE) {
      uint32_t imm = 0;
      if (eynas_parse_imm32(inst->operands[1].value, &imm) == 0) {
        if (((uint8_t)imm) != 1)
          imm_bytes = 1;
      } else {
        // Conservative: if it's not a plain immediate, assume imm8 is present.
        imm_bytes = 1;
      }
    }

    return prefix + 1 + rm_bytes + imm_bytes;
  }

  if (!strcmp(inst->mnemonic, "int"))
    return 2;

  if (!strcmp(inst->mnemonic, "call") || !strcmp(inst->mnemonic, "jmp")) {
    // assume rel32
    return 5;
  }

  // jcc near
  if (eynas_is_jcc_mnemonic(inst->mnemonic))
    return 6;

  if (!strcmp(inst->mnemonic, "push") && inst->operands[0].type == EYNAS_OPERAND_IMMEDIATE)
    return 5;

  if (!strcmp(inst->mnemonic, "push") && inst->operands[0].type == EYNAS_OPERAND_LABEL)
    return 5; // 68 imm32

  if (!strcmp(inst->mnemonic, "push") && inst->operands[0].type == EYNAS_OPERAND_REGISTER)
    return 1;

  if (!strcmp(inst->mnemonic, "push") && inst->operands[0].type == EYNAS_OPERAND_MEMORY)
    return 1 + eynas_est_modrm_sib_disp_bytes(inst->operands[0].value);

  if (!strcmp(inst->mnemonic, "pop") && inst->operands[0].type == EYNAS_OPERAND_REGISTER)
    return 1;

  if (!strcmp(inst->mnemonic, "mov") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_IMMEDIATE) {
    // B0+rb ib or B8+rd id
    if (eynas_is_reg8(inst->operands[0].value))
      return 2;
    return 5;
  }

  if (!strcmp(inst->mnemonic, "mov") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_LABEL) {
    // B8+rd id (label treated as imm32 address)
    return 5;
  }

  if (!strcmp(inst->mnemonic, "mov") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_REGISTER) {
    // 89/8B /r
    return 2;
  }

  if (!strcmp(inst->mnemonic, "mov") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_MEMORY) {
    // 8B /r + ModRM/SIB/disp
    return 1 + eynas_est_modrm_sib_disp_bytes(inst->operands[1].value);
  }

  if (!strcmp(inst->mnemonic, "mov") && inst->operands[0].type == EYNAS_OPERAND_MEMORY && inst->operands[1].type == EYNAS_OPERAND_REGISTER) {
    // 89 /r + ModRM/SIB/disp
    return 1 + eynas_est_modrm_sib_disp_bytes(inst->operands[0].value);
  }

  if (!strcmp(inst->mnemonic, "mov") && inst->operands[0].type == EYNAS_OPERAND_MEMORY && inst->operands[1].type == EYNAS_OPERAND_IMMEDIATE) {
    // C6/C7 /0 + ModRM/SIB/disp + imm
    int imm_bytes = 4;
    if (inst->operands[0].size_hint == 8)
      imm_bytes = 1;
    else if (inst->operands[0].size_hint == 16)
      imm_bytes = 2;
    return 1 + eynas_est_modrm_sib_disp_bytes(inst->operands[0].value) + imm_bytes;
  }

  if (!strcmp(inst->mnemonic, "lea") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_MEMORY) {
    // 8D /r + ModRM/SIB/disp
    return 1 + eynas_est_modrm_sib_disp_bytes(inst->operands[1].value);
  }

  if (!strcmp(inst->mnemonic, "movzx") || !strcmp(inst->mnemonic, "movsx")) {
    // 0F B6/B7/BE/BF /r
    if (inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_REGISTER)
      return 2 + 1;
    if (inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_MEMORY)
      return 2 + eynas_est_modrm_sib_disp_bytes(inst->operands[1].value);
  }

  // add/sub/xor/and/or/cmp reg, imm8/imm32 or reg, reg
  if ((!strcmp(inst->mnemonic, "add") || !strcmp(inst->mnemonic, "sub") || !strcmp(inst->mnemonic, "xor") ||
       !strcmp(inst->mnemonic, "and") || !strcmp(inst->mnemonic, "or") || !strcmp(inst->mnemonic, "cmp")) &&
      inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_IMMEDIATE) {
    uint32_t imm = 0;
    if (eynas_parse_imm32(inst->operands[1].value, &imm) == 0) {
      if ((int32_t)imm >= -128 && (int32_t)imm <= 127)
        return 3; // 83 /r ib
      return 6;   // 81 /r id
    }
    return 6;
  }

  if ((!strcmp(inst->mnemonic, "add") || !strcmp(inst->mnemonic, "sub") || !strcmp(inst->mnemonic, "xor") ||
       !strcmp(inst->mnemonic, "and") || !strcmp(inst->mnemonic, "or") || !strcmp(inst->mnemonic, "cmp")) &&
      inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_REGISTER) {
    return 2;
  }

  if (!strcmp(inst->mnemonic, "imul") && inst->operands[0].type == EYNAS_OPERAND_REGISTER && inst->operands[1].type == EYNAS_OPERAND_REGISTER) {
    // 0F AF /r
    return 3;
  }

  // typical reg/reg op
  return 6;
}

static int eynas_count_db_bytes(const char *s) {
  // Very small version: count comma-separated values; strings contribute their length.
  int count = 0;
  const char *p = s;
  while (*p) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    if (*p == '"') {
      p++;
      while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p += 2;
        else p++;
        count++;
      }
      if (*p == '"') p++;
    } else {
      // number or label treated as 1 byte for db
      count++;
      while (*p && *p != ',') p++;
    }
    if (*p == ',') p++;
  }
  return count;
}

static int eynas_count_comma_separated_items(const char *s) {
  if (!s) return 0;
  int count = 0;
  const char *p = s;
  for (;;) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    count++;
    // consume token (best-effort: handle quoted strings)
    if (*p == '"') {
      p++;
      while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p += 2;
        else p++;
      }
      if (*p == '"') p++;
    } else {
      while (*p && *p != ',') p++;
    }

    while (*p == ' ' || *p == '\t') p++;
    if (*p == ',') {
      p++;
      continue;
    }
  }
  return count;
}

static void eynas_write_db(uint8_t **data, size_t *len, size_t *cap, eynas_symtab_t *symtab, const char *value) {
  const char *p = value;
  while (*p) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    if (*p == '"') {
      p++;
      while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
          char e = *p++;
          if (e == 'n') c = '\n';
          else if (e == 't') c = '\t';
          else if (e == 'r') c = '\r';
          else c = e;
        }
        eynas_emit_u8(data, len, cap, (uint8_t)c);
      }
      if (*p == '"') p++;
    } else {
      // token until comma
      char tok[64];
      size_t n = 0;
      while (*p && *p != ',' && n < sizeof(tok) - 1)
        tok[n++] = *p++;
      tok[n] = 0;
      // trim right
      while (n && (tok[n - 1] == ' ' || tok[n - 1] == '\t')) tok[--n] = 0;

      uint32_t imm = 0;
      if (eynas_parse_imm32(tok, &imm) == 0) {
        eynas_emit_u8(data, len, cap, (uint8_t)imm);
      } else {
        int addr = eynas_symtab_lookup(symtab, tok, EYNAS_SECTION_DATA);
        if (addr < 0) addr = eynas_symtab_lookup(symtab, tok, EYNAS_SECTION_TEXT);
        if (addr < 0)
          error("unknown symbol in db: %s", tok);
        eynas_emit_u8(data, len, cap, (uint8_t)addr);
      }
    }

    while (*p == ' ' || *p == '\t') p++;
    if (*p == ',') p++;
  }
}

static void eynas_write_dd(uint8_t **data, size_t *len, size_t *cap, eynas_symtab_t *symtab, const char *value) {
  const char *p = value;
  while (*p) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    char tok[128];
    size_t n = 0;
    while (*p && *p != ',' && n < sizeof(tok) - 1)
      tok[n++] = *p++;
    tok[n] = 0;
    while (n && (tok[n - 1] == ' ' || tok[n - 1] == '\t')) tok[--n] = 0;

    uint32_t imm = 0;
    if (eynas_parse_imm32(tok, &imm) == 0) {
      eynas_emit_u32(data, len, cap, imm);
    } else {
      int addr = eynas_symtab_lookup(symtab, tok, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, tok, EYNAS_SECTION_TEXT);
      if (addr < 0)
        error("unknown symbol in dd: %s", tok);
      eynas_emit_u32(data, len, cap, (uint32_t)addr);
    }

    while (*p == ' ' || *p == '\t') p++;
    if (*p == ',') p++;
  }
}

static void eynas_write_dw(uint8_t **data, size_t *len, size_t *cap, eynas_symtab_t *symtab, const char *value) {
  const char *p = value;
  while (*p) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    char tok[128];
    size_t n = 0;
    while (*p && *p != ',' && n < sizeof(tok) - 1)
      tok[n++] = *p++;
    tok[n] = 0;
    while (n && (tok[n - 1] == ' ' || tok[n - 1] == '\t')) tok[--n] = 0;

    uint32_t imm = 0;
    if (eynas_parse_imm32(tok, &imm) == 0) {
      eynas_emit_u16(data, len, cap, (uint16_t)imm);
    } else {
      int addr = eynas_symtab_lookup(symtab, tok, EYNAS_SECTION_DATA);
      if (addr < 0) addr = eynas_symtab_lookup(symtab, tok, EYNAS_SECTION_TEXT);
      if (addr < 0)
        error("unknown symbol in dw: %s", tok);
      eynas_emit_u16(data, len, cap, (uint16_t)addr);
    }

    while (*p == ' ' || *p == '\t') p++;
    if (*p == ',') p++;
  }
}

static void eynas_generate(eynas_ast_t *ast, eynas_symtab_t *symtab,
                          uint8_t **out_code, size_t *out_code_size,
                          uint8_t **out_data, size_t *out_data_size,
                          const char *input_path) {
  uint8_t *code = NULL;
  size_t code_len = 0, code_cap = 0;

  uint8_t *data = NULL;
  size_t data_len = 0, data_cap = 0;

  // Emit code
  const int code_base = 0x00400000;
  int cur_off = 0;
  for (eynas_instruction_t *inst = ast->instructions; inst; inst = inst->next) {
    if (inst->section != EYNAS_SECTION_TEXT)
      continue;
    const eynas_instinfo_t *info = eynas_find_inst(inst->mnemonic);
    if (!info)
      error("unknown instruction: %s", inst->mnemonic);
    size_t before = code_len;
    eynas_encode_inst(info, inst, symtab, &code, &code_len, &code_cap, code_base + cur_off, input_path);
    cur_off += (int)(code_len - before);
  }

  // Emit data
  for (eynas_datadef_t *d = ast->data_defs; d; d = d->next) {
    if (d->section != EYNAS_SECTION_DATA)
      continue;
    if (!strcmp(d->directive, "db")) {
      eynas_write_db(&data, &data_len, &data_cap, symtab, d->value);
    } else if (!strcmp(d->directive, "dw")) {
      eynas_write_dw(&data, &data_len, &data_cap, symtab, d->value);
    } else if (!strcmp(d->directive, "dd")) {
      eynas_write_dd(&data, &data_len, &data_cap, symtab, d->value);
    } else if (!strcmp(d->directive, "resb")) {
      int n = eynas_parse_int(d->value);
      for (int i = 0; i < n; i++) eynas_emit_u8(&data, &data_len, &data_cap, 0);
    } else if (!strcmp(d->directive, "align")) {
      int a = eynas_parse_int(d->value);
      if (a <= 0) a = 1;
      while ((int)data_len % a)
        eynas_emit_u8(&data, &data_len, &data_cap, 0);
    } else {
      error("unsupported data directive: %s", d->directive);
    }
  }

  *out_code = code;
  *out_code_size = code_len;
  *out_data = data;
  *out_data_size = data_len;
}

static eynas_ast_t *eynas_parse(const char *src, const char *input_path) {
  (void)input_path;
  eynas_ast_t *ast = calloc(1, sizeof(*ast));
  if (!ast) error("out of memory");

  eynas_lexer_t lx;
  eynas_lexer_init(&lx, src);

  eynas_section_t cur_sec = EYNAS_SECTION_TEXT;
  int line = 1;

  // Track PCs so labels get correct offsets within their section.
  int text_pc = 0;
  int data_pc = 0;

  // First pass: parse into AST nodes.
  for (;;) {
    eynas_token_t t = eynas_next_token(&lx);
    if (t.type == EYNAS_TOK_EOF) break;
    if (t.type == EYNAS_TOK_NEWLINE) { line++; continue; }

    if (t.type == EYNAS_TOK_SECTION) {
      eynas_token_t name = eynas_next_token(&lx);
      if (name.type != EYNAS_TOK_UNKNOWN)
        error("section expects a name");
      if (!strcmp(name.text, ".text")) cur_sec = EYNAS_SECTION_TEXT;
      else cur_sec = EYNAS_SECTION_DATA;
      continue;
    }

    if (t.type == EYNAS_TOK_LABEL) {
      eynas_label_t *lab = calloc(1, sizeof(*lab));
      if (!lab) error("out of memory");
      strncpy(lab->name, t.text, sizeof(lab->name) - 1);
      lab->section = cur_sec;
      lab->offset = (cur_sec == EYNAS_SECTION_TEXT) ? text_pc : data_pc;
      lab->line_num = line;
      eynas_ast_add_label(ast, lab);
      continue;
    }

    if (t.type == EYNAS_TOK_DIRECTIVE) {
      if (!strcmp(t.text, "global")) {
        // ignore: we will still export symbols if present
        // consume rest of line
        for (;;) {
          eynas_token_t x = eynas_next_token(&lx);
          if (x.type == EYNAS_TOK_EOF || x.type == EYNAS_TOK_NEWLINE) {
            if (x.type == EYNAS_TOK_NEWLINE) line++;
            break;
          }
        }
        continue;
      }

      // data directive in .data
      eynas_datadef_t *d = calloc(1, sizeof(*d));
      if (!d) error("out of memory");
      strncpy(d->directive, t.text, sizeof(d->directive) - 1);
      d->line_num = line;
      d->section = cur_sec;

      // Read the rest of the line as value.
      sbuf_t v; sbuf_init(&v);
      for (;;) {
        eynas_token_t x = eynas_next_token(&lx);
        if (x.type == EYNAS_TOK_EOF || x.type == EYNAS_TOK_NEWLINE) {
          if (x.type == EYNAS_TOK_NEWLINE) line++;
          break;
        }
        if (x.type == EYNAS_TOK_COMMA) {
          sbuf_putc(&v, ',');
          sbuf_putc(&v, ' ');
          continue;
        }
        // preserve token text
        sbuf_puts(&v, x.text);
        sbuf_putc(&v, ' ');
      }
      trim_right(v.data ? v.data : (char*)"");
      strncpy(d->value, v.data ? v.data : "", sizeof(d->value) - 1);
      sbuf_free(&v);
      eynas_ast_add_data(ast, d);

      // Update data PC in-order so subsequent labels land correctly.
      if (cur_sec == EYNAS_SECTION_DATA) {
        if (!strcmp(d->directive, "db")) {
          data_pc += eynas_count_db_bytes(d->value);
        } else if (!strcmp(d->directive, "dw")) {
          int n = eynas_count_comma_separated_items(d->value);
          data_pc += 2 * n;
        } else if (!strcmp(d->directive, "dd")) {
          int n = eynas_count_comma_separated_items(d->value);
          data_pc += 4 * n;
        } else if (!strcmp(d->directive, "resb")) {
          data_pc += eynas_parse_int(d->value);
        } else if (!strcmp(d->directive, "align")) {
          int a = eynas_parse_int(d->value);
          if (a <= 0) a = 1;
          while (data_pc % a) data_pc++;
        }
      }
      continue;
    }

    if (t.type == EYNAS_TOK_MNEMONIC) {
      eynas_instruction_t *inst = calloc(1, sizeof(*inst));
      if (!inst) error("out of memory");
      strncpy(inst->mnemonic, t.text, sizeof(inst->mnemonic) - 1);
      inst->section = cur_sec;
      inst->line_num = line;

      // Prefix mnemonics (rep/repne) do not take operands here.
      // We must not consume the next mnemonic on the same line (e.g. `rep stosb`).
      if (!strcmp(inst->mnemonic, "rep") || !strcmp(inst->mnemonic, "repne")) {
        eynas_ast_add_inst(ast, inst);
        if (cur_sec == EYNAS_SECTION_TEXT)
          text_pc += eynas_est_inst_size(inst);
        continue;
      }

      // parse up to 2 operands
      int opi = 0;
      int pending_size_hint = 0;

      for (;;) {
        eynas_token_t x = eynas_next_token(&lx);
        if (x.type == EYNAS_TOK_EOF || x.type == EYNAS_TOK_NEWLINE) {
          if (x.type == EYNAS_TOK_NEWLINE) line++;
          break;
        }
        if (x.type == EYNAS_TOK_COMMA) continue;

        if (x.type == EYNAS_TOK_SIZE) {
          if (!strcmp(x.text, "byte")) pending_size_hint = 8;
          else if (!strcmp(x.text, "word")) pending_size_hint = 16;
          else if (!strcmp(x.text, "dword")) pending_size_hint = 32;
          continue;
        }

        if (opi >= 2) continue;

        eynas_operand_t *op = &inst->operands[opi++];
        memset(op, 0, sizeof(*op));
        op->size_hint = pending_size_hint;
        pending_size_hint = 0;

        if (x.type == EYNAS_TOK_REGISTER) {
          op->type = EYNAS_OPERAND_REGISTER;
          strncpy(op->value, x.text, sizeof(op->value) - 1);
          continue;
        }

        if (x.type == EYNAS_TOK_IMMEDIATE) {
          op->type = EYNAS_OPERAND_IMMEDIATE;
          strncpy(op->value, x.text, sizeof(op->value) - 1);
          continue;
        }

        if (x.type == EYNAS_TOK_MEMORY) {
          op->type = EYNAS_OPERAND_MEMORY;
          strncpy(op->value, x.text, sizeof(op->value) - 1);
          continue;
        }

        // unknown treated as label
        op->type = EYNAS_OPERAND_LABEL;
        strncpy(op->value, x.text, sizeof(op->value) - 1);
      }

      eynas_ast_add_inst(ast, inst);

      if (cur_sec == EYNAS_SECTION_TEXT)
        text_pc += eynas_est_inst_size(inst);
      continue;
    }

    // Skip anything else on that line
    for (;;) {
      eynas_token_t x = eynas_next_token(&lx);
      if (x.type == EYNAS_TOK_EOF || x.type == EYNAS_TOK_NEWLINE) {
        if (x.type == EYNAS_TOK_NEWLINE) line++;
        break;
      }
    }
  }

  // Finalize label absolute addresses.
  // Base addresses
  const int code_base = 0x00400000;
  const int data_base = code_base + (int)(((text_pc + 0x0FFF) / 0x1000) * 0x1000);

  for (eynas_label_t *l = ast->labels; l; l = l->next) {
    if (l->section == EYNAS_SECTION_TEXT)
      l->address = code_base + l->offset;
    else
      l->address = data_base + l->offset;
  }

  return ast;
}

static void eynas_free_ast(eynas_ast_t *ast) {
  if (!ast) return;
  eynas_instruction_t *i = ast->instructions;
  while (i) { eynas_instruction_t *n = i->next; free(i); i = n; }
  eynas_label_t *l = ast->labels;
  while (l) { eynas_label_t *n = l->next; free(l); l = n; }
  eynas_datadef_t *d = ast->data_defs;
  while (d) { eynas_datadef_t *n = d->next; free(d); d = n; }
  free(ast);
}

static int source_defines_label(const char *src, const char *name) {
  if (!src || !name || !name[0])
    return 0;

  size_t name_len = strlen(name);
  const char *p = src;
  while (*p) {
    // line start
    const char *ls = p;
    while (*p && *p != '\n')
      p++;
    const char *le = p;

    while (ls < le && (*ls == ' ' || *ls == '\t' || *ls == '\r'))
      ls++;

    // "name:" label
    if ((size_t)(le - ls) >= name_len + 1 && !strncmp(ls, name, name_len) && ls[name_len] == ':')
      return 1;

    if (*p == '\n')
      p++;
  }
  return 0;
}

static int source_references_call(const char *src, const char *name) {
  if (!src || !name || !name[0])
    return 0;

  const char *p = src;
  size_t name_len = strlen(name);
  while ((p = strstr(p, "call")) != NULL) {
    // ensure word boundary before 'call'
    if (p != src && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) { p++; continue; }
    const char *q = p + 4;
    while (*q && (*q == ' ' || *q == '\t')) q++;
    if (!strncmp(q, name, name_len)) {
      char next = q[name_len];
      if (!(isalnum((unsigned char)next) || next == '_' || next == '.'))
        return 1;
    }
    p++;
  }
  return 0;
}

static char *append_minimal_runtime(char *intel) {
  // Minimal implementations sufficient for many chibicc test programs:
  // - _exit: syscall 2
  // - getkey: syscall 6
  // - write: syscall 1
  // - read: syscall 3
  // - open: syscall 4
  // - close: syscall 5
  // - getdents: syscall 7
  // - writefile: syscall 21
  // - strlen: NUL-terminated
  // - puts: write string + "\n" to stdout
  // - printf: treat fmt as plain string (ignores formatting)
  static const char rt[] =
      "\n"
      "section .text\n"
      "_exit:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov eax, 2\n"
      "  int 0x80\n"
  "exit_hang:\n"
  "  jmp exit_hang\n"
      "\n"
      "getkey:\n"
      "  mov eax, 6\n"
      "  int 0x80\n"
      "  ret\n"
      "\n"
      "write:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov ecx, [ebp+12]\n"
      "  mov edx, [ebp+16]\n"
      "  mov eax, 1\n"
      "  int 0x80\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "read:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov ecx, [ebp+12]\n"
      "  mov edx, [ebp+16]\n"
      "  mov eax, 3\n"
      "  int 0x80\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "open:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov ecx, [ebp+12]\n"
      "  mov edx, [ebp+16]\n"
      "  mov eax, 4\n"
      "  int 0x80\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "close:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov eax, 5\n"
      "  int 0x80\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "getdents:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov ecx, [ebp+12]\n"
      "  mov edx, [ebp+16]\n"
      "  mov eax, 7\n"
      "  int 0x80\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "writefile:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  mov ebx, [ebp+8]\n"
      "  mov ecx, [ebp+12]\n"
      "  mov edx, [ebp+16]\n"
      "  mov eax, 21\n"
      "  int 0x80\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "strlen:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push esi\n"
      "  mov esi, [ebp+8]\n"
      "  xor eax, eax\n"
  "sl_loop:\n"
      "  movzx edx, byte [esi]\n"
      "  cmp edx, 0\n"
  "  je sl_done\n"
      "  inc eax\n"
      "  inc esi\n"
  "  jmp sl_loop\n"
  "sl_done:\n"
      "  pop esi\n"
      "  leave\n"
      "  ret\n"
      "\n"
      "printf:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  push ecx\n"
      "  push edx\n"
      "  mov ecx, [ebp+8]\n"
      "  push ecx\n"
      "  call strlen\n"
      "  add esp, 4\n"
      "  mov edx, eax\n"
      "  push edx\n"
      "  push ecx\n"
      "  mov ebx, 1\n"
      "  push ebx\n"
      "  call write\n"
      "  add esp, 12\n"
      "  pop edx\n"
      "  pop ecx\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n";

  // Append `puts` after `printf` so it can reuse `strlen`/`write`.
  // Note: our freestanding environment doesn't provide full libc; this is
  // just enough to satisfy common test programs.
  static const char puts_rt[] =
      "\n"
      "puts:\n"
      "  push ebp\n"
      "  mov ebp, esp\n"
      "  push ebx\n"
      "  push ecx\n"
      "  push edx\n"
      "  mov ecx, [ebp+8]\n"
      "  push ecx\n"
      "  call strlen\n"
      "  add esp, 4\n"
      "  mov edx, eax\n"
      "  push edx\n"
      "  push ecx\n"
      "  mov ebx, 1\n"
      "  push ebx\n"
      "  call write\n"
      "  add esp, 12\n"
      "  sub esp, 4\n"
      "  mov byte [esp], 10\n"
      "  mov ecx, esp\n"
      "  push 1\n"
      "  push ecx\n"
      "  mov ebx, 1\n"
      "  push ebx\n"
      "  call write\n"
      "  add esp, 12\n"
      "  add esp, 4\n"
      "  xor eax, eax\n"
      "  pop edx\n"
      "  pop ecx\n"
      "  pop ebx\n"
      "  leave\n"
      "  ret\n";

  size_t rt_len = strlen(rt);
  size_t puts_len = strlen(puts_rt);
  size_t intel_len = intel ? strlen(intel) : 0;
  char *out = calloc(1, intel_len + rt_len + puts_len + 1);
  if (!out)
    error("out of memory");
  if (intel_len)
    memcpy(out, intel, intel_len);
  memcpy(out + intel_len, rt, rt_len);
  memcpy(out + intel_len + rt_len, puts_rt, puts_len);
  out[intel_len + rt_len + puts_len] = 0;
  free(intel);
  return out;
}

static char *prepend_start_shim(char *intel) {
  static const char shim[] =
      "section .text\n"
      "global _start\n"
      "_start:\n"
      "  mov eax, [esp]\n"
      "  lea edx, [esp+4]\n"
      "  push edx\n"
      "  push eax\n"
      "  call main\n"
      "  mov ebx, eax\n"
      "  mov eax, 2\n"
      "  int 0x80\n"
      ".hang:\n"
      "  jmp .hang\n\n";

  size_t shim_len = strlen(shim);
  size_t intel_len = intel ? strlen(intel) : 0;
  char *out = calloc(1, shim_len + intel_len + 1);
  if (!out)
    error("out of memory");
  memcpy(out, shim, shim_len);
  if (intel_len)
    memcpy(out + shim_len, intel, intel_len);
  out[shim_len + intel_len] = 0;
  free(intel);
  return out;
}

// ------------------------
// Public entrypoint
// ------------------------

int eynos_assemble_uelf_from_file(const char *input_path, const char *output_path) {
  size_t src_len = 0;
  char *src = read_entire_file(input_path, &src_len);
  (void)src_len;

  int has_start = source_defines_label(src, "_start");
  int has_main = source_defines_label(src, "main");

  int needs_printf = source_references_call(src, "printf") && !source_defines_label(src, "printf");
  int needs_puts = source_references_call(src, "puts") && !source_defines_label(src, "puts");
  int needs_getkey = source_references_call(src, "getkey") && !source_defines_label(src, "getkey");
  int needs_exit = source_references_call(src, "_exit") && !source_defines_label(src, "_exit");
  int needs_read = source_references_call(src, "read") && !source_defines_label(src, "read");
  int needs_write = source_references_call(src, "write") && !source_defines_label(src, "write");
  int needs_strlen = source_references_call(src, "strlen") && !source_defines_label(src, "strlen");
  int needs_open = source_references_call(src, "open") && !source_defines_label(src, "open");
  int needs_close = source_references_call(src, "close") && !source_defines_label(src, "close");
  int needs_getdents = source_references_call(src, "getdents") && !source_defines_label(src, "getdents");
  int needs_writefile = source_references_call(src, "writefile") && !source_defines_label(src, "writefile");

  char *intel = translate_gas_to_intel(src);
  free(src);

  if (!has_start && has_main)
    intel = prepend_start_shim(intel);

  // If we're assembling compiler output (.s) directly, it may reference libc/syscall
  // entrypoints without providing their implementations. Inject a minimal runtime so
  // the resulting .uelf can run.
  if (needs_printf || needs_puts || needs_getkey || needs_exit || needs_read || needs_write || needs_strlen ||
      needs_open || needs_close || needs_getdents || needs_writefile)
    intel = append_minimal_runtime(intel);

  eynas_ast_t *ast = eynas_parse(intel, input_path);

  eynas_symtab_t symtab;
  eynas_build_symtab(ast, &symtab);

  // Require _start.
  int entry = eynas_symtab_lookup(&symtab, "_start", EYNAS_SECTION_TEXT);
  if (entry < 0) {
    eynas_symtab_free(&symtab);
    eynas_free_ast(ast);
    sbuf_t tmp = {0};
    (void)tmp;
    free(intel);
    error("--as: missing _start symbol (input must define _start or define main)");
  }

  uint8_t *code = NULL;
  uint8_t *data = NULL;
  size_t code_size = 0;
  size_t data_size = 0;

  eynas_generate(ast, &symtab, &code, &code_size, &data, &data_size, input_path);

  eynos_link_config_t cfg;
  eynos_link_config_init(&cfg);

  cfg.text_vaddr = 0x00400000u;
  // Place rodata/data after text, page aligned.
  cfg.rodata_vaddr = cfg.text_vaddr + (uint32_t)(((code_size + 0x0FFFu) / 0x1000u) * 0x1000u);
  cfg.entry_vaddr = (uint32_t)entry;

  cfg.text.data = code;
  cfg.text.size = (uint32_t)code_size;
  cfg.rodata.data = data;
  cfg.rodata.size = (uint32_t)data_size;

  // Add a minimal symbol set (optional): _start
  (void)eynos_link_add_symbol;
  eynos_link_add_symbol(&cfg, "_start", (uint32_t)entry, 0, STB_GLOBAL, STT_FUNC, 1);

  int rc = eynos_link_write_uelf(&cfg, output_path);

  free(code);
  free(data);
  eynas_symtab_free(&symtab);
  eynas_free_ast(ast);
  free(intel);

  if (rc != 0)
    error("--as: failed to write output: %s", output_path);

  return 0;
}

#endif // CHIBICC_EYNOS_USERLAND
