# EYN-OS Target (i386)

This fork adds an explicit EYN-OS target mode to chibicc backed by a fully
integrated assembler (`eynos_as`) and linker (`eynos_linker`).  No external
toolchain (NASM, ld, etc.) is required.

## Selecting the Target

Supported spellings:

```bash
./chibicc -target eynos ...
./chibicc -target=eynos ...
./chibicc -target eynos-i386 ...
./chibicc -target i386-eynos ...
```

Behavior:
- Sets the target OS to EYN-OS
- Forces `i386` codegen
- Treats the target as **freestanding** (see macros below)

## Sysroot and Includes

To keep the compiler usable outside the EYN-OS monorepo layout, the EYN-OS
target prefers an explicit sysroot.

### `--sysroot`

`--sysroot` should point at a directory containing an `include/` folder.

```bash
./chibicc -target eynos --sysroot /path/to/eynos-userland -c app.c -o app.o
# expects headers in:
#   /path/to/eynos-userland/include
```

### `CHIBICC_SYSROOT`

If `--sysroot` is not provided, chibicc checks:

```bash
export CHIBICC_SYSROOT=/path/to/eynos-userland
```

### Best-effort Convenience Path

If neither `--sysroot` nor `CHIBICC_SYSROOT` is set, chibicc will also try:

```
<dir-of-chibicc-binary>/../userland/include
```

This is only a convenience for the EYN-OS monorepo layout.

## Predefined Macros (Target)

When targeting EYN-OS:
- Defines: `__EYNOS__=1`
- Sets: `__STDC_HOSTED__=0`
- Does **not** define Linux/Unix macros such as `__linux__`, `__gnu_linux__`, `unix`, etc.

Architecture macros follow the existing chibicc behavior:
- `__i386__`, `__ILP32__` for i386

## i386 Code-Generation Notes

### `long double`

On i386, `long double` is treated as `double` for cast purposes (both stored
in x87 `ST(0)`).  The old behaviour was to `error()` on any `long double`
cast; the new behaviour silently re-classifies `TY_LDOUBLE` as `TY_DOUBLE`
inside `cast_i386()`, making programs that use `long double` arithmetic
compile and run correctly.

### `alloca()`

`alloca` is implemented as an **inline** i386 sequence rather than a library
call.  The generated code aligns the requested size to 16 bytes, uses
`rep movsb` to relocate any already-pushed temporaries below `esp`, grows the
stack, and returns the new `alloca_bottom` as the allocated pointer.

## Built-in Assembler (eynos_as)

The assembler translates GAS/AT&T syntax to x86 machine code in two passes:

1. **Translator** (`translate_gas_to_intel`) — converts AT&T mnemonics and
   operand notation to an internal Intel-style representation.
2. **Binary encoder** (`eynas_encode_inst`) — encodes instructions directly
   into an in-memory byte buffer.

### Supported Sections

| GAS directive    | Behaviour                            |
|------------------|--------------------------------------|
| `.text`          | switch to code section               |
| `.data`          | switch to initialized-data section   |
| `.bss`           | switch to zero-initialized section   |
| `.comm name,sz`  | emit `name: resb sz` in `.bss`       |
| `.section .rodata` | treated as `.data`                 |

### Supported Instructions (additions over baseline)

**Integer arithmetic / logic**

| Instruction          | Notes                                     |
|----------------------|-------------------------------------------|
| `div`, `mul`, `neg`  | F7 group (single-register form)           |
| `shl`, `shr`, `sar`, `sal` | Added to the binary-op table        |
| `not` / `neg`        | F7 /2, F7 /3                             |
| `imul reg,reg`       | Two-operand form (0x0F AF)                |

**16-bit register operands**

All `mov`, `add`/`sub`/`and`/`or`/`xor`/`cmp`/`test`, `movzx`/`movsx`, and
address-size computations now accept the 16-bit registers `ax cx dx bx sp bp
si di`.  A 0x66 operand-size prefix is emitted automatically.

**`qword` size hint** — recognised in operands that need explicit widths.

**Indirect call / jmp through register**

`call eax` and `jmp ecx` are encoded as `FF /2` and `FF /4` respectively.

**FPU (x87) instructions**

| Mnemonic               | Encoding                  |
|------------------------|---------------------------|
| `fld` / `fst` / `fstp` | D9 or DD + ModRM (32/64)  |
| `fild` / `fistp`       | DB + ModRM                |
| `faddp` / `fsubp` / `fmulp` / `fdivp` | DE Cx/Ex/Cx/Fx |
| `fchs`                 | D9 E0                     |
| `fucompp`              | DA E9                     |
| `fnstsw ax`            | DF E0                     |
| `fstp st0`             | DD D8                     |
| `fnstcw` / `fldcw`     | D9 /7, D9 /5              |
| `sahf`                 | 9E                        |

The AT&T suffixed mnemonics (`flds`, `fldl`, `fsts`, `fstl`, `fstps`, `fstpl`,
`fildl`, `fistpl`, `fnstcw`, `fldcw`) are translated to their Intel-syntax
equivalents with the correct size hint before encoding.

**`dd` directive — symbol+offset**

The `.dd expr` pseudo-op now accepts `symbol+N` and `symbol-N` forms to embed
a symbol address plus a constant byte offset.

### Runtime Stub Injection

When the assembled source references certain symbols that it does not define,
the assembler prepends the corresponding stub automatically:

| Symbol(s) referenced      | Stub injected                            |
|---------------------------|------------------------------------------|
| `eyn_syscall3` (and variants `_pii`, `_ppi`, `_iip`, `_iii`) | cdecl i386 `int 0x80` wrappers (eax=n, ebx=a1, ecx=a2, edx=a3) |
| `eyn_syscall1`            | single-argument `int 0x80` wrapper       |
| `eyn_syscall0`            | zero-argument `int 0x80` wrapper         |
| `write`, `read`, `exit`, `open`, `close`, `getdents`, `writefile` | minimal runtime stubs |
| `_start` (missing)        | CRT shim that calls `main` and `exit`    |

## Built-in Linker (eynos_linker)

The linker produces a **flat ELF32 ET_EXEC** loadable by the EYN-OS ring3
loader.

### ELF layout

| Segment (PT_LOAD) | Contents                          | Flags    |
|-------------------|-----------------------------------|----------|
| Segment 0         | `.text` (code)                    | R + X    |
| Segment 1         | `.data` + BSS zero-fill           | R + W    |

BSS is represented as `p_memsz > p_filesz` on segment 1: the loader
zero-fills the gap between the end of `.data` bytes and the end of the
virtual mapping.  The `bss_size` field in `eynos_link_config_t` controls
the additional memory beyond `.data`.

## Building `.uelf` — Quick Example

```bash
# from the EYN-OS monorepo
devtools/build_user_c_chibicc.sh testdir/hello_c_uelf.c testdir/hello_c_uelf.uelf

# standalone (chibicc handles assemble + link internally for -target eynos)
./chibicc -target eynos --sysroot /path/to/eynos-userland app.c -o app.uelf
```

## Troubleshooting

### "Missing header" errors
- Ensure you passed `--sysroot /path/to/userland` (or set `CHIBICC_SYSROOT`)
- Confirm the headers exist at `<sysroot>/include`

### Accidentally using host headers
- For EYN-OS target, chibicc intentionally avoids default host include paths
- If you manually add `-I/usr/include`, you can still break freestanding builds

### Build takes a very long time / appears frozen
- chibicc now prints progress messages to `stderr` at each compilation phase
  (tokenize, preprocess every 10 000 tokens, parse every 25 functions,
  codegen every 25 functions).  This is normal for large unity builds.

### "token pool exhausted"
- The default token pool holds 750 000 `Token` structs (~54 MB BSS).
  If you hit this limit on a very large translation unit, rebuild chibicc
  with a larger `TOKEN_POOL_CAPACITY` in `tokenize.c`.
