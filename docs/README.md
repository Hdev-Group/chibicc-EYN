# chibicc (EYN-OS fork) Documentation

This directory documents the EYN-OS-focused fork of **chibicc**.

Design goal: keep the compiler **self-contained** and produce runnable EYN-OS
ring3 executables (`.uelf`) directly, without any external assembler or linker.

## Documentation Structure

### Getting Started
- **[EYN-OS Target](target-eynos.md)** - `-target eynos`, sysroot, predefined macros, include paths, and supported features
- **[Build & Development](development.md)** - building the compiler, sanity checks, and conventions for this fork

## Quick Start (Host Build)

From the chibicc repo root:

```bash
make -j
```

This builds the `chibicc` binary.

## How `.uelf` Builds Work

When `-target eynos` is used, chibicc drives a fully integrated pipeline that
produces a runnable EYN-OS ring3 executable (`.uelf`) without any external tools:

```
  app.c
    |
    |  chibicc -target eynos  (tokenize -> preprocess -> parse -> codegen)
    v
  AT&T assembly (temp file)
    |
    |  eynos_as  (built-in GAS->Intel translator + x86 binary assembler)
    v
  machine code + data + BSS metadata
    |
    |  eynos_linker  (built-in ELF32 ET_EXEC writer)
    v
  app.uelf  (loadable EYN-OS ring3 executable)
    |
    |  copied into EYNFS image
    v
  run inside EYN-OS (ring3)
```

The assembler automatically injects required runtime stubs (CRT `_start` shim,
system-call wrappers `eyn_syscall3` / `eyn_syscall1` / `eyn_syscall0`, and
optional helpers such as `getdents`, `writefile`) when the compiled source
references them by name.

In the EYN-OS monorepo the wrapper script lives at:
- `devtools/build_user_c_chibicc.sh`

In a standalone fork you can invoke chibicc directly with `-target eynos`.

## Non-Goals (For Now)

- No attempt to consume host `/usr/include` when targeting EYN-OS
- No "mixing" kernel headers into user programs
