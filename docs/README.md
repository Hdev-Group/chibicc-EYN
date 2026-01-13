# chibicc (EYN-OS fork) Documentation

This directory documents the EYN-OS-focused fork of **chibicc**.

Design goal: keep the compiler **self-contained** and usable as its own repository.
EYN-OS integration (building `.uelf`, CRT, libc, disk image deployment) should remain **optional** and live outside the compiler where possible.

## Documentation Structure

### Getting Started
- **[EYN-OS Target](target-eynos.md)** - `-target eynos`, sysroot, predefined macros, and include paths
- **[Build & Development](development.md)** - building the compiler, sanity checks, and conventions for this fork

## Quick Start (Host Build)

From the chibicc repo root:

```bash
make -j
```

This builds the `chibicc` binary.

## How `.uelf` Builds Fit In (When Used With EYN-OS)

This compiler emits `.o`/`.s`. Producing an EYN-OS ring3 executable (`.uelf`) is a **separate** link step using EYN-OS’s CRT + libc + linker script.

Pipeline:

```
  app.c
    |
    |  chibicc  (-target eynos)
    v
  app.o
    |
    |  i686-elf-gcc/gcc + EYN-OS CRT + libc + user_elf32.ld
    v
  app.uelf
    |
    |  copied into EYNFS image
    v
  run inside EYN-OS (ring3)
```

In the EYN-OS monorepo, the wrapper script lives at:
- `devtools/build_user_c_chibicc.sh`

In a standalone fork, you can provide your own wrapper or build system.

## Non-Goals (For Now)

- No native linker integration for EYN-OS inside chibicc
- No attempt to consume host `/usr/include` when targeting EYN-OS
- No "mixing" kernel headers into user programs
