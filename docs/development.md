# Build & Development Notes

This fork is intended to become its own repository.

Guiding rules:
- Keep EYN-OS integration **opt-in** (via `-target eynos` + sysroot), not implicit
- Prefer generic compiler switches over EYN-OS-specific hardcoded paths
- Avoid pulling EYN-OS kernel headers into the compiler or user programs

## Build

```bash
make -j
```

## Sanity Checks

### Build a trivial object for EYN-OS

```bash
./chibicc -target eynos --sysroot /path/to/eynos-userland -c app.c -o app.o
```

### Verify macros

You can dump preprocessed output with:

```bash
./chibicc -target eynos --sysroot /path/to/eynos-userland -E app.c
```

Expected (informally):
- `__EYNOS__` is defined
- `__linux__` is not defined

## Ring3 Smoke Programs (Optional)

In the EYN-OS monorepo, small deterministic user programs live in `testdir/`:
- `ring3_smoke_globals.c` (data/bss init + struct load/store)
- `ring3_smoke_structs.c` (struct passing/return + basic libc + recursion)

They’re intended as quick regression tests for the compiler + loader.

## Directory Layout (Recommended for Standalone Repo)

A clean split looks like:

```
chibicc-eynos/
  chibicc-main/        (compiler sources)
  docs/                (these docs)
  tools/               (optional: build wrappers)
```

If you keep an EYN-OS wrapper script, treat it as a separate tool that happens to call the compiler.
