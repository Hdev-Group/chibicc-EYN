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

### Produce a runnable `.uelf` directly

```bash
./chibicc -target eynos --sysroot /path/to/eynos-userland app.c -o app.uelf
```

### Verify macros

```bash
./chibicc -target eynos --sysroot /path/to/eynos-userland -E app.c
```

Expected (informally):
- `__EYNOS__` is defined
- `__linux__` is not defined

## Token Pool

All `Token` structs are allocated from a static BSS pool (`g_token_pool` in
`tokenize.c`) rather than via individual `calloc()` calls.

- **Capacity**: 750 000 tokens (~54 MB of BSS virtual address space)
- **Cost**: zero physical RAM until a page is first written (demand-zero BSS)
- **Limit**: if the pool is exhausted, chibicc prints a clear error message
  and aborts.  Rebuild with a larger `TOKEN_POOL_CAPACITY` for very large
  translation units.
- **80% warning**: a `[chibicc] WARNING: token pool 80% full` message is
  printed to `stderr` when 600 000 slots have been consumed.

The `token_alloc()` function is declared in `chibicc.h` so the preprocessor
can also use it via `copy_token()`.

## O(n) `append()` in Preprocessor

The `append()` function in `preprocess.c` was rewritten from a copying loop
(O(n) allocations per call) to an in-place tail-splice (O(n) walk, zero
allocations).  This eliminates quadratic heap growth when processing hundreds
of `#include` directives in a unity build.

## Progress Logging

chibicc prints progress messages to `stderr` during compilation so large builds
do not appear to hang:

| Phase        | Frequency                                   |
|--------------|---------------------------------------------|
| Tokenize     | start/done per file, lex count every 10 000 |
| Preprocess   | every 10 000 tokens processed; every `#include` |
| Parse        | every 25 functions parsed                   |
| Codegen      | every 25 functions emitted                  |
| Driver       | at each major phase transition              |

All progress messages begin with `[chibicc]` and are written to `stderr` so
they do not interfere with `-E` preprocessed output on `stdout`.

## Ring3 Smoke Programs (Optional)

In the EYN-OS monorepo, small deterministic user programs live in `testdir/`:
- `ring3_smoke_globals.c` (data/bss init + struct load/store)
- `ring3_smoke_structs.c` (struct passing/return + basic libc + recursion)

They are intended as quick regression tests for the compiler + loader.

## Directory Layout (Recommended for Standalone Repo)

```
chibicc-eynos/
  chibicc-main/        (compiler sources)
  docs/                (these docs)
  tools/               (optional: build wrappers)
```

If you keep an EYN-OS wrapper script, treat it as a separate tool that happens
to call the compiler.
