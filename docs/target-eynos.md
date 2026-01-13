# EYN-OS Target (i386)

This fork adds an explicit EYN-OS target mode to chibicc.

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

To keep the compiler usable outside the EYN-OS monorepo layout, the EYN-OS target prefers an explicit sysroot.

### `--sysroot`

`--sysroot` should point at a directory containing an `include/` folder.

Example:

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

If neither `--sysroot` nor `CHIBICC_SYSROOT` is set, chibicc will *also* try:

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

## Building `.uelf` (Outside the Compiler)

chibicc produces an object file. Creating a runnable ring3 `.uelf` is done by linking with EYN-OS CRT + libc + linker script.

In the EYN-OS monorepo:

```bash
devtools/build_user_c_chibicc.sh testdir/hello_c_uelf.c testdir/hello_c_uelf_chibicc.uelf
```

That script:
- Compiles EYN-OS CRT + libc with GCC
- Compiles your app with chibicc (`-target eynos --sysroot ...`)
- Links a simple ELF32 ET_EXEC at the expected base address

## Troubleshooting

### "Missing header" errors
- Ensure you passed `--sysroot /path/to/userland` (or set `CHIBICC_SYSROOT`)
- Confirm the headers exist at `<sysroot>/include`

### Accidentally using host headers
- For EYN-OS target, chibicc intentionally avoids default host include paths
- If you manually add `-I/usr/include`, you can still break freestanding builds
