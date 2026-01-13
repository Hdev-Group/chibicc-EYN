#include "chibicc.h"

// Upstream chibicc defaults to building for x86-64 Linux.
// For the EYN-OS userland build, default to i386 + OS_EYNOS so the compiler
// emits 32-bit code (and avoids x86-64-only relocations like @GOTPCREL).
#ifdef CHIBICC_EYNOS_USERLAND
TargetArch target_arch = ARCH_I386;
TargetOS target_os = OS_EYNOS;
#else
TargetArch target_arch = ARCH_X86_64;
TargetOS target_os = OS_LINUX;
#endif

int target_ptr_size = 8;
int target_ptr_align = 8;
int target_long_size = 8;
int target_long_align = 8;
int target_size_t_size = 8;
int target_ptrdiff_t_size = 8;

void init_target(void) {
  // Default matches the original upstream chibicc assumptions (LP64 x86-64).
  if (target_arch == ARCH_X86_64) {
    target_ptr_size = 8;
    target_ptr_align = 8;
    target_long_size = 8;
    target_long_align = 8;
    target_size_t_size = 8;
    target_ptrdiff_t_size = 8;
    return;
  }

  // i386 SysV (ILP32-ish): int/long/pointer are 32-bit.
  target_ptr_size = 4;
  target_ptr_align = 4;
  target_long_size = 4;
  target_long_align = 4;
  target_size_t_size = 4;
  target_ptrdiff_t_size = 4;
}
