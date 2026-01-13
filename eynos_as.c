#include "chibicc.h"

#ifdef CHIBICC_EYNOS_USERLAND

// Implemented in eynos_as_impl.c
int eynos_assemble_uelf_from_file(const char *input_path, const char *output_path);

#else

int eynos_assemble_uelf_from_file(const char *input_path, const char *output_path) {
  (void)input_path;
  (void)output_path;
  error("--as is only supported in EYN-OS userland builds");
  return 1;
}

#endif
