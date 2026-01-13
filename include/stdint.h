#ifndef __STDC_STDINT_H__
#define __STDC_STDINT_H__

// Minimal freestanding <stdint.h> for chibicc.
// Types are selected to match the *target* sizes described by chibicc's
// predefined __SIZEOF_*__ macros.

typedef signed char int8_t;
typedef unsigned char uint8_t;

typedef short int16_t;
typedef unsigned short uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef long long int64_t;
typedef unsigned long long uint64_t;

#if __SIZEOF_POINTER__ == 8
typedef int64_t intptr_t;
typedef uint64_t uintptr_t;
#else
typedef int32_t intptr_t;
typedef uint32_t uintptr_t;
#endif

typedef int64_t intmax_t;
typedef uint64_t uintmax_t;

#endif
