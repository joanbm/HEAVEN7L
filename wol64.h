#ifndef WOL64_H
#define WOL64_H

/**
 * ---------------------------------------
 * "WoL64": 32-bit Windows on 64-bit Linux
 * ---------------------------------------
 * Running a x86_32 Windows EXE in a x86_64 Linux ELF creates a few challenges:
 *
 * * RUNNING 32-BIT CODE: x86_64 is not backwards compatible with x86_32, so
 *   just jumping to 32-bit code from 64-bit will quickly result in a SIGILL.
 *   And none of the usual Linux tools (libc, syscalls, etc.) allows switching
 *   to 32-bit mode and back.
 *   However, it turns out that it is possible to switch by using a far call.
 *   This technique is also known as "Heaven's Gate". See:
 *   - https://stackoverflow.com/questions/18272384/far-call-into-user32-cs-from-64-bit-code-on-linux
 *   - https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html
 *
 * * INTERFACING WITH 32 BIT CODE: Since 32-bit code uses 32-bit pointers, we
 *   must ensure that any pointer we pass to it is allocated in the low 4GB
 *   of memory. This does not preclude using libraries (e.g. libc, SDL) which
 *   may allocate memory past the 4GB barrier, as long as we hide it.
 *   For example, we can store a 64-bit SDL_Window* inside an (opaque) HWND,
 *   as long as the HWND is allocated in the low 4GB.
 *
 * * SWITCHING ACROSS WIN32 AND LINUX64: Running a simple 32-bit code fragment
 *   like in the links above is fairly doable, but we need to let 32-bit Windows
 *   code (which uses the stdcall calling convention) to call 64-bit Linux
 *   functions (which use the SysV calling convention) with an arbitrary number
 *   of parameters. This requires some tricky trampolines & stack manipulation.
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// -------------
// 32-BIT MEMORY
// -------------

void *malloc32(size_t size);
void free32(void *ptr);

#define assert_32bitptr(p) assert((uintptr_t)p <= UINT32_MAX)

static inline uint32_t as32bitptr(void *ptr) {
    assert_32bitptr(ptr);
    return (uint32_t)(uintptr_t)ptr;
}

// ---------------------------------
// CALL 32-BIT CODE FROM 64-BIT CODE
// ---------------------------------

typedef struct __attribute__((packed, aligned(16))) {
    int32_t address;
    int16_t segment;
} FarCallGateDescriptor;

/**
 * Start running a 32-bit function in a new thread. This sets up the context
 * to be able to even run 32-bit code from a 64-bit process
 * (such as allocating a stack in the lower 4GB of memory).
 */
bool Launch32(pthread_t *out_thread, void *function, void *argument);

/**
 * Call a 32-bit function. This should only be called from code that runs inside
 * a `Launch32`, since it assumes a 32-bit context is already configured.
 */
void Call32(void *function, size_t nargs, ...);

// --------------------------------------
// RETURN TO 64-BIT CODE FROM 32-BIT CODE
// --------------------------------------

// Macro helper to stringify "x".
#define QUOTE(x) #x
#define EXPAND_AND_QUOTE(x) QUOTE(x)

// Macro helper to concatenate two macros for expansion.
#define _CONCATENATE(a, b) a ## b
#define CONCATENATE(a, b) _CONCATENATE(a, b)

#define STDCALL_TO_SYSV_REGS_0
#define STDCALL_TO_SYSV_REGS_1 STDCALL_TO_SYSV_REGS_0 "pop %rdi\n"
#define STDCALL_TO_SYSV_REGS_2 STDCALL_TO_SYSV_REGS_1 "pop %rsi\n"
#define STDCALL_TO_SYSV_REGS_3 STDCALL_TO_SYSV_REGS_2 "pop %rdx\n"
#define STDCALL_TO_SYSV_REGS_4 STDCALL_TO_SYSV_REGS_3 "pop %rcx\n"
#define STDCALL_TO_SYSV_REGS_5 STDCALL_TO_SYSV_REGS_4 "pop %r8\n"
#define STDCALL_TO_SYSV_REGS_6 STDCALL_TO_SYSV_REGS_5 "pop %r9\n"
#define STDCALL_TO_SYSV_REGS_7 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_8 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_9 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_10 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_11 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_12 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_13 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_14 STDCALL_TO_SYSV_REGS_6
#define STDCALL_TO_SYSV_REGS_15 STDCALL_TO_SYSV_REGS_6

#define MK_TRAMPOLINE_32TO64(func, nargs) \
    static __attribute__((naked)) void func##_Call64AndRetf() { \
        asm volatile ( \
            /* x86_32 __stdcall preserves ESI / EDI, but x86_64 SysV ABI does not,
               so save them in r12-r15 (callee preserved) to restore them later */ \
            "movq %rsi, %r12\n" \
            "movq %rdi, %r13\n" \
            /* Save 4 byte return address of the 32-bit function
               (it's right beyond the 8 byte return vector of the FAR CALL) */ \
            "movl 8(%esp), %r15d\n" \
            /* Set EAX to point to the first of the 32-bit arguments */ \
            "leal 12(%esp), %eax\n" \
            /* Push the 32-bit return address as 64 bits.
               This avoids a crash if pthread_cancel unwinds the thread. */ \
            "push %r15\n" \
            /* 32-bit stdcall to 64-bit SysV calling convention ABI, part 1:
             * Expand each 32-bit argument in the stack to 64 bits.
             * This is a bit wasfteful since:
             * - We do this for all arguments, even those that will end up in
             *   registers, just to make our life easier.
             * - Similarly, we use a runtime loop instead of emitting a
                 taylor-made codegen for the number of arguments */ \
            "movl $" QUOTE(nargs) ", %edx\n" \
            "1:\n" \
            "decl %edx\n" \
            "jl 2f\n" \
            "movl (%eax,%edx,4), %ecx\n" \
            "push %rcx\n" \
            "jg 1b\n" \
            "2:\n" \
            /* 32-bit stdcall to 64-bit SysV calling convention ABI, part 2:
             * Move up to 6 (expanded) stack arguments to registers */ \
            CONCATENATE(STDCALL_TO_SYSV_REGS_, nargs) \
            /* Call 64 bit function */ \
            "call " EXPAND_AND_QUOTE(func) "\n" \
            /* 32-bit stdcall to 64-bit SysV calling convention ABI, part 3:
             * Since syscall is callee cleanup by SysV is caller cleanup,
             * we have to clean up the stack (if we have more than 6 arguments;
             * otherwise there's nothing to clean. Notes:
             * - Since we are advancing over *expanded* stack arguments,
                 we have to advance 8 bytes for each argument.
             * - The minus sign here is because the GNU assembler returns -1
                 for a true comparison */ \
            "addl $((" QUOTE(nargs) " - 6) * -(" QUOTE(nargs) " > 6)) * 8, %esp\n" \
            /* Pop the expanded 32-bit return address of the 32-bit function */ \
            "pop %r15\n" \
            /* Pop the 8 byte return vector of the FAR CALL */ \
            "pop %r14\n" \
            /* Advance over the original 32-bit return address + arguments */ \
            "addl $(" QUOTE(nargs*4+4) "), %esp\n" \
            /* Push 4 byte return address of the 32-bit function */ \
            "subl $4, %esp\n" \
            "movl %r15d, (%esp)\n" \
            /* Push 8 byte return vector of the FAR CALL */ \
            "push %r14\n" \
            /* Restore saved registers */ \
            "movq %r12, %rsi\n" \
            "movq %r13, %rdi\n" \
            "retfl\n" \
        ); \
    } \
     \
    static FarCallGateDescriptor func##_FarCall; \
     \
    __attribute__((constructor)) \
    static void func##_FarCall_Init(void) { \
        func##_FarCall.address = (int32_t)(intptr_t)func##_Call64AndRetf; \
        func##_FarCall.segment = 0x33 /* __USER_CS */; \
    } \
     \
    __attribute__((naked)) void func##_32to64() { \
        /* FIXME: This is very, very fragile. We are executing this in 32-bit mode,
           but the assembler is 64-bit. It works because the encoding is
           close enough across x86_32 and x86_64 that we can wing it this way. */ \
        asm volatile ( \
            "movl $%c0, %%eax\n" \
            "lcall *(%%rax)\n" /* RAX, not EAX, to avoid addressing prefix */ \
            "ret\n" \
            : \
            : "i"(&func##_FarCall) /* FIXME: Don't depend on non-PIE. */ \
        ); \
    } \

#endif
