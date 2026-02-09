#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <assert.h>
#include <sys/mman.h>
#include "wol64.h"

void *malloc32(size_t size) {
    assert(size <= UINT32_MAX - 4);
    // Allocate 4 extra bytes to store the size (for munmap)
    size += 4;

    void *map = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap for malloc32 failed - FATAL: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    *((uint32_t *)map) = size;
    return (char *)map + 4;
}

void free32(void *ptr) {
    if (ptr == NULL)
        return;

    char *map = (char *)ptr - 4;
    size_t size = *(uint32_t *)map;
    munmap(map, size);
}

struct Launch32Target {
    void *function;
    void *argument;
};

void *Launch32ThreadFn(void *argsvp) {
    struct Launch32Target *args = (struct Launch32Target *)argsvp;

    // Configure DS/ES for 32-bit usage. Those are unused in 64-bit mode,
    // and necessary for memory accesses in 32 bit mode to work.
#ifdef DEBUG
    printf("Configuring DS/ES for 32 bits\n");
#endif
    asm volatile (
        "mov $0x2b, %%ax\n" // __USER_DS
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        :
        :
        : "eax"
    );

    Call32(args->function, 1 /* nargs */, args->argument);
    free(args);
    return NULL;
}

bool Launch32(pthread_t *out_thread, void *function, void *argument) {
    struct Launch32Target *args = malloc(sizeof(struct Launch32Target));
    if (args == NULL) {
        fprintf(stderr, "Could not allocate Launch32 thread args\n");
        return false;
    }
    args->function = function;
    args->argument = argument;

    // Since we want to jump to 32 bit code, we need our stack to live in the
    // lower 32 bits. We use pthread_attr_setstack to set the stack without
    // needing to do more assembly trickery.
    const size_t LOW_STACK_SIZE = 1024 * 1024;
    void *low_stack = mmap(NULL, LOW_STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low_stack == MAP_FAILED) {
        fprintf(stderr, "Could not allocate low stack\n");
        goto cleanup_args;
    }

    pthread_attr_t thread_attr;
    if (pthread_attr_init(&thread_attr) != 0) {
        fprintf(stderr, "Could not set low stack thread attribute\n");
        goto cleanup_args_stack;
    }

    if (pthread_attr_setstack(&thread_attr, low_stack, LOW_STACK_SIZE) != 0) {
        fprintf(stderr, "Could not set low stack thread attribute\n");
        goto cleanup_attr_args_stack;
    }

    if (pthread_create(out_thread, &thread_attr, Launch32ThreadFn,
                       args) != 0) {
        fprintf(stderr, "Could not create low stack thread\n");
        goto cleanup_attr_args_stack;
    }

    pthread_attr_destroy(&thread_attr);
    // NOTE: low_stack is leaked here. We can not free it, see:
    // https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
    // "The application grants to the implementation permanent ownership of and
    //  control over the application-managed stack when the attributes object in
    //  which the stack or stackaddr attribute has been set is used [...]
    //  in particular, the region of memory cannot be freed"
    return true;

cleanup_attr_args_stack:
    pthread_attr_destroy(&thread_attr);

cleanup_args_stack:
    if (munmap(low_stack, LOW_STACK_SIZE) != 0) {
        fprintf(stderr, "WARNING: Could not unmap low stack on Launch32 failure\n");
    }

cleanup_args:
    free(args);
    return false;
}

__attribute__((naked)) void PivotStackAndCall32() {
    // IMPORTANT: This is interpreted as x86_32 code, even though the assembler
    // is written as x86_64 syntax. We take advantage of the fact that the
    // instruction set is similar, so it's mostly compatible.
    asm volatile(
        "xchg %ebx, %esp\n" // Same in x86_32
        "call *%rax\n"      // call %eax
        "xchg %ebx, %esp\n" // Same in x86_32
        "retfl\n"           // retfl
    );
}

void Call32(void *function, size_t nargs, ...) {
    assert_32bitptr(function);

    assert(nargs <= 6);
    uint32_t args32[6];

    va_list args;
    va_start(args, nargs);
    for (size_t i = 0; i < nargs; i++) {
        uintptr_t arg_value = va_arg(args, uintptr_t);
        assert(arg_value <= UINT32_MAX);
        args32[i] = (uint32_t)arg_value;
    }
    va_end(args);

    FarCallGateDescriptor target = {as32bitptr(PivotStackAndCall32), 0x23 /* __USER32_CS */};
#ifdef DEBUG
    fprintf(stderr, "Calling 32-bit function: %p, %zu args\n", function, nargs);
#endif
    asm volatile(
        // Push up the arguments to the 32 bit code in the stack.
        // The major problem here is that the far jump below pushes 8 bytes
        // into the stack. So we pre-push the arguments to the 32 bit code
        // further up, and leave %ebx pointing to the top of the stack.
        // Then, the 32 bit code can just swap %ebx and %esp to fixup the stack.
        "movq %[nargs], %%rcx\n"
        "movq %[args32r], %%rsi\n"
        "leal -8(%%esp), %%ebx\n"
        "1:\n"
        "cmp $0, %%ecx\n"
        "je 2f\n"
        "subl $4, %%ebx\n"
        "subl $4, %%esi\n"
        "movl (%%esi), %%eax\n"
        "movl %%eax, (%%ebx)\n"
        "decl %%ecx\n"
        "jmp 1b\n"
        "2:\n"
        // We can not just do a normal jump from x86_64 to x86_32, since the
        // instruction set is different (e.g. PUSHAD does not exist on x86_64).
        // However, this can be done with a far call into __USER32_CS.
        "movq %[function], %%rax\n"
        "lcall *(%[target])\n"
        :
        : [function] "r"(function),
          [nargs] "r"(nargs),
          [args32r] "r"(&args32[nargs]),
          [target] "r"(&target)
        // FIXME: Review this list of clobbers
        : "cc", "memory",
          "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r12", "r13", "r14", "r15",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}
