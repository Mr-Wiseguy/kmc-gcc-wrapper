#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <malloc.h>
#include <ucontext.h>
#include <stdlib.h>
#include "dos.h"
#include "log.h"

// Variable include
#define INCLUDE_PROG() <PROG.h>
#include INCLUDE_PROG()

typedef __attribute__((__cdecl__)) void (func_t)();
typedef __attribute__((__cdecl__)) const char* (getenv_t)(const char*);


#define NUM_NOPS (sizeof(nops) / sizeof(nops[0]))
#define NUM_INT21 (sizeof(int21Addrs) / sizeof(int21Addrs[0]))

#define INT3 0xCC
#define NOP 0x90

// SIGTRAP handler that creates the context passed to the DOS 21h handler
void sig_handler(__attribute__((unused)) int signum, __attribute__((unused)) siginfo_t *info, void *vcontext)
{
    ucontext_t *context = (ucontext_t*)vcontext;
    uint32_t *eax = (uint32_t *)&context->uc_mcontext.gregs[REG_EAX];
    uint32_t *ebx = (uint32_t *)&context->uc_mcontext.gregs[REG_EBX];
    uint32_t *ecx = (uint32_t *)&context->uc_mcontext.gregs[REG_ECX];
    uint32_t *edx = (uint32_t *)&context->uc_mcontext.gregs[REG_EDX];
    uint32_t *efl = (uint32_t *)&context->uc_mcontext.gregs[REG_EFL];
    uint32_t *esi = (uint32_t *)&context->uc_mcontext.gregs[REG_ESI];
    unsigned long ip = context->uc_mcontext.gregs[REG_EIP];
    unsigned long ds = context->uc_mcontext.gregs[REG_DS];
    uint32_t *sp = (uint32_t*)context->uc_mcontext.gregs[REG_ESP];
    unsigned long ah = ((*eax) >> 8) & 0xFF;
    unsigned long al = ((*eax) >> 0) & 0xFF;
    context_t ctx = {
        .eax = eax,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
        .efl = efl,
        .esi = esi,
        .ah = ah,
        .al = al
    };
    
    LOG_PRINT("DOS syscall\n"
           "  IP:  0x%08lX\n"
           "  AH:  0x%02lX\n"
           "  AL:  0x%02lX\n"
           "  EBX: 0x%08X\n"
           "  ECX: 0x%08X\n"
           "  EDX: 0x%08X\n"
           "  DS:  0x%04lX\n", 
           ip, ah, al, *ebx, *ecx, *edx, ds);
    LOG_PRINT("  stack\n"
           "    0x%08X 0x%08X 0x%08X 0x%08X\n"
           "    0x%08X 0x%08X 0x%08X 0x%08X\n"
           "    0x%08X 0x%08X 0x%08X 0x%08X\n"
           "    0x%08X 0x%08X 0x%08X 0x%08X\n",
           sp[0],  sp[1],  sp[2],  sp[3],
           sp[4],  sp[5],  sp[6],  sp[7],
           sp[8],  sp[9],  sp[10], sp[11],
           sp[12], sp[13], sp[14], sp[15]);

    dos_21h_handler(&ctx);
}

// Wrapper for malloc that will be jumped to via a patch on the original binary's malloc
__attribute__((__cdecl__)) void *malloc_wrapper(size_t len)
{
    return malloc(len);
}

// Wrapper for malloc that will be jumped to via a patch on the original binary's malloc
__attribute__((__cdecl__)) void *realloc_wrapper(void *ptr, size_t len)
{
    return realloc(ptr, len);
}

// Overwrites the first instructions of some functions in the original binary with jumps to our wrappers instead
void write_jump_hooks()
{
    uint32_t mallocWrapperAddr = (uint32_t)&malloc_wrapper;
    uint32_t reallocWrapperAddr = (uint32_t)&realloc_wrapper;
    uint32_t rel32 = mallocWrapperAddr - (uint32_t)mallocAddr - 5;
    // x86 jmp rel32
    ((uint8_t*)mallocAddr)[0] = 0xE9;

    // jump offset
    ((uint8_t*)mallocAddr)[1] = (rel32 >>  0) & 0xFF;
    ((uint8_t*)mallocAddr)[2] = (rel32 >>  8) & 0xFF;
    ((uint8_t*)mallocAddr)[3] = (rel32 >> 16) & 0xFF;
    ((uint8_t*)mallocAddr)[4] = (rel32 >> 24) & 0xFF;
    
    rel32 = reallocWrapperAddr - (uint32_t)reallocAddr - 5;
    // x86 jmp rel32
    ((uint8_t*)reallocAddr)[0] = 0xE9;

    // jump offset
    ((uint8_t*)reallocAddr)[1] = (rel32 >>  0) & 0xFF;
    ((uint8_t*)reallocAddr)[2] = (rel32 >>  8) & 0xFF;
    ((uint8_t*)reallocAddr)[3] = (rel32 >> 16) & 0xFF;
    ((uint8_t*)reallocAddr)[4] = (rel32 >> 24) & 0xFF;
}

int main(int argc, char* argv[])
{
    FILE *f;
    void *progMem;
    func_t *binStart = (func_t *)startAddr;
    size_t i;
    struct sigaction sig_action;
    
    // Set up the SIGTRAP handler
    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = sig_handler;
    sig_action.sa_flags = SA_RESTART | SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGTRAP, &sig_action, 0); // Register signal handler

    // Get the length of the input binary
    f = fopen(BIN_FILE, "rb");
    if (f == NULL)
    {
        LOG_PRINT("Error: Cannot open %s\n", BIN_FILE);
        return 1;
    }
    
    // mmap a region of memory at the fixed load address for the given binary
    progMem = mmap((void*)loadAddr, codeDataLength + bssSize - fileOffset, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0x0);
    // Read the program bytes into the mmap'd memory region
    fseek(f, fileOffset, SEEK_SET);
    if (fread(progMem, codeDataLength, 1, f) < 1)
    {
        LOG_PRINT("Error: Failed to read file contents\n");
        return 1;
    }
    fclose(f);

    // Overwrite any instructions that need to be nop'd
    for (i = 0; i < NUM_NOPS; i++)
    {
        *((uint8_t *)nops[i]) = NOP;
    }

    // Overwrite any int 0x21 instructions with int3; nop so they can be caught by the SIGTRAP handler
    for (i = 0; i < NUM_INT21; i++)
    {
        *((uint8_t *)(int21Addrs[i] + 0)) = INT3;
        *((uint8_t *)(int21Addrs[i] + 1)) = NOP;
    }

    // Overwrite the program's environ with the real one
    *(char***)environAddr = environ;

    // Write malloc/realloc jump hooks onto the program's ram
    write_jump_hooks();

    // Initialize any required DOS state
    dos_init();

    // Call the program's main function
    binStart(argc, argv);

    return 0;
}
