#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dos.h"

FILE *fileHandles[100]; // Should be plenty
int numFileHandles = 0;

void dos_open_file(context_t *ctx)
{
    const char *filename = (const char*)*ctx->edx;
    int filemode = ctx->al;
    char *modestr = NULL;
    switch (filemode)
    {
        case DOS_FILE_READ:
            modestr = "rb";
            break;
        case DOS_FILE_WRITE:
            modestr = "wb";
            break;
        case DOS_FILE_READWRITE:
            modestr = "wb";
            break;
    }
    if (modestr == NULL)
    {
        printf("  invalid access code\n");
        printf("    setting carry flag\n");
        *ctx->efl |= 0x0001; // Set carry flag
        DOS_RETURN(ctx, 0x0C); // access code invalid
    }
    if (filemode == DOS_FILE_READ && (access(filename, F_OK) != 0))
    {
        printf("  file does not exist\n");
        printf("    setting carry flag\n");
        *ctx->efl |= 0x0001; // Set carry flag
        DOS_RETURN(ctx, 0x02); // does not exist
    }
    fileHandles[numFileHandles] = fopen(filename, modestr);
    printf("    returned file handle: %d\n", numFileHandles);
    printf("    clearing carry flag\n");
    *ctx->efl &= ~0x0001; // Clear carry flag
    DOS_RETURN(ctx, numFileHandles++);
}

void dos_create_file(context_t *ctx)
{
    const char *filename = (const char*)*ctx->edx;
    printf("  create file: %s\n", filename);
    fileHandles[numFileHandles] = fopen(filename, "wb");
    printf("    returned file handle: %d\n", numFileHandles);
    printf("    clearing carry flag\n");
    *ctx->efl &= ~0x0001; // Clear carry flag
    DOS_RETURN(ctx, numFileHandles++);
}

void dos_ioctl(context_t *ctx)
{

}

void dos_21h_handler(context_t *ctx)
{        
    switch (ctx->ah)
    {
        case DOS_GET_VER:
            *ctx->eax = 0x00000006; // DOS version 6
            break;
        case DOS_CREATE_FILE:
            dos_create_file(ctx);
            break;
        case DOS_OPEN_FILE:
            dos_open_file(ctx);
            break;
        case DOS_IOCTL:
            dos_ioctl(ctx);
            break;
        case DOS_EXIT:
            exit(ctx->al);
            break;
    }
}


