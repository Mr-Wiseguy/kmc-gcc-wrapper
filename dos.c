#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "dos.h"
#include "log.h"

FILE *fileHandles[NUM_HANDLES]; // Should be plenty
char filenames[NUM_HANDLES][MAX_FILENAME_LEN];

// Start at nonzero to skip the default file handles
int numFileHandles = 10;

#define VALID_HANDLE(handle) ((handle) >= 0 && (handle) < NUM_HANDLES && fileHandles[(handle)] != NULL)

#define VALID_HANDLE_CHECK(ctx, handle) \
    if (!VALID_HANDLE(handle)) \
    { \
        LOG_PRINT("  invalid handle\n"); \
        DOS_SET_ERROR(ctx); \
        DOS_RETURN(ctx, DOS_ERR_INVALID_HANDLE); \
    }

void replace_backslashes(char *input, int len)
{
    while (len > 0)
    {
        if (*input == '\\')
        {
            *input = '/';
        }
        input++;
        len--;
    }
}

void dos_open_file(context_t *ctx)
{
    const char *filename = (const char*)*ctx->edx;
    int filemode = ctx->al;
    int filenameLen = strnlen(filename, FILENAME_MAX);
    char *filenameReplaced; // After replacing backslashes with forward slashes
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
        LOG_PRINT("  invalid access code\n");
        LOG_PRINT("    setting carry flag\n");
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_INVALID_ACCESS_MODE); // access code invalid
    }
    if (filenameLen == FILENAME_MAX)
    {
        LOG_PRINT("  filename too long: %s\n", filename);
        LOG_PRINT("    setting carry flag\n");
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_FILE_NOT_FOUND); // does not exist
    }
    filenameReplaced = malloc(filenameLen + 1);
    filenameReplaced[filenameLen] = 0;
    memcpy(filenameReplaced, filename, filenameLen);
    replace_backslashes(filenameReplaced, filenameLen);


    if (filemode == DOS_FILE_READ && (access(filenameReplaced, F_OK) != 0))
    {
        LOG_PRINT("  file does not exist: %s\n", filenameReplaced);
        LOG_PRINT("    setting carry flag\n");
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_FILE_NOT_FOUND); // does not exist
    }
    LOG_PRINT("  open file: %s\n", filenameReplaced);
    for (int i = 0; i < NUM_HANDLES; i++)
    {
        if (fileHandles[i] && strcmp(filenameReplaced, filenames[i]) == 0)
        {
            LOG_PRINT("    returning existing file handle: %d\n", i);
            DOS_CLEAR_ERROR(ctx);
            DOS_RETURN(ctx, i);
        }
    }
    fileHandles[numFileHandles] = fopen(filenameReplaced, modestr);
    strncpy(filenames[numFileHandles], filenameReplaced, MAX_FILENAME_LEN);
    LOG_PRINT("    returned file handle: %d\n", numFileHandles);
    LOG_PRINT("    clearing carry flag\n");
    DOS_CLEAR_ERROR(ctx); // Clear carry flag
    DOS_RETURN(ctx, numFileHandles++);
}

void dos_create_file(context_t *ctx)
{
    const char *filename = (const char*)*ctx->edx;
    int filenameLen = strnlen(filename, FILENAME_MAX);
    char *filenameReplaced; // After replacing backslashes with forward slashes
    LOG_PRINT("  create file: %s\n", filename);
    if (filenameLen == FILENAME_MAX)
    {
        LOG_PRINT("  filename too long: %s\n", filename);
        LOG_PRINT("    setting carry flag\n");
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_FILE_NOT_FOUND); // does not exist
    }
    filenameReplaced = malloc(filenameLen + 1);
    filenameReplaced[filenameLen] = 0;
    memcpy(filenameReplaced, filename, filenameLen);
    replace_backslashes(filenameReplaced, filenameLen);
    for (int i = 0; i < NUM_HANDLES; i++)
    {
        if (fileHandles[i] && strcmp(filenameReplaced, filenames[i]) == 0)
        {
            LOG_PRINT("    returning existing file handle: %d\n", i);
            DOS_CLEAR_ERROR(ctx);
            DOS_RETURN(ctx, i);
        }
    }
    fileHandles[numFileHandles] = fopen(filenameReplaced, "wb");
    strncpy(filenames[numFileHandles], filenameReplaced, MAX_FILENAME_LEN);
    LOG_PRINT("    returned file handle: %d\n", numFileHandles);
    LOG_PRINT("    clearing carry flag\n");
    DOS_CLEAR_ERROR(ctx);
    DOS_RETURN(ctx, numFileHandles++);
}

void dos_ioctl(context_t *ctx)
{
    int ioctlFunc = ctx->al;
    int handle = (*ctx->ebx) & 0xFFFF;
    __attribute__((unused)) int devNum = (*ctx->ebx) & 0xFF;
    __attribute__((unused)) int numBytes = *ctx->ecx;
    __attribute__((unused)) void *buf = (void*)*ctx->edx;

    LOG_PRINT("  ioctl: function 0x%02X\n", ioctlFunc);

    switch (ioctlFunc)
    {
        case DOS_IOCTL_GET_INFO:
            {
                VALID_HANDLE_CHECK(ctx, handle);
                uint32_t devInfo = 0;
                // uint32_t devInfo = 0b0100100010110000;
                // uint32_t devInfo = 0xFFFF;
                LOG_PRINT("    devinfo: %u\n", devInfo);
                *ctx->edx = devInfo; // TODO real values
                DOS_CLEAR_ERROR(ctx);
                DOS_RETURN(ctx, devInfo);
            }
            break;
    }
}

void dos_write(context_t *ctx)
{
    int handle = (*ctx->ebx) & 0xFFFF;
    int numBytes = *ctx->ecx;
    const char *bytes = (const char*)*ctx->edx;
    int bytesWritten;

    LOG_PRINT("  write 0x%X bytes to handle: %d\n", numBytes, handle);
    LOG_PRINT("    %.*s\n", numBytes, bytes);

    VALID_HANDLE_CHECK(ctx, handle);

    bytesWritten = fwrite(bytes, 1, numBytes, fileHandles[handle]);
    fflush(fileHandles[handle]);
    DOS_CLEAR_ERROR(ctx);
    DOS_RETURN(ctx, bytesWritten);
}

void dos_delete(context_t *ctx)
{
    const char *filename = (const char*)*ctx->edx;
    int ret;

    LOG_PRINT("  deleting file: %s\n", filename);

    ret = remove(filename);
    if (ret != 0)
    {
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_FILE_NOT_FOUND); // Technically could be another reason but w/e
    }
    DOS_CLEAR_ERROR(ctx);
    DOS_RETURN(ctx, 0);
}

void dos_seek(context_t *ctx)
{
    int whence = ctx->al;
    int handle = (*ctx->ebx) & 0xFFFF;
    uint64_t offset = ((uint64_t)*ctx->ecx) << 32 | (*ctx->edx);

    LOG_PRINT("  seeking file handle %d to 0x%016llX bytes from whence %d\n", handle, offset, whence);

    VALID_HANDLE_CHECK(ctx, handle);

    if (fseek(fileHandles[handle], offset, whence) != 0)
    {
        LOG_PRINT("  failed to seek\n");
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_SEEK);
    }

    DOS_CLEAR_ERROR(ctx);
    DOS_RETURN(ctx, ftell(fileHandles[handle]));
}

const char testdata[] = ".set noreorder\naddiu $2, $4, 2\njr $31\nnop\n";

void dos_read(context_t *ctx)
{
    int handle = (*ctx->ebx) & 0xFFFF;
    int numBytes = *ctx->ecx;
    void *out = (void**)*ctx->edx;
    int bytesRead;

    VALID_HANDLE_CHECK(ctx, handle);

    LOG_PRINT("  reading 0x%X bytes into address 0x%08X from handle: %d\n", numBytes, (uint32_t)out, handle);

    bytesRead = fread(out, 1, numBytes, fileHandles[handle]);
    LOG_PRINT("    %.*s\n", numBytes, (const char*)out);
    
    DOS_CLEAR_ERROR(ctx);
    DOS_RETURN(ctx, bytesRead);
}

void dos_close_file(context_t *ctx)
{
    int handle = (*ctx->ebx) & 0xFFFF;

    if ((handle) < 0 || (handle) >= NUM_HANDLES)
    {
        DOS_SET_ERROR(ctx);
        DOS_RETURN(ctx, DOS_ERR_INVALID_HANDLE);
    }
    if (fileHandles[handle])
    {
        LOG_PRINT("    closing and clearing file handle: %d\n", handle);
        fclose(fileHandles[handle]);
        filenames[handle][0] = 0x00;
        fileHandles[handle] = NULL;
    }
    DOS_CLEAR_ERROR(ctx);
    DOS_RETURN(ctx, 0x00);
}

#define DOS_HANDLER(ctx, value, handler) \
    case value: \
        handler(ctx); \
        break

void dos_21h_handler(context_t *ctx)
{        
    switch (ctx->ah)
    {
        case DOS_GET_VER:
            *ctx->eax = 0x00000006; // DOS version 6
            break;
        DOS_HANDLER(ctx, DOS_CREATE_FILE, dos_create_file);
        DOS_HANDLER(ctx, DOS_OPEN_FILE, dos_open_file);
        DOS_HANDLER(ctx, DOS_IOCTL, dos_ioctl);
        DOS_HANDLER(ctx, DOS_WRITE, dos_write);
        DOS_HANDLER(ctx, DOS_DELETE, dos_delete);
        DOS_HANDLER(ctx, DOS_SEEK, dos_seek);
        DOS_HANDLER(ctx, DOS_READ, dos_read);
        DOS_HANDLER(ctx, DOS_CLOSE_FILE, dos_close_file);
        case DOS_EXIT:
            exit(ctx->al);
            break;
        default:
            LOG_PRINT("Unimplemented system call: %02X\n", ctx->ah);
            break;
    }
}

FILE *logFile;

void dos_init(void)
{
#ifndef NDEBUG
    logFile = fopen("log.txt", "w");
#endif
    memset(fileHandles, 0, sizeof(fileHandles));
    fileHandles[0] = stdin;
    fileHandles[1] = stdout;
    fileHandles[2] = stderr;
}

