#ifndef __DOS_H__
#define __DOS_H__

#include <stdint.h>

typedef enum {
    DOS_GET_VER = 0x30,
    DOS_CREATE_FILE = 0x3C,
    DOS_OPEN_FILE = 0x3D,
    DOS_IOCTL = 0x44,
    DOS_EXIT = 0x4C,
} dos_api_t;

typedef enum {
    DOS_FILE_READ = 0,
    DOS_FILE_WRITE = 1,
    DOS_FILE_READWRITE = 2,
} dos_file_mode_t;

typedef struct {
    uint32_t *eax;
    uint32_t *ebx;
    uint32_t *ecx;
    uint32_t *edx;
    uint32_t *efl;
    int8_t ah;
    int8_t al;
} context_t;

#define DOS_RETURN(ctx, val) *(ctx)->eax = (val); return

void dos_21h_handler(context_t *ctx);

#endif