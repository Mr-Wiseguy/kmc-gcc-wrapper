// AS.OUT
#define BIN_FILE "kmc/gcc/MIPSE/BIN/GCC.OUT"
uint8_t dummy;
uintptr_t loadAddr = 0x1000000;
uintptr_t startAddr = 0x1000488; // TODO
int fileOffset = 0x1000; // TODO
int codeDataLength = 0x5beb4 + 0x1a8c; // TODO
size_t bssSize = 0x010dd940; // TODO
uintptr_t mallocAddr = 0x010d77cc; // TODO
uintptr_t reallocAddr = 0x010d7a14; // TODO
uintptr_t environAddr = 0x010e6340; // TODO
uintptr_t nops[] = {
    (uintptr_t)&dummy,
};

uintptr_t int21Addrs[] = {
    0x00000000, // TODO
};
