#!/usr/bin/env python3
import coff
import sys
from capstone import *
import argparse

progname = 'kmc-translate'

parser = argparse.ArgumentParser(prog=progname, description='Translates a kmc gcc binary to 32-bit linux')
parser.add_argument('bin', help='The kmc gcc binary to convert')
parser.add_argument('--output', '-o', type=argparse.FileType('w'), default=sys.stdout, help='The file to write the generated assembly to')

args = parser.parse_args()

md = Cs(CS_ARCH_X86, CS_MODE_32)

def make_names_unique(syms):
    dups = dict()
    nameMapping = dict()

    for _, (i, val) in enumerate(syms.items()):
        if val.name not in dups:
            # Store index of first occurrence and occurrence value
            dups[val.name] = 1
        else:
            # Increment occurrence value
            dups[val.name] += 1

            # Use stored occurrence value
            nameMapping[syms[i].value] = syms[i].name + str(dups[val.name])
        
    return nameMapping

def write_code_section(filebytes, section, symbols):
    args.output.write('.intel_syntax noprefix\n')
    args.output.write('.section .text, "ax",@progbits\n')
    sectionBytes = filebytes[section.offdata:section.offdata + section.size]
    symbolDict = {sym.value:sym for sym in symbols} if symbols is not None else dict()
    nameMapping = make_names_unique(symbolDict)
    symbolAddrs = list(symbolDict.keys()) # Already sorted, so no need to resort
    curSymbolIndex = 0
    curSymbol = symbolDict[symbolAddrs[curSymbolIndex]] if len(symbolAddrs) > 0 else None
    for i in md.disasm(sectionBytes, section.vaddr):
        # Print all symbols that are between the last instruction and this one
        while curSymbolIndex < len(symbolAddrs) and i.address >= curSymbol.value:
            symName = curSymbol.name
            if symName != '__gnu_compiled_c':
                if curSymbol.value in nameMapping: # Resolve duplicate named symbols
                    symName = nameMapping[curSymbol.value]
                if curSymbol.storagecls == 0x02: # extern
                    args.output.write('.global ' + symName + '\n')
                    args.output.write('.type ' + symName + ',@function\n')
                args.output.write((symName + ':').ljust(76) + '# ' + hex(curSymbol.value) + '\n')
            curSymbolIndex += 1
            if curSymbolIndex < len(symbolAddrs):
                curSymbol = symbolDict[symbolAddrs[curSymbolIndex]]

        mnemonic = i.mnemonic
        op_str = i.op_str
        if mnemonic in ('pushal','popal'):
            mnemonic = mnemonic[:-1]
        if mnemonic == 'salc':
            mnemonic = '.byte 0xd6'
            op_str = ''
        args.output.write(('    {:12s} {:59s}'.format(mnemonic, op_str)) + '# ' + hex(i.address) + '\n')

def main():
    in_file = open(args.bin, 'rb')
    filebytes = in_file.read()
    in_file.close()
    cffmt = coff.Coff(args.bin)
    print(cffmt)
    print(cffmt.sections)
    print(cffmt.symtables)
    for seckey in range(len(cffmt.sections)):
        section = cffmt.sections[seckey]
        print(section)
        if section.flags & 0x00000020: # code
            write_code_section(filebytes, section, cffmt.symtables.get(seckey))
        # TODO data, bss
    sys.exit(0)

main()