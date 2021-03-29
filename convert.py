#!/usr/bin/env python3
import coff
import sys
from capstone import *

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
    print('.intel_syntax noprefix')
    print('.section .text, "ax",@progbits')
    sectionBytes = filebytes[section.offdata:section.offdata + section.size]
    symbolDict = {sym.value:sym for sym in symbols}
    nameMapping = make_names_unique(symbolDict)
    symbolAddrs = list(symbolDict.keys()) # Already sorted, so no need to resort
    symbolAddrs.append(symbolDict[symbolAddrs[0]].value) # Dummy at the end of the list to prevent an error
    curSymbolIndex = 0
    curSymbol = symbolDict[symbolAddrs[curSymbolIndex]]
    for i in md.disasm(sectionBytes, section.vaddr):
        # Print all symbols that are between the last instruction and this one
        while curSymbolIndex < (len(symbolAddrs) - 1) and i.address >= curSymbol.value:
            symName = curSymbol.name
            if symName != '__gnu_compiled_c':
                if curSymbol.value in nameMapping: # Resolve duplicate named symbols
                    symName = nameMapping[curSymbol.value]
                if curSymbol.storagecls == 0x02: # extern
                    print('.global ' + symName)
                    print('.type ' + symName + ',@function')
                print((symName + ':').ljust(76) + '# ' + hex(curSymbol.value))
            curSymbolIndex += 1
            curSymbol = symbolDict[symbolAddrs[curSymbolIndex]]

        mnemonic = i.mnemonic
        op_str = i.op_str
        if mnemonic in ('pushal','popal'):
            mnemonic = mnemonic[:-1]
        if mnemonic == 'salc':
            mnemonic = '.byte 0xd6'
            op_str = ''
        print(('    {:12s} {:59s}'.format(mnemonic, op_str)) + '# ' + hex(i.address))

def main():
    for v in sys.argv[1:]:
        in_file = open(v, 'rb')
        filebytes = in_file.read()
        in_file.close()
        cffmt = coff.Coff(v)
        for seckey in cffmt.symtables.keys():
            section = cffmt.sections[seckey]
            if section.flags & 0x00000020: # code
                write_code_section(filebytes, section, cffmt.symtables[seckey])
            # TODO data, bss
    sys.exit(0)

main()