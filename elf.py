#!/usr/bin/env python3
from makeelf.elf import *
import coff
import argparse
import sys

progname = 'kmc-translate'

parser = argparse.ArgumentParser(prog=progname, description='Translates a kmc gcc binary to 32-bit linux')
parser.add_argument('bin', help='The kmc gcc binary to convert')
parser.add_argument('--output', '-o', type=argparse.FileType('w'), default=sys.stdout, help='The file to write the generated assembly to')

args = parser.parse_args()

in_file = open(args.bin, 'rb')
filebytes = in_file.read()
in_file.close()
cffmt = coff.Coff(args.bin)
print(cffmt)
print(cffmt.opthdr)
print(cffmt.sections)
print(cffmt.symtables)

elf = ELF(e_machine=EM.EM_386)

print(elf)