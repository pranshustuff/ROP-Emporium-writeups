import os

str = 'flag.txt'

for c in str:
    hexcode = hex(ord(c)).strip('0x')
    os.system("ROPgadget --binary fluff --opcode "+hexcode+" | tail -n1")


