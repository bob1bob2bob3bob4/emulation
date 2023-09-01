from capstone import *
from capstone.x86 import *

def read_shellcode(sc_file):
    try:
        with open(sc_file, 'rb') as shellcode_file:
            shellcode = shellcode_file.read()

            return shellcode
    
    except FileNotFoundError:
        print(f"The shellcode file '{sc_file}' does not exist.")
    except IOError:
        print(f"An error occurred while reading the shellcode file '{sc_file}'")


def disassenble_shellcode(shellcode):
    
    arch = CS_ARCH_X86
    mode = CS_MODE_32

    md = Cs(arch, mode)
    md.detail = True
    md.skipdata = True

    disassenbled_shellcode= []
    address = 0

    for instruction in md.disasm(shellcode, address):
        print(f"0x{instruction.address:08x}: {instruction.mnemonic} {instruction.op_str}")
        disassenbled_shellcode.append(instruction)

    return disassenbled_shellcode


def add_handler(disassenbled_shellcode):
    registers = {}
    registers[X86_REG_EAX] = 0
    registers[X86_REG_EBX] = 0
    # registers[X86_REG_EIP] = 0


    for instruction in disassenbled_shellcode:
        mnemonic = instruction.mnemonic
        operands = instruction.operands
        
        if mnemonic == 'mov':
            # mov <reg>,<imm>
            if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
                registers[operands[0].reg] = operands[1].value.imm
            else:
                print(f"\n{instruction} implementation error")
                break  
        elif mnemonic == 'add':
             # add <reg>,<reg>  
             if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:    
                registers[operands[0].reg] = registers[operands[0].reg] + registers[operands[1].reg]
             else:
                print(f"\n{instruction} implementation error")
                break
        else:
            print(f"\nInstruction not implemented: {instruction}")
            break  


    print(f"\nCompleted emulation, EAX: {registers[X86_REG_EAX]}") 


if __name__ == '__main__':
    
    shellcode = read_shellcode('add.bin')
    disassenbled_shellcode = disassenble_shellcode(shellcode)
    add_handler(disassenbled_shellcode)