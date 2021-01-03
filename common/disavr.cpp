#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void handleUnimplemented()
{
    //printf("Warning unimplemented\n");
}

const char* avr_decode(uint32_t opcode)
{
    uint8_t opcode0 = (opcode & 0xFF00) >> 8;
    uint8_t opcode1 = opcode & 0xFF;
    uint8_t opcode2 = (opcode & 0xFF000000) >> 24;
    uint8_t opcode3 = (opcode & 0xFF0000) >> 16;

    switch(opcode2)
    {
        case 0x90:
        case 0x91:
            if((opcode3 & 0xF) == 0x0)
            {
                return "lds";
            }
            break;
        case 0x92:
        case 0x93:
            if((opcode3 & 0xF) == 0x0)
            {
                return "sts";
            }
            break;
        case 0x94:
        case 0x95:
            switch(opcode3)
            {
                case 0xC:
                case 0xD:
                    return "jmp";
                    break;
                case 0xE:
                case 0xF:
                    return "call";
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }

    if(((opcode0 == 0x95) && (opcode1 == 0x98))) //break
        return "break";

    switch(opcode0)
    {
        case 0x0:
            if(opcode1 == 0x00) //nop
            {
                return "nop";
            }
            handleUnimplemented();
            break;
        case 0x1: //movw
            return "movw";
        case 0x2: //muls
        case 0x3: //mulsu
            return "muls";
        case 0x4:
        case 0x5:
        case 0x6:
        case 0x7: //cpc
            return "cpc";
        case 0x8:
        case 0x9:
        case 0xA:
        case 0xB: //sbc
            return "sbc";
        case 0xC:
        case 0xD:
        case 0xE:
        case 0xF: //add
            return "add";
        case 0x10:
        case 0x11:
        case 0x12:
        case 0x13: //cpse
            //longOpcode
            break;
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17: //cp
           return "cp";
        case 0x18:
        case 0x19:
        case 0x1A:
        case 0x1B: //sub
           return "sub";
        case 0x1C:
        case 0x1D:
        case 0x1E:
        case 0x1F: //adc
           return "adc";
        case 0x20:
        case 0x21:
        case 0x22:
        case 0x23: //and
           return "and";
        case 0x24:
        case 0x25:
        case 0x26:
        case 0x27: //eor
           return "eor";
        case 0x28:
        case 0x29:
        case 0x2A:
        case 0x2B: //or
           return "or";
        case 0x2C:
        case 0x2D:
        case 0x2E:
        case 0x2F: //mov
           return "mov";
        case 0x30:
        case 0x31:
        case 0x32:
        case 0x33:
        case 0x34:
        case 0x35:
        case 0x36:
        case 0x37:
        case 0x38:
        case 0x39:
        case 0x3A:
        case 0x3B:
        case 0x3C:
        case 0x3D:
        case 0x3E:
        case 0x3F: //cpi
            return "cpi";
        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
        case 0x48:
        case 0x49:
        case 0x4A:
        case 0x4B:
        case 0x4C:
        case 0x4D:
        case 0x4E:
        case 0x4F: //sbci
            return "sbci";
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
        case 0x58:
        case 0x59:
        case 0x5A:
        case 0x5B:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F: //subi
            return "subi";
        case 0x60:
        case 0x61:
        case 0x62:
        case 0x63:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
        case 0x68:
        case 0x69:
        case 0x6A:
        case 0x6B:
        case 0x6C:
        case 0x6D:
        case 0x6E:
        case 0x6F: //ori
            return "ori";
        case 0x70:
        case 0x71:
        case 0x72:
        case 0x73:
        case 0x74:
        case 0x75:
        case 0x76:
        case 0x77:
        case 0x78:
        case 0x79:
        case 0x7A:
        case 0x7B:
        case 0x7C:
        case 0x7D:
        case 0x7E:
        case 0x7F: //andi
            return "andi";
        case 0x80:
        case 0x81:
            if((opcode1 & 0xF) >= 0x8) //ld (ldd) y
            {
                return "ldd";
            }
            if((opcode1 & 0xF) < 0x8) //ld (ldd) z
            {
                return "ldd";
            }
            handleUnimplemented();
            break;
        case 0x82:
        case 0x83:
            if((opcode1 & 0xF) >= 0x8) //st (std) y
            {
                return "std";
            }
            if((opcode1 & 0xF) < 0x8) //st (std) z
            {
                return "std";
            }
            handleUnimplemented();
            break;
        case 0x84:
        case 0x85:
        case 0x8C:
        case 0x8D:
            if((opcode1 & 0xF) >= 0x8) //ld (ldd) y
            {
                return "ldd";
            }
            if((opcode1 & 0xF) < 0x8) //ld (ldd) z
            {
                return "ldd";
            }
            handleUnimplemented();
            break;
        case 0x86:
        case 0x87:
            if((opcode1 & 0xF) >= 0x8) //st (std) y
            {
                return "std";
            }
            if((opcode1 & 0xF) < 0x8) //st (std) z
            {
                return "std";
            }
            handleUnimplemented();
            break;
        case 0x88:
        case 0x89:
            if((opcode1 & 0xF) >= 0x8) //ld (ldd) y
            {
                return "ldd";
            }
            if((opcode1 & 0xF) < 0x8) //ld (ldd) z
            {
                return "ldd";
            }
            handleUnimplemented();
            break;
        case 0x8A:
        case 0x8B:
        case 0x8E:
        case 0x8F:
            if((opcode1 & 0xF) >= 0x8) //st (std) y
            {
                return "std";
            }
            if((opcode1 & 0xF) < 0x8) //st (std) z
            {
                return "std";
            }
            handleUnimplemented();
            break;
        case 0x90:
        case 0x91:
            if((opcode1 & 0xF) == 0x0) //lds
            {
               return "lds";
            }
            if((opcode1 & 0xF) == 0x1) //ld z+
            {
                return "ld";
            }
            if((opcode1 & 0xF) == 0x2) //ld -z
            {
                return "ld";
            }
            if((opcode1 & 0xF) == 0x4) //lpm (rd, z)
            {
                return "lpm";
            }
            if((opcode1 & 0xF) == 0x5) //lpm (rd, z+)
            {
                return "lpm";
            }
            if((opcode1 & 0xF) == 0x7) //elpm
            {
                return "elpm";
            }
            if((opcode1 & 0xF) == 0x9) //ld y+
            {
                return "ld";
            }
            if((opcode1 & 0xF) == 0xA) //ld -y
            {
                return "ld";
            }
            if((opcode1 & 0xF) == 0xC) //ld x
            {
                return "ld";
            }
            if((opcode1 & 0xF) == 0xD) //ld x+
            {
                return "ld";
            }
            if((opcode1 & 0xF) == 0xF) //pop
            {
                return "pop";
            }
            handleUnimplemented();
            break;
        case 0x92:
        case 0x93:
           if((opcode1 & 0xF) == 0x0) //sts
           {
              return "sts";
           }
           if((opcode1 & 0xF) == 0x1) //st (std) z+
           {
               return "std";
           }
           if((opcode1 & 0xF) == 0x2) //st (std) -z
           {
               return "std";
           }
           if((opcode1 & 0xF) == 0x9) //st (std) y+
           {
               return "std";
           }
           if((opcode1 & 0xF) == 0xA) //st (std) -y
           {
               return "std";
           }
           if((opcode1 & 0xF) == 0xF) //push
           {
               return "push";
           }
           if((opcode1 & 0xF) == 0xC) //st x
           {
               return "st";
           }
           if((opcode1 & 0xF) == 0xD) //st x+
           {
               return "st";
           }
           if((opcode1 & 0xF) == 0xE) //st -x
           {
               return "st";
           }
           handleUnimplemented();
           break;
        case 0x94:
        case 0x95:
            if((opcode0 == 0x94) && (opcode1 == 0x08)) //sec
            {
                return "sec";
            }
            if((opcode0 == 0x94) && (opcode1 == 0x09)) //ijmp
            {
                return "ijmp";
            }
            if((opcode0 == 0x94) && (opcode1 == 0x68)) //set
            {
                return "set";
            }
            if((opcode0 == 0x94) && (opcode1 == 0x78)) //sei
            {
                return "sei";
            }
            if((opcode0 == 0x94) && (opcode1 == 0xE8)) //clt
            {
                return "clt";
            }
            if((opcode0 == 0x94) && (opcode1 == 0xF8)) //cli
            {
                return "cli";
            }
            if((opcode0 == 0x95) && (opcode1 == 0x88)) //sleep
            {
                return "sleep";
            }
            if((opcode0 == 0x95) && (opcode1 == 0xA8)) //wdr
            {
                return "wdr";
            }
            if((opcode0 == 0x95) && (opcode1 == 0x8)) //ret
            {
                return "ret";
            }
            if((opcode0 == 0x95) && (opcode1 == 0x9)) //icall
            {
                return "icall";
            }
            if((opcode0 == 0x95) && (opcode1 == 0x18)) //reti
            {
                return "reti";
            }
            switch(opcode1 & 0x0F)
            {
                case 0x0: //com
                    return "com";
                case 0x1: //neg
                    return "neg";
                case 0x2: //swap
                    return "swap";
                case 0x3: //inc
                    return "inc";
                case 0x5: //asr
                    return "asr";
                case 0x6: //lsr
                    return "lsr";
                case 0x7: //ror
                    return "ror";
                case 0xA: //dec
                    return "dec";
                case 0xC:
                case 0xD: //jmp
                    handleUnimplemented(); //32-bit
                    break;
                case 0xE:
                case 0xF: //call
                    handleUnimplemented(); //32-bit
                    break;
                default:
                    handleUnimplemented();
                    break;
            }
            break;
        case 0x96: //adiw
        case 0x97: //sbiw
            switch((opcode1 & 0x30) >> 4)
            {
                case 0:
                    break;
                case 1:
                    break;
                case 2:
                    break;
                case 3:
                    break;
                default:
                    handleUnimplemented();
                    break;
            }
            if(opcode0 == 0x96)
            {
                return "adiw";
            }
            if(opcode0 == 0x97)
            {
                return "sbiw";
            }
            switch((opcode1 & 0x30) >> 4)
            {
                case 0:
                    break;
                case 1:
                    break;
                case 2:
                    break;
                case 3:
                    break;
                default:
                    handleUnimplemented();
                    break;
            }
            break;
        case 0x98: //cbi
            return "cbi";
        case 0x9A: //sbi
            return "sbi";
        case 0x9B: //sbis
            return "sbis";
        case 0x9C:
        case 0x9D:
        case 0x9E:
        case 0x9F: //mul
           return "mul";
        case 0xA0:
        case 0xA1:
        case 0xA4:
        case 0xA5:
        case 0xA8:
        case 0xA9:
        case 0xAC:
        case 0xAD:
            if((opcode1 & 0xF) < 0x8) //ld (ldd) z
            {
                return "ldd";
            }
            if((opcode1 & 0xF) >= 0x8) //ld (ldd) y
            {
                return "ldd";
            }
            handleUnimplemented();
            break;
        case 0xA2:
        case 0xA3:
        case 0xA6:
        case 0xA7:
        case 0xAA:
        case 0xAB:
        case 0xAE:
        case 0xAF:
            if((opcode1 & 0xF) < 0x8) //st (std) z
            {
                return "std";
            }
            if((opcode1 & 0xF) >= 0x8) //st (std) y
            {
                return "std";
            }
            handleUnimplemented();
            break;
        case 0xB0:
        case 0xB1:
        case 0xB2:
        case 0xB3:
        case 0xB4:
        case 0xB5:
        case 0xB6:
        case 0xB7: //in
            return "in";
        case 0xB8:
        case 0xB9:
        case 0xBA:
        case 0xBB:
        case 0xBC:
        case 0xBD:
        case 0xBE:
        case 0xBF: //out
            return "out";
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC4:
        case 0xC5:
        case 0xC6:
        case 0xC7:
        case 0xC8:
        case 0xC9:
        case 0xCA:
        case 0xCB:
        case 0xCC:
        case 0xCD:
        case 0xCE:
        case 0xCF: //rjmp
            if((opcode0 == 0xCF) && (opcode1 == 0xFF))
            {
                //Program Exit
                return "exit";
            }
            return "rjmp";
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
        case 0xD4:
        case 0xD5:
        case 0xD6:
        case 0xD7:
        case 0xD8:
        case 0xD9:
        case 0xDA:
        case 0xDB:
        case 0xDC:
        case 0xDD:
        case 0xDE:
        case 0xDF: //rcall
            return "rcall";
        case 0xE0:
        case 0xE1:
        case 0xE2:
        case 0xE3:
        case 0xE4:
        case 0xE5:
        case 0xE6:
        case 0xE7:
        case 0xE8:
        case 0xE9:
        case 0xEA:
        case 0xEB:
        case 0xEC:
        case 0xED:
        case 0xEE:
        case 0xEF: //ldi
            return "ldi";
        case 0xF0:
        case 0xF1:
        case 0xF2:
        case 0xF3:
            if((((opcode0 & 0x0C) >> 2) == 0x0) && ((opcode1 & 0x7) == 0x0)) //brcs
            {
                return "brcs";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x0) && ((opcode1 & 0x7) == 0x1)) //breq
            {
                return "breq";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x0) && ((opcode1 & 0x7) == 0x2)) //brmi
            {
                return "brmi";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x0) && ((opcode1 & 0x7) == 0x4)) //brlt
            {
                return "brlt";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x0) && ((opcode1 & 0x7) == 0x6)) //brts
            {
                return "brts";
            }
            handleUnimplemented();
            break;
        case 0xF4:
        case 0xF5:
        case 0xF6:
        case 0xF7:
            if((((opcode0 & 0x0C) >> 2) == 0x1) && ((opcode1 & 0x7) == 0x2)) //brpl
            {
                return "brpl";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x1) && ((opcode1 & 0x7) == 0x0)) //brcc
            {
                return "brcc";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x1) && ((opcode1 & 0x7) == 0x1)) //brne
            {
                return "brne";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x1) && ((opcode1 & 0x7) == 0x4)) //brge
            {
                return "brge";
            }
            if((((opcode0 & 0x0C) >> 2) == 0x1) && ((opcode1 & 0x7) == 0x6)) //brtc
            {
                return "brtc";
            }
            handleUnimplemented();
            break;
        case 0xF8:
        case 0xF9: //bld
            if((opcode1 & 0xF) < 0x8)
            {
                return "bld";
            }
            handleUnimplemented();
            break;
        case 0xFA:
        case 0xFB: //bst
            return "bst";
        case 0xFC:
        case 0xFD: //sbrc
            return "sbrc";
        case 0xFE:
        case 0xFF: //sbrs
            return "sbrs";
        default:
            handleUnimplemented();
            break;
    }

    return "invalid";
}
