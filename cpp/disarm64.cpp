#include <stdint.h>

/*
datamov
arith
logical
bit
branch
control
stack
conver
binary
decimal
shftrot
cond
break
string
inout
flgctrl
segreg
*/

/*
AND
ASR
ASRV
AT
B.cond
ANDS
B
BFI
BFM
BFXIL
BIC
BL
BLR
BR
BRK
CBNZ
CBZ
CCMN
CCMP
CINC
CINV
CLREX
CLS
CLZ
CMN
BICS
CNEG
CRC32B
CRC32H
CRC32W
CRC32CB
CRC32CH
CRC32CW
CRC32CX
CSEL
CSET
CSETM
CSINC
CSINV
CSNEG
DC
DCPS1
DCPS2
DCPS3
DMB
DRPS
DSB
EON
CMP
EOR
ERET
EXTR
HINT
HLT
HVC
IC
ISB
LSL
LSLV
LSR
LSRV
MADD
MNEG
MOV
MOVK
MOVL
MOVN
MOVZ
MRS
MSR
MSUB
MUL
MVN
NEG
NEGS
NGC
NGCS
NOP
ORN
RBIT
RET
REV
REV16
REV32
ROR
RORV
SBC
SBCS
SBFIZ
SBFM
SBFX
SDIV
SEV
SEVL
SMADDL
SMC
ORR
SMNEGL
SMSUBL
SMULH
SMULL
SUB
SVC
SXTB
SXTH
SXTW
SYS
SYSL
TBNZ
TBZ
TLBI
TST
UBFIZ
UBFM
UBFX
UDIV
SUBS
TST
UMADDL
UMNEGL
UMSUBL
UMULH
UMULL
UXTB
UXTH
WFE
WFI
YIELD
*/

const uint32_t FILTER0 = 0x7FE0FC00;
const uint32_t FILTER1 = 0x7FE00000;
const uint32_t FILTER2 = 0x7F200000;
const uint32_t FILTER3 = 0x7F000000;
const uint32_t FILTER4 = 0x9F000000;
const uint32_t FILTER5 = 0x7F800000;
const uint32_t FILTER6 = 0x7FE0FFE0;
const uint32_t FILTER7 = 0xBFC00000;
const uint32_t FILTER8 = 0xBFD00C00;
const uint32_t FILTER9 = 0xFC000000;
const uint32_t FILTERA = 0xFFFFFC1F;
const uint32_t FILTERB = 0xFF200000;
const uint32_t FILTERC = 0x7FE0001F;
const uint32_t FILTERD = 0x7F00001F;
const uint32_t FILTERE = 0x7F20001F;
const uint32_t FILTERF = 0xFF000010;
const uint32_t FILTER10 = 0x7F807C00;
const uint32_t FILTER11 = 0x7FC00000;
const uint32_t FILTER12 = 0x3FC00000;
const uint32_t FILTER13 = 0xBFE00C00;
const uint32_t FILTER14 = 0x3FE00C00;
const uint32_t FILTER15 = 0x3F600C00;
const uint32_t FILTER16 = 0xFFE00C00;
const uint32_t FILTER17 = 0xFFC00000;
const uint32_t FILTER18 = 0xFFFFFC00;
const uint32_t FILTER19 = 0x7F30FC00;
const uint32_t FILTER1A = 0xBFFFFC00;
const uint32_t FILTER1B = 0xBFE0FC00;
const uint32_t FILTER1C = 0x7FE07C00;
const uint32_t FILTER1D = 0xFF20FC00;
const uint32_t FILTER1E = 0xFF201FE0;
const uint32_t FILTER1F = 0xBF80FC00;
const uint32_t FILTER20 = 0xBF000000;
const uint32_t FILTER21 = 0x9FF80C00;

const char* arm64_decode(uint32_t opcode)
{
    uint16_t category = (opcode & 0x1E000000) >> 25;
    switch(category)
    {
        case 0: //Technically UNALLOCATED
            break;
        case 1:
        case 2:
        case 3:
//            printf("UNALLOCATED\n");
            break;
        case 4:
        case 6:
        case 12:
        case 14:
//            printf("Load and store\n");
            if((opcode & FILTER7) == 0xB9400000)
            {
                return "LDR";
            }
            else if((opcode & FILTER8) == 0xB8400C00)
            {
                return "LDR";
            }
            else if((opcode & FILTER8) == 0xB8400800)
            {
                return "LDR";
            }
            else if((opcode & FILTER11) == 0x28800000 || (opcode & FILTER11) == 0x29800000 || (opcode & FILTER11) == 0x29000000)
            {
                return "STP";
            }
            else if((opcode & FILTER12) == 0x2C800000 || (opcode & FILTER12) == 0x2C900000 || (opcode & FILTER12) == 0x2C000000)
            {
                return "STP";
            }
            else if((opcode & FILTER14) == 0x3C000400 || (opcode & FILTER14) == 0x3C000C00)
            {
                return "STR";
            }
            else if((opcode & FILTER15) == 0x3C000C00)
            {
                return "STR";
            }
            else if((opcode & FILTER13) == 0xB8000400 || (opcode & FILTER13) == 0xB8000C00)
            {
                return "STR";
            }
            else if((opcode & FILTER7) == 0xB9000000)
            {
                return "STR";
            }
            else if((opcode & FILTER14) == 0x3C200800)
            {
                return "STR";
            }
            else if((opcode & FILTER13) == 0xB8200800)
            {
                return "STR";
            }
            else if((opcode & FILTER11) == 0x28C00000 || (opcode & FILTER11) == 0x29C00000 || (opcode & FILTER11) == 0x29400000)
            {
                return "LDP";
            }
            else if((opcode & FILTER12) == 0x2CC00000 || (opcode & FILTER12) == 0x2DC00000 || (opcode & FILTER12) == 0x2D400000)
            {
                return "LDP";
            }
            else if((opcode & FILTER16) == 0x38400C00 || (opcode & FILTER16) == 0x38400400)
            {
                return "LDRB";
            }
            else if((opcode & FILTER17) == 0x39400000)
            {
                return "LDRB";
            }
            else if((opcode & FILTER16) == 0x38600800)
            {
                return "LDRB";
            }
            else if((opcode & FILTER16) == 0x38000400 || (opcode & FILTER16) == 0x38000C00)
            {
                return "STRB";
            }
            else if((opcode & FILTER17) == 0x39000000)
            {
                return "STRB";
            }
            else if((opcode & FILTER1A) == 0x885FFC00)
            {
                return "LDAXR";
            }
            else if((opcode & FILTER1B) == 0x8800FC00)
            {
                return "STLXR";
            }
            else if((opcode & FILTER13) == 0xB8000000)
            {
                return "STUR";
            }
            else if((opcode & FILTER13) == 0xB8400000)
            {
                return "LDUR";
            }
            else if((opcode & FILTER16) == 0xB8800400 || (opcode & FILTER16) == 0xB8800C00)
            {
                return "LDRSW";
            }
            else if((opcode & FILTER17) == 0xB9800000)
            {
                return "LDRSW";
            }
            else if((opcode & FILTER14) == 0x3C400400 || (opcode & FILTER14) == 0x3C400C00)
            {
                return "LDR";
            }
            else if((opcode & FILTER12) == 0x3D400000)
            {
                return "LDR";
            }
            else if((opcode & FILTER13) == 0xB8400400 || (opcode & FILTER13) == 0xB8400C00)
            {
                return "LDR";
            }
            else if((opcode & FILTER20) == 0x1C000000)
            {
                return "LDR";
            }
            else if((opcode & FILTER20) == 0x18000000)
            {
                return "LDR";
            }
            else if((opcode & FILTER14) == 0x3C600800)
            {
                return "LDR";
            }
            else if((opcode & FILTER13) == 0xB8600800)
            {
                return "LDR";
            }
            else if((opcode & FILTER11) == 0x28800000)
            {
                return "STP";
            }
            else if((opcode & FILTER11) == 0x29800000)
            {
                return "STP";
            }
            else if((opcode & FILTER11) == 0x29000000)
            {
                return "STP";
            }
            else if((opcode & FILTER12) == 0x2C800000 || (opcode & FILTER12) == 0x2D800000 || (opcode & FILTER12) == 0x2D000000)
            {
                return "STP";
            }
            else if((opcode & FILTER16) == 0x38000400 || (opcode & FILTER16) == 0x38000C00)
            {
                return "STRB";
            }
            else if((opcode & FILTER17) == 0x39000000)
            {
                return "STRB";
            }
            else if((opcode & FILTER16) == 0x38200800)
            {
                return "STRB";
            }
            else if((opcode & FILTER16) == 0x78200800)
            {
                return "STRH";
            }
            else if((opcode & FILTER17) == 0x79000000)
            {
                return "STRH";
            }
            else if((opcode & FILTER16) == 0x38400000)
            {
                return "LDURB";
            }
            else if((opcode & FILTER16) == 0x38000000)
            {
                return "STURB";
            }
            else if((opcode & FILTER16) == 0x78000000)
            {
                return "STURH";
            }
            break;
        case 8:
        case 9:
//            printf("Data processing - immediate\n");
            if((opcode & FILTER19) == 0x11000000)
            {
                return "MOV";
            }
            else if((opcode & FILTER3) == 0x11000000)
            {
                return "ADD";
            }
            else if((opcode & FILTER3) == 0x31000000)
            {
                return "ADDS";
            }
            else if((opcode & FILTER5) == 0x52800000)
            {
                return "MOV";
            }
            else if((opcode & FILTER4) == 0x10000000)
            {
                return "ADR";
            }
            else if((opcode & FILTER4) == 0x90000000)
            {
                return "ADRP";
            }
            else if((opcode & FILTER3) == 0x51000000)
            {
                return "SUB";
            }
            else if((opcode & FILTERD) == 0x7100001F)
            {
                return "CMP";
            }
            else if((opcode & FILTER18) == 0x93407C00)
            {
                return "SXTW";
            }
            else if((opcode & FILTER10) == 0x13007C00)
            {
                return "ASR";
            }
            else if((opcode & FILTER18) == 0x53001C00)
            {
                return "UXTB";
            }
            else if((opcode & FILTER17) == 0x71000000)
            {
                return "SUBS";
            }
            else if((opcode & FILTER5) == 0x72800000)
            {
                return "MOVK";
            }
            else if((opcode & FILTER10) == 0x53007C00)
            {
                return "LSR";
            }
            else if((opcode & FILTER5) == 0x32000000)
            {
                return "ORR";
            }
            else if((opcode & FILTER5) == 0x53000000)
            {
                return "LSL";
            }
            else if((opcode & FILTER5) == 0x12000000)
            {
                return "AND";
            }
            break;
        case 10:
        case 11:
//            printf("Branch, exception, system\n");
            if((opcode & FILTER9) == 0x94000000)
            {
                return "BL";
            }
            else if((opcode & FILTER9) == 0x14000000)
            {
                return "B";
            }
            else if((opcode & FILTERA) == 0xD65F0000)
            {
                return "RET";
            }
            else if(opcode == 0xD503201F)
            {
                return "NOP";
            }
            else if((opcode & FILTER3) == 0x34000000)
            {
                return "CBZ";
            }
            else if((opcode & FILTERA) == 0xD61F0000)
            {
                return "BR";
            }
            else if((opcode & FILTERF) == 0x54000000)
            {
                return "B.cond";
            }
            else if((opcode & FILTERA) == 0xD63F0000)
            {
                return "BLR";
            }
            else if((opcode & FILTER3) == 0x37000000)
            {
                return "TBNZ";
            }
            else if((opcode & FILTER3) == 0x35000000)
            {
                return "CBNZ";
            }
            break;
        case 5:
        case 13:
//            printf("Data processing - register\n");
            if((opcode & FILTER1) == 0x0B200000)
            {
                return "ADD";
            }
            else if((opcode & FILTER1) == 0x4B200000)
            {
                return "SUB";
            }
            else if((opcode & FILTER3) == 0x0B000000)
            {
                return "ADD";
            }
            else if((opcode & FILTER1) == 0x2B200000)
            {
                return "ADDS";
            }
            else if((opcode & FILTER2) == 0x2B000000)
            {
                return "ADDS";
            }
            else if((opcode & FILTER6) == 0x2A0003E0)
            {
                return "MOV";
            }
            else if((opcode & FILTER2) == 0x4B000000)
            {
                return "SUB";
            }
            else if((opcode & FILTERC) == 0x6B20001F)
            {
                return "CMP";
            }
            else if((opcode & FILTERE) == 0x6B00001F)
            {
                return "CMP";
            }
            else if((opcode & FILTER0) == 0x1AC02800)
            {
                return "ASR";
            }
            else if((opcode & FILTER1C) == 0x1B007C00)
            {
                return "MUL";
            }
            else if((opcode & FILTER0) == 0x1AC02400)
            {
                return "LSR";
            }
            else if((opcode & FILTER3) == 0x2A000000)
            {
                return "ORR";
            }
            else if((opcode & FILTER2) == 0x0A000000)
            {
                return "AND";
            }
            break;
        case 7:
        case 15:
//            printf("Data processing - SIMD and floating point\n");
            if((opcode & FILTER0) == 0x1A000000)
            {
                return "ADC";
            }
            else if((opcode & FILTER0) == 0x3A000000)
            {
                return "ADCS";
            }
            else if((opcode & FILTERB) == 0x7E200000)
            {
                return "SUB";
            }
            else if((opcode & FILTER1D) == 0x1E202800)
            {
                return "FADD";
            }
            else if((opcode & FILTER1E) == 0x1E201000)
            {
                return "FMOV";
            }
            else if((opcode & FILTER16) == 0x5E000400)
            {
                return "DUP";
            }
            else if((opcode & FILTER1F) == 0x0F00A400)
            {
                return "SXTL";
            }
            else if((opcode & FILTER21) == 0x0F000400)
            {
                return "MOVI";
            }
            break;
        default:
            break;
    }

    return "invalid";
}
