/* Copyright (c) 2008-2015 Eugene Zharkov
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

   * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

   * Neither the name of the copyright holders nor the names of
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#define VERSION "32"

/* HISTORY
150619 V32. Different prologue/epilogue on parts with 8-bit RAM address.
141003 V31. FIX141003A: Yet another stack allocation pattern.
140402 V30.
     - FIX140402C: The setup for epilogue call changed a bit.
     - FIX140402B: New icall location within fputc.
     - FIX140402A: Xmega prologue/epilogue are slightly different.
140319 V29.
     - Another __tablejump2__pattern.
140121 Do not report unreached padding bytes at the end of data blocks.
140119 V28.
     - FIX140119A: Yet another ijmp pattern.
     - Cosmetic: moved most of stack/ijmp stuff from cpu to arch.
     - Implemented __tablejump2__ (GNU_Toolchain_3.4.3).
140118 FIX140118A: New stack initialization pattern in GNU_Toolchain_3.4.3.
131117 V27.
     - Added version number to RRR message.
     - Added -includeBadInterrupt (joeymorin@avrfreaks).
131114 FIX131114A: Something to do with longjmp.
130913 V26. FIX130913A: Don't check AVR's elf.e_flags.
130831 V25. FIX130831A: push-push-ret is used instead of ijmp.
130816 V24. FIX130816A: Do not look for interrupt vectors in data block.
130409 V23. FIX130406A: Added yet another ijmp pattern.
121218 V22.
     - CPSE.
121201 V21.
     - FIX121201A: Fixed args.format.
121028 V20.
     - Added -iCall=fputc and -wrap0 suggestions.
     - FIX121028A: "Total RAM usage=" -> "TotalData:".
121014 V19. FIX121014: Accept all E_AVR_MACH_XMEGA types.
121002 V18. FIX121002: Increased ijmp table size.
120704 V17.
     - More xmega stack alloc/dealloc patterns.
120411 V16.
120325 Added -totalOnly.
     - FI120305 Added E_AVR_MACH_XMEGA5=105.
111224 V15.
     - Error if call from vector. Use -allowCallsFromIsr to disable.
110810 Removed old sim stuff from cpu.c.
     - FIX110810A: Take care of the extra stuff before ijmp.
     - Replaced -nowrap0 with -wrap0.
     - Allow wrap0 rcall.
110707 V14.
     - Added iCall.
     - Added selective ignoreICall.
     - Fixed mazeBuildBlockList with F_stack|F_ret.
     - qmatrix epiloque.
     - More generic cpu_analyzeStackChangeCodeSection.
110106 V13.
     - Allow longer arch_epilogue.
100614 V12.
     - Added -ignoreICall.
100526 Added -nowrap0.
100524 V11.
     - Rjmp addresses can wrap across 0, again.
100522 V10.
100516 Implemented prologue/epilogue.
     - Implemented setjmp/longjmp.
100515 V9. Major revision.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#define ARRAYSIZE(x) (sizeof (x) / sizeof (x[0]))

typedef enum { false = 0, true } Bool;
typedef unsigned char Uint8;
typedef unsigned short Uint16;
typedef unsigned int Uint32;
typedef signed char Int8;
typedef signed short Int16;
typedef signed int Int32;

static void rrrva(char* file, int line, char* format, ...) {
  va_list vl;
  va_start(vl, format);
  fflush(stdout);
  perror("rrr");
  printf("%s:%d: v" VERSION " error", file, line);
  if (format != NULL) {
    printf(", ");
    vprintf(format, vl);
  }
  printf("\n");
  va_end(vl);
  exit(EXIT_FAILURE);
}

#define RRR() rrr(__FILE__, __LINE__)
#define RRRA(addr) rrra(__FILE__, __LINE__, addr)

static void rrr(char* file, int line) {
  rrrva(file, line, NULL);
}

static void rrra(char* file, int line, unsigned addr) {
  rrrva(file, line, "addr=0x%x\n", addr);
}

#define TRACE() do {				\
  printf("%s:%u: trace\n", __FILE__, __LINE__);	\
  fflush(stdout);				\
} while (0)

unsigned badInterrupt; 

enum {
  FE_999 = 999,
  /*1000*/ FE_retiExpected,
  /*1001*/ FE_retiUnexpected,
  /*1002*/ FE_stackChangeLoop,
  /*1003*/ FE_negativeStackChange,
  /*1004*/ FE_recursion,
  /*1005*/ FE_callFromIsr,
};

static void fePrintf(unsigned code, char* format, ...) {
  va_list vl;
  va_start(vl, format);
  printf("Error C%u", code);
  if (format != NULL)
    vprintf(format, vl);
  printf("\n");
  va_end(vl);
  exit(EXIT_FAILURE);
}

static void fe(unsigned code, unsigned addr) {
  fePrintf(code, " @ %x", addr);
}

typedef struct {
  unsigned srcOffset;
  unsigned dstCount;
  char* src;
  char** dst;
} MainICall;

static struct {
  unsigned format;
  char* name;
  Bool allowCallsFromIsr;
  Bool mcuSpecified;
  Bool wrap0;
  Bool includeBadInterrupt;
  Bool ignoreICallAll;
  Bool totalOnly;
  MainICall* iCallList;
  unsigned iCallListSize;
} args;

void myFree(void* ptr) {
  if (ptr != NULL)
    free(ptr);
}

static void* myMalloc(unsigned size) {
  void* ptr = malloc(size);
  if (size == 0) RRR();
  if (ptr == NULL) RRR();
  return ptr;
}

void* myMalloc0(unsigned size) {
  void* ptr = calloc(1, size);
  if (size == 0) RRR();
  if (ptr == NULL) RRR();
  return ptr;
}

void* myRealloc(void* ptr, unsigned size) {
  if ((ptr = realloc(ptr, size)) == NULL) RRR();
  if (size == 0) RRR();
  return ptr;
}

char* myStrdup(char* string) {
  char* retval = strdup(string);
  if (retval == NULL) RRR();
  return retval;
}
typedef unsigned CpuAddr;
typedef struct Cpu Cpu;
typedef void CpuExecFunc(void);
typedef void CpuParseFunc(void);

typedef struct {
  CpuParseFunc* parseFunc;
  CpuExecFunc* execFunc;
  char* mn;
  Bool op32;
} CpuInstr;

typedef struct {
  CpuAddr src;
  CpuAddr* dst;
  unsigned dstCount;
} CpuICallListEntry;

typedef struct {
  unsigned size;
  CpuICallListEntry* ptr;
} CpuICallList;

struct {
  CpuInstr instrArray[100];
  unsigned instrArrayUsed;

  CpuInstr* instr[0x10000];
  unsigned flags;

  CpuAddr pc;
  CpuAddr pcPrev;
  CpuAddr pcAtFirstStackOut;
  CpuAddr jumpTo2[256]; // FIX121002: Was 128.

  unsigned bProgSize;
  unsigned iProgSize;
  unsigned iProgSizeM2; // Lowest multiple of 2 >= iProgSize.
  unsigned ramStart;
  unsigned opcode;
  unsigned opcode2; // If Instr->op32.

  unsigned bigA;
  unsigned bigK;
  unsigned bbb;
  unsigned k;
  unsigned rd;
  unsigned rr;
  unsigned q;
  unsigned sss;

  Uint8* prog;
  int stackChange;

  Bool wrap0;

  CpuICallList* icall;
  CpuAddr parseHistory[5];

  struct {
    unsigned tableSize;
    unsigned dataSize;
    unsigned addr;
  } ijmp;

} cpu;

#define CPU_minInstrSize 2

#define CPU_F_stack		0x004
#define CPU_F_call		0x008
#define CPU_F_condJump		0x010
#define CPU_F_uncondJump	0x020
#define CPU_F_ret		0x040
#define CPU_F_instr		0x080
#define CPU_F_ijmp		0x100
#define CPU_F_reti		0x200
#define CPU_F_longjmp		0x400
#define CPU_F_unknownDest	0x800

#define CPU_FF_flow (0				\
  | CPU_F_ret					\
  | CPU_F_call					\
  | CPU_F_ijmp					\
  | CPU_F_condJump				\
  | CPU_F_uncondJump				\
)

#define addrSignExtend7(x) ((x) & 0x40 ? (x) | 0xffffff80 : (x))
#define addrSignExtend12(x) ((x) & 0x800 ? (x) | 0xfffff000 : (x))

#define CPURRR() cpu_rrr(__FILE__, __LINE__, cpu.pcPrev)
#define CPURRRA(addr) cpu_rrr(__FILE__, __LINE__, addr)
static void cpu_rrr(char* file, int line, CpuAddr addr) {
  rrrva(file, line, "cpu.pc = 0x%x\n", addr * CPU_minInstrSize);
}

static unsigned getPc16(void) {
  return cpu.pc;
}
  
static unsigned fetch8(unsigned pc8) {
  return cpu.prog[pc8];
}

static unsigned fetch16(void) {
  unsigned pc8 = cpu.pc * CPU_minInstrSize;
  if (cpu.pc++ >= cpu.iProgSize) RRR();
  return fetch8(pc8) + fetch8(pc8 + 1) * 256;
}

static void defineInstr(CpuExecFunc* execFunc,
			char* opcodeStringArg,
			char* mn,
			CpuParseFunc* parseFunc,
			Bool op32) {

  unsigned varPos[16];
  unsigned numVarPos = 0;
  char opcodeString[4 * 4 + 1];
  unsigned opcode = 0;
  CpuInstr* instr;
  int i;

  if (cpu.instrArrayUsed >= ARRAYSIZE(cpu.instrArray)) RRR();
  instr = cpu.instrArray + cpu.instrArrayUsed++;
  instr->parseFunc = parseFunc;
  instr->execFunc = execFunc;
  instr->op32 = op32;
  instr->mn = mn;

  if (strlen(opcodeStringArg) != 4 * 4 + 3) RRR();

  memcpy(opcodeString +  0, opcodeStringArg + 0, 4);
  memcpy(opcodeString +  4, opcodeStringArg + 5, 4);
  memcpy(opcodeString +  8, opcodeStringArg + 10, 4);
  memcpy(opcodeString + 12, opcodeStringArg + 15, 4);
  opcodeString[sizeof opcodeString - 1] = 0;

  for (i = 0; i < 16; i++) {
    if (i != 0)
      opcode <<= 1;
    if (opcodeString[i] == '1')
      opcode |= 1;
    else if (opcodeString[i] != '0')
      varPos[numVarPos++] = 15 - i;
  }

  for (i = 0; i < (1 << numVarPos); i++) {
    unsigned x = 0;
    unsigned j;
    for (j = 0; j < numVarPos; j++)
      if (i & (1 << j))
	x |= (1 << varPos[j]);
    if (opcode + x >= 0x10000) {
      unsigned k;
      for (k = 0; k < numVarPos; k++) {
	printf("vp[%d]=%x\n", k, varPos[k]);
      }
      printf("numVarPos=%d\n", numVarPos);
      printf("Line %d %x %x %x\n", __LINE__, opcode, x, opcode + x); fflush(stdout);
      RRR();
    }
    x += opcode;

    if (cpu.instr[x] != NULL) {
      printf("%04x is already defined %s %s\n", x, opcodeStringArg, mn);
      RRR();
    }
    cpu.instr[x] = instr;
  }
}

static void cpuParse_instrNotImplemented(void) {}
static void cpuExec_instrNotImplemented(void) {}
static void cpuParse_none(void) {}

static void cpuParse_AAr_rrrr_AAAA(void) {
  cpu.rr = (cpu.opcode & 0x1f0) >> 4;
  cpu.bigA = (cpu.opcode & 0x0f) | ((cpu.opcode & 0x600) >> 5);
}

static void cpuParse_AAd_dddd_AAAA(void) {
  cpu.rd = (cpu.opcode & 0x1f0) >> 4;
  cpu.bigA = (cpu.opcode & 0x0f) | ((cpu.opcode & 0x600) >> 5);
}

static void cpuParse_AAAA_Abbb(void) {}

static void cpuParse_sss_0000(void) {
  cpu.sss = (cpu.opcode & 0x70) >> 4;
}

static void cpuParse_d_dddd_0000(void) {
  cpu.rd = (cpu.opcode & 0x1F0) >> 4;
}

static void cpuParse_2dddd_rrrr(void) {
  cpu.rd = ((cpu.opcode & 0xf0) >> 4) * 2;
  cpu.rr = (cpu.opcode & 0x0f) * 2;
}

static void cpuParse_kk_kkkk_ksss(void) {
  cpu.k = (cpu.opcode & 0x3F8) >> 3;
  cpu.k = addrSignExtend7(cpu.k);
  cpu.sss = cpu.opcode & 0x7;
}

static void cpuParse_KKdd_KKKK(void) {
  cpu.bigK = (cpu.opcode & 0x0F) | ((cpu.opcode & 0xC0) >> 2);
  cpu.rd = (((cpu.opcode & 0x30) >> 4) * 2) + 24;
}

static void cpuParse_k_kkkk_000k_kkkk_kkkk_kkkk_kkkk(void) {
  unsigned addr = cpu.opcode;
  addr = (addr & 1) | ((addr & 0x1f0) >> 3);
  cpu.k = (addr << 16) | cpu.opcode2;
}

static void cpuParse_KKKK_dddd_KKKK(void) {
  cpu.bigK = (cpu.opcode & 0xF) | ((cpu.opcode & 0xF00) >> 4);
  cpu.rd = ((cpu.opcode & 0xF0) >> 4) + 16;
  //printf("opcode=%x rd=%d\n", cpu.opcode, cpu.rd);
}

static void cpuParse_kkkk_kkkk_kkkk(void) {
  cpu.k = cpu.opcode & 0x0fff;
  cpu.k = addrSignExtend12(cpu.k);
}

static void cpuParse_r_rrrr_0bbb(void) {
  cpu.rr = (cpu.opcode & 0x1F0) >> 4;
  cpu.bbb = cpu.opcode & 0x7;
}

static void cpuParse_rd_dddd_rrrr(void) {
  unsigned op = cpu.opcode;
  cpu.rd = (op & 0x1F0) >> 4;
  cpu.rr = (op & 0x0F) | (op & 0x200 ? 0x10 : 0x00);
}

static CpuAddr cpu_wrap0(CpuAddr addr) {
  if (! cpu.wrap0) {
    printf("pc=%x\n", cpu.pc * 2);
    printf("addr=%x\n", addr);
    printf("suggest -wrap0 option\n");
    RRR();
  }
  addr &= cpu.iProgSizeM2 - 1;
  if (addr >= cpu.iProgSize) RRR();
  return addr;
}

static void cpu_uncondJump(CpuAddr addr) {
  if (addr >= cpu.iProgSize)
    addr = cpu_wrap0(addr);
  cpu.pc = addr;
  cpu.flags |= CPU_F_uncondJump;
}

static void cpu_condJump(CpuAddr addr) {
  cpu.jumpTo2[0] = addr;
  if (addr >= cpu.iProgSize) RRR();
  cpu.flags |= CPU_F_condJump;
}

static void jmp_1001_010k_kkkk_110k(void) {
  if (cpu.k >= cpu.iProgSize) RRR();
  cpu_uncondJump(cpu.k);
}

#define CPU_stackPort 0x3d

static void cpuExec_noSuchInstr(void) {
  printf("%x %04x\n", cpu.pcPrev * CPU_minInstrSize, cpu.opcode);
  RRR();
}

static void cpuStack(int change) {
  cpu.stackChange = change;
  cpu.flags |= CPU_F_stack;
  if (cpu.pcAtFirstStackOut == 0) {
    cpu.pcAtFirstStackOut = cpu.pcPrev;
    if (change != 0) RRR();
  }
}

static void cpuRet(void) { cpu.flags |= CPU_F_ret; } // LNK.undoCpuRet
static void cpuReti(void) { cpu.flags |= CPU_F_ret | CPU_F_reti; }

static void cpu_call(CpuAddr addr) {
  if (addr >= cpu.iProgSize)
    addr = cpu_wrap0(addr);
  cpu.jumpTo2[0] = addr;
  cpu.flags |= CPU_F_call;
}

static CpuAddr cpu_getNextAddr(void) {
  CpuAddr pcSaved = cpu.pc;
  CpuAddr retval;
  unsigned opcode = fetch16();
  CpuInstr* instr  = cpu.instr[opcode];
  if (instr == NULL) RRR();
  if (instr->op32)
    fetch16();
  retval = cpu.pc;
  cpu.pc = pcSaved;
  return retval;
}

static void cpu_addToParseHistory(CpuAddr pcPrev) {
  unsigned i;
  for (i = 1; i < ARRAYSIZE(cpu.parseHistory); i++) {
    unsigned x = ARRAYSIZE(cpu.parseHistory) - i;
    cpu.parseHistory[x] = cpu.parseHistory[x - 1];
  }
  cpu.parseHistory[0] = pcPrev;
}

static unsigned cpu_parseAndExec(unsigned addr, Bool exec) {
  CpuInstr* instr;
  unsigned n = 2;
  cpu.flags = 0;
  if ((addr & 1) != 0) RRR();
  cpu.pc = addr / CPU_minInstrSize;
  cpu.pcPrev = cpu.pc;
  cpu.opcode = fetch16();
  cpu_addToParseHistory(cpu.pcPrev);
  instr = cpu.instr[cpu.opcode];
  if (instr != NULL) {
    cpu.flags |= CPU_F_instr;
    //printf("cpu line %d\n", __LINE__); fflush(stdout);
    if (instr->op32) {
      cpu.opcode2 = fetch16();
      n += 2;
    }
    instr->parseFunc();
    //printf("Parse %x %s\n", cpu.pcPrev * CPU_minInstrSize, instr->mn); fflush(stdout);
    if (exec)
      instr->execFunc();
  }
  return n;
}

static Bool cpu_isInstr(CpuAddr iAddr, char* mn) {
  CpuInstr* instr;
  cpu_parseAndExec(iAddr * CPU_minInstrSize, false);
  instr = cpu.instr[cpu.opcode];
  if (instr == NULL) CPURRRA(iAddr);
  //printf("isInstr %x %s\n", iAddr * CPU_minInstrSize, instr->mn);
  return strcmp(instr->mn, mn) == 0;
}

static Bool cpu_isInstr_rd(CpuAddr addr, char* mn, unsigned rd) {
  return cpu_isInstr(addr, mn) && cpu.rd == rd;
}
static Bool cpu_isInstr_rdrr(CpuAddr addr, char* mn, unsigned rd, unsigned rr) {
  return cpu_isInstr(addr, mn)
    && cpu.rd == rd
    && cpu.rr == rr;
}

static Bool cpu_isInstr_rdBigK(CpuAddr iAddr, char* mn,
			       unsigned rd, unsigned* value) {
  if (cpu_isInstr(iAddr, mn) && cpu.rd == rd) {
    *value = cpu.bigK;
    return true;
  }
  return false;
}

static Bool cpu_isInstr_rjmp(CpuAddr addr, unsigned* addrPtr) {
  if (addrPtr != NULL) RRR();
  return cpu_isInstr(addr, "rjmp");
}
static Bool cpu_isInstr_rcall(CpuAddr addr, unsigned* addrPtr) {
  if (addrPtr != NULL) RRR();
  return cpu_isInstr(addr, "rcall");
}

static Bool cpu_isInstr_jmp(CpuAddr addr, unsigned* addrPtr) {
  if (addrPtr != NULL) RRR();
  return cpu_isInstr(addr, "jmp");
}
static Bool cpu_isInstr_call(CpuAddr addr, unsigned* addrPtr) {
  if (addrPtr != NULL) RRR();
  return cpu_isInstr(addr, "call");
}

static Bool cpu_isInstr_brcc(CpuAddr addr, unsigned* addrPtr) {
  if (addrPtr != NULL) RRR();
  return cpu_isInstr(addr, "brbc") && cpu.sss == 0;
}

static Bool cpu_isInstr_brcs(CpuAddr addr, unsigned* addrPtr) {
  if (addrPtr != NULL) RRR();
  return cpu_isInstr(addr, "brbs") && cpu.sss == 0;
}

static Bool cpu_isInstr_adiw(CpuAddr addr, unsigned rd, unsigned* value) {
  return cpu_isInstr_rdBigK(addr, "adiw", rd, value);
}
static Bool cpu_isInstr_cpi(CpuAddr addr, unsigned rd, unsigned* value) {
  return cpu_isInstr_rdBigK(addr, "cpi", rd, value);
}
static Bool cpu_isInstr_ldi(CpuAddr iAddr, unsigned rd, unsigned* value) {
  return cpu_isInstr_rdBigK(iAddr, "ldi", rd, value);
}
static Bool cpu_isInstr_sbci(CpuAddr addr, unsigned rd, unsigned* value) {
  return cpu_isInstr_rdBigK(addr, "sbci", rd, value);
}
static Bool cpu_isInstr_sbiw(CpuAddr addr, unsigned rd, unsigned* value) {
  return cpu_isInstr_rdBigK(addr, "sbiw", rd, value);
}
static Bool cpu_isInstr_subi(CpuAddr addr, unsigned rd, unsigned* value) {
  return cpu_isInstr_rdBigK(addr, "subi", rd, value);
}

static Bool cpu_isInstr_in(CpuAddr addr, unsigned rd, unsigned bigA) {
  return cpu_isInstr(addr, "in")
    && cpu.rd == rd
    && cpu.bigA == bigA;
}

static Bool cpu_isInstr_cli(CpuAddr addr) {
  return cpu_isInstr(addr, "bclr") && cpu.sss == 7;
}

static Bool cpu_isInstr_outN(CpuAddr iAddr, unsigned rr, unsigned bigA) {
  return (cpu_isInstr(iAddr, "out")
	  && cpu.bigA == bigA
	  && cpu.rr == rr);
}

static Bool cpu_isInstr_outX(CpuAddr addr, unsigned* rx, unsigned bigA) {
  if (cpu_isInstr(addr, "out")
      && cpu.bigA == bigA) {
    *rx = cpu.rr;
    return true;
  }
  return false;
}

static Bool cpu_isInstr_adc(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "adc", rd, rr);
}
static Bool cpu_isInstr_add(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "add", rd, rr);
}
static Bool cpu_isInstr_cpc(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "cpc", rd, rr);
}
static Bool cpu_isInstr_eor(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "eor", rd, rr);
}
static Bool cpu_isInstr_mov(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "mov", rd, rr);
}
static Bool cpu_isInstr_sbc(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "sbc", rd, rr);
}
static Bool cpu_isInstr_movw(CpuAddr addr, unsigned rd, unsigned rr) {
  return cpu_isInstr_rdrr(addr, "movw", rd, rr);
}
static Bool cpu_isInstr_movw_rrx(CpuAddr addr, unsigned rd, unsigned* rr) {
  if (! cpu_isInstr(addr, "movw"))
    return false;
  if (cpu.rd != rd)
    return false;
  *rr = cpu.rr;
  return true;
}

static Bool cpu_isInstr_lpm(CpuAddr addr, unsigned rd) {
  return cpu_isInstr_rd(addr, "lpm", rd);
}
static Bool cpu_isInstr_lpmP(CpuAddr addr, unsigned rd) {
  return cpu_isInstr_rd(addr, "lpmP", rd);
}

static Bool cpu_isInstr_push(CpuAddr addr, unsigned* reg) {
  if (! cpu_isInstr(addr, "push"))
    return false;
  *reg = cpu.rd;
  return true;
}

static Bool cpu_isInstrDoesNotTouchZ(CpuAddr addr) {
  if (cpu_isInstr(addr, "mov")) {
    if (cpu.rd < 30)
      return true;
  }
  else if (cpu_isInstr(addr, "subi")) {
    if (cpu.rd < 30)
      return true;
  }
  return false; // We just don't know.
}

static void adiw_1001_0110_KKdd_KKKK(void) {}
static void bclr_1001_0100_1sss_1000(void) {}

static void brbc_1111_01kk_kkkk_ksss(void) {
  CpuAddr addr = cpu.pc + cpu.k;
  cpu_condJump(addr);
}

static void brbs_1111_00kk_kkkk_ksss(void) {
  CpuAddr addr = cpu.pc + cpu.k;
  cpu_condJump(addr);
}

static void call_1001_010k_kkkk_111k(void) {
  CpuAddr addr = cpu.k;
  cpu_call(addr);
}

static void eicall_1001_0101_0001_1001(void) { RRR(); }

Bool cpuIsUnknownICall(unsigned addr) {
  CpuICallList* t = cpu.icall;
  if (t != NULL) {
    unsigned i;
    for (i = 0; i < t->size; i++) {
      CpuICallListEntry* e = t->ptr + i;
      if (e->src == addr && e->dstCount == 0)
	return true;
    }
  }
  return false;
}

static void icall_1001_0101_0000_1001(void) {
  CpuICallList* t = cpu.icall;
  if (t != NULL) {
    unsigned i;
    for (i = 0; i < t->size; i++) {
      CpuICallListEntry* e = t->ptr + i;
      if (e->src == cpu.pcPrev * CPU_minInstrSize) {
	if (e->dstCount > 1) RRR();
	if (e->dstCount == 0)
	  break;
	cpu_call(e->dst[0] / CPU_minInstrSize);
	return;
      }
    }
  }
  cpu_call(cpu.pcPrev);
  cpu.flags |= CPU_F_unknownDest;
}

static void eijmp_1001_0100_0001_1001(void) { RRR(); }

static void ijmp_1001_0100_0000_1001(void) {
  cpu.flags |= CPU_F_ijmp;
}

static void in_1011_0AAd_dddd_AAAA(void) {}

static void ldi_1110_KKKK_dddd_KKKK(void) {}

static void out_1011_1AAr_rrrr_AAAA(void) {
  if (cpu.bigA == CPU_stackPort ||
      cpu.bigA == CPU_stackPort + 1) {
    cpuStack(0);
  }
}

static void pop_1001_000d_dddd_1111(void) { cpuStack(-1); }
static void push_1001_001d_dddd_1111(void) { cpuStack(1); }

static void rcall_1101_kkkk_kkkk_kkkk(void) {
  CpuAddr addr = cpu.k;
  if (cpu.k != 0)
    cpu_call(addr + getPc16());
  else
    cpuStack(2); // gcc uses 'rcall .+0' to reserve 2 bytes in stack.
}

static void ret_1001_0101_0000_1000(void) {
  cpuRet();
}

static void reti_1001_0101_0001_1000(void) {
  cpuReti();
}

static void rjmp_1100_kkkk_kkkk_kkkk(void) {
  CpuAddr addr = cpu.k;
  addr += getPc16();
  cpu_uncondJump(addr);
}

static void cpse_0001_00rd_dddd_rrrr(void) {
  cpu_condJump(cpu_getNextAddr());
}

static void sbic_1001_1001_AAAA_Abbb(void) {
  cpu_condJump(cpu_getNextAddr());
}

static void sbis_1001_1011_AAAA_Abbb(void) {
  cpu_condJump(cpu_getNextAddr());
}

static void sbiw_1001_0111_KKdd_KKKK(void) {}

static void sbrc_1111_110r_rrrr_0bbb(void) {
  cpu_condJump(cpu_getNextAddr());
}

static void sbrs_1111_111r_rrrr_0bbb(void) {
  cpu_condJump(cpu_getNextAddr());
}

static void sbci_0100_KKKK_dddd_KKKK(void) {}
static void subi_0101_KKKK_dddd_KKKK(void) {}

static void adc_0001_11rd_dddd_rrrr(void) {}
static void sbc_0000_10rd_dddd_rrrr(void) {}
static void add_0000_11rd_dddd_rrrr(void) {}
static void cpc_0000_01rd_dddd_rrrr(void) {}
static void cpi_0011_KKKK_dddd_KKKK(void) {}
static void eor_0010_01rd_dddd_rrrr(void) {}
static void lpm_1001_000d_dddd_0100(void) {}
static void lpmP_1001_000d_dddd_0101(void) {}
static void mov_0010_11rd_dddd_rrrr(void) {}
static void movw_0000_0001_dddd_rrrr(void) {}

static void defineInstructions(void) {

  CpuInstr* noSuchInstr;

#define Y(op, mn, opType, op32)					\
  defineInstr(mn##_##op, #op, #mn, cpuParse_##opType, op32)
#define N(op, mn, opType, op32)					\
  defineInstr(cpuExec_instrNotImplemented,			\
	      #op, #mn, cpuParse_instrNotImplemented, op32)
#define Y1(op, mn, opType) Y(op, mn, opType, false)
#define Y2(op, mn, opType) Y(op, mn, opType, true)
#define N1(op, mn, opType) N(op, mn, opType, false)
#define N2(op, mn, opType) N(op, mn, opType, true)

  Y1(0001_11rd_dddd_rrrr, adc,		  rd_dddd_rrrr);
  Y1(0000_11rd_dddd_rrrr, add,		  rd_dddd_rrrr);
  Y1(1001_0110_KKdd_KKKK, adiw,		     KKdd_KKKK);
  N1(0010_00rd_dddd_rrrr, and,		  rd_dddd_rrrr);
  N1(0111_KKKK_dddd_KKKK, andi,		KKKK_dddd_KKKK);
  N1(1001_010d_dddd_0101, asr,	           d_dddd_0000);
  Y1(1001_0100_1sss_1000, bclr,	              sss_0000);
  N1(1111_100d_dddd_0bbb, bld,	           d_dddd_0bbb);
  Y1(1111_01kk_kkkk_ksss, brbc,	          kk_kkkk_ksss);
  Y1(1111_00kk_kkkk_ksss, brbs,		  kk_kkkk_ksss);
  // brcc - brbc with sss = 0
  // brcs - brbs with sss = 0
  N1(1001_0101_1001_1000, break,		  none);
  // breq - brbs with sss = 1
  // brge - brbc with sss = 4
  // brhc - brbc with sss = 5
  // bres - brbs with sss = 5
  // brid - brbs with sss = 7
  // brie - brbc with sss = 7
  // brlo - brbs with sss = 0
  // brlt - brbs with sss = 4
  // brmi - brbs with sss = 2
  // brne - brbc with sss = 1
  // brpl - brbc with sss = 2
  // brsh - brbc with sss = 0
  // brtc - brbc with sss = 6
  // brvc - brbs with sss = 3
  // brvs - brbs with sss = 3
  N1(1001_0100_0sss_1000, bset,		      sss_0000);
  N1(1111_101d_dddd_0bbb, bst,		   d_dddd_0bbb);
  Y2(1001_010k_kkkk_111k, call, 	   k_kkkk_000k_kkkk_kkkk_kkkk_kkkk);
  N1(1001_1000_AAAA_Abbb, cbi,		     AAAA_Abbb);
  // clc - bclr with sss - 0
  // clh - bclr with sss - 5
  // cli - bclr with sss - 7
  // cln - bclr with sss - 2
  // clr - eor with the same register
  // cls - bclr with sss - 4
  // clt - bclr with sss - 6
  // clv - bclr with sss - 3
  // clz - bclr with sss - 1
  N1(1001_010d_dddd_0000, com,		   d_dddd_0000);
  N1(0001_01rd_dddd_rrrr, cp,		  rd_dddd_rrrr);
  Y1(0000_01rd_dddd_rrrr, cpc,		  rd_dddd_rrrr);
  Y1(0011_KKKK_dddd_KKKK, cpi,	        KKKK_dddd_KKKK);
  Y1(0001_00rd_dddd_rrrr, cpse,	          rd_dddd_rrrr);
  N1(1001_010d_dddd_1010, dec,		   d_dddd_0000);
  N1(1001_0100_KKKK_1011, des,		     KKKK_0000);
  Y1(1001_0101_0001_1001, eicall,	          none);
  Y1(1001_0100_0001_1001, eijmp,		  none);
  N1(1001_0101_1101_1000, elpm1,	          none);
  N1(1001_000d_dddd_0110, elpm2,	   d_dddd_0000);
  N1(1001_000d_dddd_0111, elpm3,	   d_dddd_0000);
  Y1(0010_01rd_dddd_rrrr, eor,		  rd_dddd_rrrr);
  N1(0000_0011_0ddd_1rrr, fmul,		      ddd_0rrr);
  N1(0000_0011_1ddd_0rrr, fmuls,	      ddd_0rrr);
  N1(0000_0011_1ddd_1rrr, fmulsu,	      ddd_0rrr);
  Y1(1001_0101_0000_1001, icall,	          none);
  Y1(1001_0100_0000_1001, ijmp,		          none);
  Y1(1011_0AAd_dddd_AAAA, in,		 AAd_dddd_AAAA);
  N1(1001_010d_dddd_0011, inc,		   d_dddd_0000);
  Y2(1001_010k_kkkk_110k, jmp,		   k_kkkk_000k_kkkk_kkkk_kkkk_kkkk);
  N1(1001_000d_dddd_1100, ld1,		   d_dddd_0000);
  N1(1001_000d_dddd_1101, ld2,		   d_dddd_0000);
  N1(1001_000d_dddd_1110, ld3,		   d_dddd_0000);
  //M(1000_000d_dddd_1000, lddy1, 0);
  N1(1001_000d_dddd_1001, lddy2,	   d_dddd_0000);
  N1(1001_000d_dddd_1010, lddy3,	   d_dddd_0000);
  N1(10q0_qq0d_dddd_1qqq, lddy4,     q0_qq0d_dddd_0qqq);
  //M(1000_000d_dddd_0000, lddz1, 0);
  N1(1001_000d_dddd_0001, lddz2,	   d_dddd_0000);
  N1(1001_000d_dddd_0010, lddz3,	   d_dddd_0000);
  N1(10q0_qq0d_dddd_0qqq, lddz4,     q0_qq0d_dddd_0qqq);
  Y1(1110_KKKK_dddd_KKKK, ldi,		KKKK_dddd_KKKK);
  N2(1001_000d_dddd_0000, lds,		   d_dddd_0000_kkkk_kkkk_kkkk_kkkk);
  N1(1001_0101_1100_1000, lpm0,			  none);
  Y1(1001_000d_dddd_0100, lpm,		   d_dddd_0000);
  Y1(1001_000d_dddd_0101, lpmP,		   d_dddd_0000);
  // lsl - same as add Rd,Rd
  N1(1001_010d_dddd_0110, lsr,		   d_dddd_0000);
  Y1(0010_11rd_dddd_rrrr, mov,		  rd_dddd_rrrr);
  Y1(0000_0001_dddd_rrrr, movw,		    2dddd_rrrr);
  N1(1001_11rd_dddd_rrrr, mul,		  rd_dddd_rrrr);
  N1(0000_0010_dddd_rrrr, muls,		     dddd_rrrr);
  N1(0000_0011_0ddd_0rrr, mulsu,	      ddd_0rrr);
  N1(1001_010d_dddd_0001, neg,		   d_dddd_0000);
  N1(0000_0000_0000_0000, nop,			  none);
  N1(0010_10rd_dddd_rrrr, or,		  rd_dddd_rrrr);
  N1(0110_KKKK_dddd_KKKK, ori,		KKKK_dddd_KKKK);
  Y1(1011_1AAr_rrrr_AAAA, out,		 AAr_rrrr_AAAA);
  Y1(1001_000d_dddd_1111, pop,		   d_dddd_0000);
  Y1(1001_001d_dddd_1111, push,		   d_dddd_0000);
  Y1(1101_kkkk_kkkk_kkkk, rcall,	kkkk_kkkk_kkkk);
  Y1(1001_0101_0000_1000, ret,			  none);
  Y1(1001_0101_0001_1000, reti,			  none);
  Y1(1100_kkkk_kkkk_kkkk, rjmp,		kkkk_kkkk_kkkk);
  // rol - same as adc Rd,Rd
  N1(1001_010d_dddd_0111, ror,		   d_dddd_0000);
  Y1(0000_10rd_dddd_rrrr, sbc,		  rd_dddd_rrrr);
  Y1(0100_KKKK_dddd_KKKK, sbci,		KKKK_dddd_KKKK);
  N1(1001_1010_AAAA_Abbb, sbi,		     AAAA_Abbb);
  Y1(1001_1001_AAAA_Abbb, sbic,		     AAAA_Abbb);
  Y1(1001_1011_AAAA_Abbb, sbis,		     AAAA_Abbb);
  Y1(1001_0111_KKdd_KKKK, sbiw,		     KKdd_KKKK);
  // sbr - same or ori
  Y1(1111_110r_rrrr_0bbb, sbrc,		   r_rrrr_0bbb);
  Y1(1111_111r_rrrr_0bbb, sbrs,		   r_rrrr_0bbb);
  // sec - bset with sss 0
  // seh - bset with sss 5
  // sei - bset with sss 7
  // sen - bset with sss 2
  // ser - ldi 0xFF
  // ses - bset with sss 4
  // set - bset with sss 6
  // sev - bset with sss 3
  // sez - bset with sss 1
  N1(1001_0101_1000_1000, sleep,		  none);
  //M(1001_0101_1110_1000, spm, 0);
  N1(1001_0101_1110_1000, spm2,			  none);
  N1(1001_0101_1111_1000, spm3,			  none);
  N1(1001_001r_rrrr_1100, st1,		   r_rrrr_0000);
  N1(1001_001r_rrrr_1101, st2,		   r_rrrr_0000);
  N1(1001_001r_rrrr_1110, st3,		   r_rrrr_0000);
  //M(1000_001r_rrrr_1000, stdy1, 0);
  N1(1001_001r_rrrr_1001, stdy2,	   r_rrrr_0000);
  N1(1001_001r_rrrr_1010, stdy3,	   r_rrrr_0000);
  N1(10q0_qq1r_rrrr_1qqq, stdy4,     q0_qq0r_rrrr_0qqq);
  //M(1000_001r_rrrr_0000, stdz1, 0);
  N1(1001_001r_rrrr_0001, stdz2,	   r_rrrr_0000);
  N1(1001_001r_rrrr_0010, stdz3,	   r_rrrr_0000);
  N1(10q0_qq1r_rrrr_0qqq, stdz4,     q0_qq0r_rrrr_0qqq);
  N2(1001_001d_dddd_0000, sts,		   d_dddd_0000_kkkk_kkkk_kkkk_kkkk);
  N1(0001_10rd_dddd_rrrr, sub,		  rd_dddd_rrrr);
  Y1(0101_KKKK_dddd_KKKK, subi,		KKKK_dddd_KKKK);
  N1(1001_010d_dddd_0010, swap,		   d_dddd_0000);
  // tst - same as and Rd,Rd
  N1(1001_0101_1010_1000, wdr,			  none);
#undef N1
#undef N2
#undef Y1
#undef Y2
#undef Y
#undef N

  noSuchInstr = cpu.instrArray + cpu.instrArrayUsed++;
  noSuchInstr->parseFunc = cpuParse_none;
  noSuchInstr->execFunc = cpuExec_noSuchInstr;
}

void cpuInit(Uint8* prog, unsigned size, unsigned ramStart) {
  //unsigned size16 = size / 2;
  if (size == 0) RRR();
  if ((size & 1) != 0) RRR();
  memset(&cpu, 0, sizeof cpu);
  cpu.prog = prog;
  cpu.ramStart = ramStart;
  cpu.bProgSize = size;
  cpu.iProgSize = size / CPU_minInstrSize;
  cpu.iProgSizeM2 = 1;
  while (cpu.iProgSizeM2 < cpu.iProgSize)
    cpu.iProgSizeM2 *= 2;
  defineInstructions();
}

Bool cpuIsInstr(void) { return cpu.flags & CPU_F_instr; }
Bool cpuInstrIsLongjmp(void) { return cpu.flags & CPU_F_longjmp; }
Bool cpuInstrIsFlowControl(void) { return (cpu.flags & CPU_FF_flow) != 0; }
Bool cpuInstrIsUncondJump(void) { return (cpu.flags & CPU_F_uncondJump) != 0; }
Bool cpuInstrIsCondJump(void) { return (cpu.flags & CPU_F_condJump) != 0; }
Bool cpuInstrIsIjmp(void) { return (cpu.flags & CPU_F_ijmp) != 0; }
Bool cpuInstrIsCall(void) { return (cpu.flags & CPU_F_call) != 0; }
Bool cpuInstrIsCallUnknown(void) {
  return (cpu.flags & CPU_F_unknownDest) != 0;
}
Bool cpuInstrIsRet(void) { return (cpu.flags & CPU_F_ret) != 0; }
Bool cpuInstrIsStackChange(void) { return (cpu.flags & CPU_F_stack) != 0; }
int cpuGetStackChange(void) { return cpu.stackChange; }
unsigned cpuGetIjmpTableSize(void) { return cpu.ijmp.tableSize; }
unsigned cpuGetIjmpDestAddr(unsigned i) {
  return cpu.jumpTo2[i] * CPU_minInstrSize;
}
unsigned cpuGetIjmpTableDataSize(void) {
  return cpu.ijmp.dataSize * CPU_minInstrSize;
}
unsigned cpuGetIjmpTableDataAddr(void) {
  return cpu.ijmp.addr * CPU_minInstrSize;
}
unsigned cpuGetProgSize(void) { return cpu.bProgSize; }
unsigned cpuGetDestAddr(void) { return cpu.jumpTo2[0] * CPU_minInstrSize; }
unsigned cpuGetPC(void) { return cpu.pc * CPU_minInstrSize; }
unsigned cpuGetCallStackDepth(void) { return 2; }

// Returns number of bytes parsed.
unsigned cpuParse(unsigned addr) {
  return cpu_parseAndExec(addr, true);
}
#define ELF_SHN_UNDEF	0
#define ELF_SHT_SYMTAB	2
#define ELF_SHT_STRTAB	3
#define ELF_STB_WEAK	2
#define ELF_STT_OBJECT	1

#define ELF_EI_NIDENT 16

typedef Uint32 Elf32_Addr;
typedef Uint32 Elf32_Off;
typedef Uint16 Elf32_Half;
typedef Uint32 Elf32_Word;
typedef Int32 Elf32_Sword;

typedef struct {
  Uint8   e_ident[ELF_EI_NIDENT];
  Elf32_Half      e_type;
  Elf32_Half      e_machine;
  Elf32_Word      e_version;
  Elf32_Addr      e_entry;
  Elf32_Off       e_phoff;
  Elf32_Off       e_shoff;
  Elf32_Word      e_flags;
  Elf32_Half      e_ehsize;
  Elf32_Half      e_phentsize;
  Elf32_Half      e_phnum;
  Elf32_Half      e_shentsize;
  Elf32_Half      e_shnum;
  Elf32_Half      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
  Elf32_Word	sh_name;
  Elf32_Word	sh_type;
  Elf32_Word	sh_flags;
  Elf32_Addr	sh_addr;
  Elf32_Off	sh_offset;
  Elf32_Word	sh_size;
  Elf32_Word	sh_link;
  Elf32_Word	sh_info;
  Elf32_Word	sh_addralign;
  Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct {
  Elf32_Word	st_name;
  Elf32_Addr	st_value;
  Elf32_Word	st_size;
  unsigned char	st_info;
  unsigned char	st_other;
  Elf32_Half	st_shndx;
} Elf32_Sym;

typedef struct {
  unsigned size;
  unsigned addr;
  char* name;
  int type; // 'c' - code, 'd' - data
} ElfSymbol;

typedef struct {
  Elf32_Shdr header;
  void* data;
  char* name;
} ElfSection;

static struct {
  ElfSection* section;
  ElfSection* textSection;
  ElfSymbol* symbol;
  Elf32_Ehdr header;
  unsigned numSymbols;
  unsigned bssAndDataSize;
  unsigned ramStart;
  FILE* file;
  Bool isArm;
  Bool isAvr;
} elf;

static void elfRead(void* buffer, unsigned n) {
  FILE* file = elf.file;
  int status = fread(buffer, 1, n, file);
  if (status != (int) n) {
    if (status != 0) {
      printf("status = %d\n", status);
      RRR();
    }
    if (ferror(file)) RRR();
    if (! feof(file)) RRR();
    printf("EOF\n");
    exit(EXIT_SUCCESS);
  }
}

static void elfSeek(unsigned pos) {
  if (fseek(elf.file, pos, SEEK_SET) != 0) RRR();
}

static void elfSeekSection(ElfSection* h) {
  elfSeek(h->header.sh_offset);
}

static ElfSection* elfFindSectionByName(char* name) {
  unsigned i;
  for (i = 0; i < elf.header.e_shnum; i++) {
    ElfSection* s = elf.section + i;
    if (strcmp(s->name, name) == 0)
      return s;
  }
  return NULL;
}

static ElfSection* elfGetSectionByIndex(unsigned index) {
  ElfSection* retval = NULL;
  if (index < elf.header.e_shnum)
    retval = elf.section + index;
  return retval;
}

static void elfReadSectionHeader(ElfSection* h) {
  elfRead(&h->header, sizeof h->header);

}

static void elfReadSectionHeaders(void) {
  unsigned i;
  elf.section = myMalloc0(elf.header.e_shnum * sizeof elf.section[0]);
  elfSeek(elf.header.e_shoff);
  for (i = 0; i < elf.header.e_shnum; i++)
    elfReadSectionHeader(elf.section + i);
}

static void elfReadSectionData(ElfSection* h) {
  unsigned size = h->header.sh_size;
  if (h->data != NULL) RRR();
  if (size == 0) RRR();
  h->data = myMalloc(size);
  elfSeekSection(h);
  elfRead(h->data, size);
}

static void elfReadShstrtab(void) {

  ElfSection* s;
  unsigned i = elf.header.e_shstrndx;
  unsigned strtabSize;
  char* strtab;

  if (i >= elf.header.e_shnum) RRR();
  s = elf.section + i;
  if (s->header.sh_type != ELF_SHT_STRTAB) RRR();
  strtabSize = s->header.sh_size;
  elfReadSectionData(s);
  strtab = s->data;

  for (i = 0; i < elf.header.e_shnum; i++) {
    s = elf.section + i;
    if (s->header.sh_name >= strtabSize) RRR();
    s->name = strtab + s->header.sh_name;

  }
}

static ElfSection* elfReadText(void) {
  ElfSection* h = elfFindSectionByName(".text");
  if (h == NULL) RRR();
  elfReadSectionData(h);
  return h;
}

static void elfReadSymbolTable(void) {

  ElfSection* strtab;
  ElfSection* symtab = elfFindSectionByName(".symtab");
  unsigned symbolTableSize;
  unsigned i;

  if (symtab == NULL) RRR();
  if ((strtab = elfFindSectionByName(".strtab")) == NULL) RRR();
  elfReadSectionData(strtab);

  symbolTableSize = symtab->header.sh_size / symtab->header.sh_entsize;
  if (symbolTableSize == 0) RRR();
  elf.symbol = myMalloc0(symbolTableSize * sizeof(ElfSymbol));
  elf.numSymbols = 0; // Count only ones that we need.
  elfSeek(symtab->header.sh_offset);
  for (i = 0; i < symbolTableSize; i++) {
    ElfSymbol* sym = elf.symbol + elf.numSymbols;
    Elf32_Sym raw;
    elfRead(&raw, sizeof raw);
    if ((raw.st_other & 0xFFFC) != 0) RRR();
    if (raw.st_name != 0) {
      ElfSection* symsec = elfGetSectionByIndex(raw.st_shndx);
      char* name;
      if (raw.st_name >= strtab->header.sh_size) RRR();
      name = (char*) strtab->data + raw.st_name;
      if (symsec != NULL && strcmp(symsec->name, ".text") == 0) {
	if ((raw.st_info & 0xf) == ELF_STT_OBJECT) {
	  if (raw.st_size != 0) {
	    sym->size = raw.st_size;
	    sym->type = 'd';
	  }
	}
	else {
	  if ((raw.st_info >> 4) != ELF_STB_WEAK)
	    sym->type = 'c';
	}
	if (sym->type != 0) {
	  elf.numSymbols++;
	  sym->name = name;
	  sym->addr = raw.st_value;

	}
      }
    }
  }
}

ElfSymbol* elfGetSymbolByAddr(unsigned addr) {
  unsigned i;
  for (i = 0; i < elf.numSymbols; i++) {
    ElfSymbol* s = elf.symbol + i;
    if (s->addr == addr)
      return s;
  }
  return NULL;
}

char* elfAddrToName(unsigned addr) {
  ElfSymbol* s = elfGetSymbolByAddr(addr);
  if (s == NULL) {
     
    char b[16];
    sprintf(b, "0x%x", addr);
    return myStrdup(b);
  }
  return s->name;
}

ElfSymbol* elfFindSymbolByName(char* name) {
  unsigned i;
  for (i = 0; i < elf.numSymbols; i++) {
    ElfSymbol* s = elf.symbol + i;
    if (strcmp(s->name, name) == 0)
      return s;
  }
  return NULL;
}

static void elfReadHeader(void) {
  Elf32_Ehdr* h = &elf.header;
  elfRead(h, sizeof *h);
  if (h->e_ident[0] != 0x7F) RRR();
  if (h->e_ident[1] != 'E') RRR();
  if (h->e_ident[2] != 'L') RRR();
  if (h->e_ident[3] != 'F') RRR();
  if (h->e_ident[4] != 1) RRR(); // EI_CLASS = ELFCLASS32
  if (h->e_ident[5] != 1) RRR(); // EI_DATA = ELFDATA2LSB
  if (h->e_ident[6] != 1) RRR(); // EI_VERSION = EV_CURRENT
  if (h->e_ident[7] != 0) RRR(); // EI_OSABI = ELFOSABI_NONE
  if (h->e_ident[8] != 0) RRR(); // EI_ABIVERSION
  if (h->e_ident[9] != 0) RRR(); // PAD
  if (h->e_ident[10] != 0) RRR();
  if (h->e_ident[11] != 0) RRR();
  if (h->e_ident[12] != 0) RRR();
  if (h->e_ident[13] != 0) RRR();
  if (h->e_ident[14] != 0) RRR();
  if (h->e_ident[15] != 0) RRR();
  if (h->e_type != 2) RRR(); // ET_EXEC
  switch (h->e_machine) {
  case 40: elf.isArm = true; break; // EM_ARM
  case 83: elf.isAvr = true; break; // EM_AVR
  default: printf("machine=%u\n", h->e_machine); RRR();
  }
  if (h->e_version != 1) RRR(); // EV_CURRENT
  if (h->e_entry != 0) {
    printf("entry = %x\n", h->e_entry);
    if (! elf.isArm) RRR();
    
  }
  //printf("e_phoff = %x\n", h->e_phoff);
  // Program header normally goes right after the header.
  if (h->e_phoff != sizeof *h) RRR();
  //printf("e_shoff = %x\n", h->e_shoff);
  if (h->e_shoff == 0) RRR(); // Section header.
  //printf("e_flags = %x\n", h->e_flags);
  if (elf.isAvr) {
    /* The last 4 bits appears to be this:
       http://www.nongnu.org/avr-libc/user-manual/using_tools.html
       http://www.google.com/codesearch?as_q=E_AVR_MACH_AVR5&as_filename=avr.h
    */
    Uint32 rest = h->e_flags & ~0x7F;
    if (rest != 0x80) RRR();

  }
  else if (elf.isArm) {
    // http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf
    if (h->e_flags != 0x5000002) RRR();
  }
  else {
    RRR();
  }
  if (h->e_ehsize != sizeof *h) RRR();
  //printf("e_phentsize = %x\n", h->e_phentsize);
  if (h->e_phentsize != 0x20) RRR();
  //printf("e_phnum = %x\n", h->e_phnum);
  if (h->e_phnum == 0) RRR();
  //printf("e_shentsize = %x\n", h->e_shentsize);
  if (h->e_shentsize != sizeof(Elf32_Shdr)) RRR();
  if (h->e_shnum == 0) RRR();
  //printf("e_shstrndx = %x\n", h->e_shstrndx);
  if (h->e_shstrndx == ELF_SHN_UNDEF) RRR();
}

static void elf_getBssDataAndRamSize(void) {
  ElfSection* bssSection = elfFindSectionByName(".bss");
  ElfSection* dataSection = elfFindSectionByName(".data");
  unsigned bssSize = bssSection == NULL ? 0 : bssSection->header.sh_size;
  unsigned dataSize = dataSection == NULL ? 0 : dataSection->header.sh_size;
  unsigned offset = 0x800000;
  unsigned addr = 0;
  elf.bssAndDataSize = bssSize + dataSize;
  if (dataSection != NULL)
    addr = dataSection->header.sh_addr;
  else if (bssSection != NULL)
    addr = bssSection->header.sh_addr;
  else
    RRR();
  if (addr < offset) RRR();
  elf.ramStart = addr - offset;
}

unsigned elfGetMinDataAddr(void) {
  Uint32 min = 0xffffffff;
  unsigned i;
  for (i = 0; i < elf.numSymbols; i++) {
    ElfSymbol* sym = elf.symbol + i;
    if (sym->type == 'd')
      min = sym->addr;
  }
  return min;
}

unsigned elfGetBssAndDataSize(void) { return elf.bssAndDataSize; }
unsigned elfGetTextSize(void) { return elf.textSection->header.sh_size; }
unsigned elfGetNumSymbols(void) { return elf.numSymbols; }
unsigned elfGetRamStart(void) { return elf.ramStart; }
Uint8* elfGetText(void) { return elf.textSection->data; }
ElfSymbol* elfGetSymbol(unsigned i) { return elf.symbol + i; }
Bool elfIsArm(void) { return elf.isArm; }
Bool elfIsAvr(void) { return elf.isAvr; }

void elfReadFile(char* name) {
  if ((elf.file = fopen(name, "rb")) == NULL) RRR();
  elfReadHeader();
  elfReadSectionHeaders();
  elfReadShstrtab();
  elfReadSymbolTable();
  elf.textSection = elfReadText();
  elf_getBssDataAndRamSize();
}
typedef struct {
  unsigned addr;
  unsigned size;
  //unsigned flags;
  unsigned type;
  Bool defined;
} ArchPattern;

typedef struct {
  ArchPattern pattern[32];
  unsigned numPatterns;

  ArchPattern prologue;
  ArchPattern epilogue;
  ArchPattern tablejump2;

  ArchPattern* reachedPattern[8];
  unsigned numReachedPatterns;
  ElfSymbol** isr;
  unsigned numIsrs;
  unsigned numInterruptVectors;
  unsigned vectorSize;
  Bool epilogueIsTiny;
} Arch;

static Uint8 setjmpPattern[] = {
  0xdc, 0x01,
  0x2d, 0x92,
  0x3d, 0x92,
  0x4d, 0x92,
  0x5d, 0x92,
  0x6d, 0x92,
  0x7d, 0x92,
  0x8d, 0x92,
  0x9d, 0x92,
  0xad, 0x92,
  0xbd, 0x92,
  0xcd, 0x92,
  0xdd, 0x92,
  0xed, 0x92,
  0xfd, 0x92,
  0x0d, 0x93,
  0x1d, 0x93,
  0xcd, 0x93,
  0xdd, 0x93,
  0xff, 0x91,
  0xef, 0x91,
  0x8d, 0xb7,
  0x8d, 0x93,
  0x8e, 0xb7,
  0x8d, 0x93,
  0x8f, 0xb7,
  0x8d, 0x93,
  0xed, 0x93,
  0xfd, 0x93,
  0x88, 0x27,
  0x99, 0x27,
  0x09, 0x94,
};

static Uint8 longjmpPattern[] = {
  0xdc, 0x01,
  0xcb, 0x01,
  0x81, 0x30,
  0x91, 0x05,
  0x81, 0x1d,
  0x2d, 0x90,
  0x3d, 0x90,
  0x4d, 0x90,
  0x5d, 0x90,
  0x6d, 0x90,
  0x7d, 0x90,
  0x8d, 0x90,
  0x9d, 0x90,
  0xad, 0x90,
  0xbd, 0x90,
  0xcd, 0x90,
  0xdd, 0x90,
  0xed, 0x90,
  0xfd, 0x90,
  0x0d, 0x91,
  0x1d, 0x91,
  0xcd, 0x91,
  0xdd, 0x91,
  0xed, 0x91,
  0xfd, 0x91,
  0x0d, 0x90,
  0xf8, 0x94,
  0xfe, 0xbf,
  0x0f, 0xbe,
  0xed, 0xbf,
  0xed, 0x91,
  0xfd, 0x91,
  0x09, 0x94,
};

static Uint8 tablejump2Pattern[] = {
  0xee, 0x0f,
  0xff, 0x1f,
  0x05, 0x90,
  0xf4, 0x91,
  0xe0, 0x2d,
  0x09, 0x94,
};

static Uint8 prologueTinyPattern[] = {
  0x2f, 0x92, // push	r2
  0x3f, 0x92, // push	r3
  0x4f, 0x92, // push	r4
  0x5f, 0x92, // push	r5
  0x6f, 0x92, // push	r6
  0x7f, 0x92, // push	r7
  0x8f, 0x92, // push	r8
  0x9f, 0x92, // push	r9
  0xaf, 0x92, // push	r10
  0xbf, 0x92, // push	r11
  0xcf, 0x92, // push	r12
  0xdf, 0x92, // push	r13
  0xef, 0x92, // push	r14
  0xff, 0x92, // push	r15
  0x0f, 0x93, // push	r16
  0x1f, 0x93, // push	r17
  0xcf, 0x93, // push	r28
  0xdf, 0x93, // push	r29
  0xcd, 0xb7, // in	r28, 0x3d
  0xca, 0x1b, // sub	r28, r26
  0xcd, 0xbf, // out	0x3d, r28
  0xdd, 0x27, // eor	r29, r29
  0x09, 0x94, // ijmp
};

static Uint8 prologuePattern[] = {
  0x2f, 0x92, // push	r2
  0x3f, 0x92, // push	r3
  0x4f, 0x92, // push	r4
  0x5f, 0x92, // push	r5
  0x6f, 0x92, // push	r6
  0x7f, 0x92, // push	r7
  0x8f, 0x92, // push	r8
  0x9f, 0x92, // push	r9
  0xaf, 0x92, // push	r10
  0xbf, 0x92, // push	r11
  0xcf, 0x92, // push	r12
  0xdf, 0x92, // push	r13
  0xef, 0x92, // push	r14
  0xff, 0x92, // push	r15
  0x0f, 0x93, // push	r16
  0x1f, 0x93, // push	r17
  0xcf, 0x93, // push	r28
  0xdf, 0x93, // push	r29
  0xcd, 0xb7, // in	r28, 0x3d
  0xde, 0xb7, // in	r29, 0x3e
  0xca, 0x1b, // sub	r28, r26
  0xdb, 0x0b, // sbc	r29, r27
  0x0f, 0xb6, // in	r0, 0x3f
  0xf8, 0x94, // cli
  0xde, 0xbf, // out	0x3e, r29
  0x0f, 0xbe, // out	0x3f, r0
  0xcd, 0xbf, // out	0x3d, r28
  0x09, 0x94, // ijmp
};

static Uint8 prologueXmegaPattern[] = { // FIX140402A
  0x2f, 0x92, // push	r2
  0x3f, 0x92, // push	r3
  0x4f, 0x92, // push	r4
  0x5f, 0x92, // push	r5
  0x6f, 0x92, // push	r6
  0x7f, 0x92, // push	r7
  0x8f, 0x92, // push	r8
  0x9f, 0x92, // push	r9
  0xaf, 0x92, // push	r10
  0xbf, 0x92, // push	r11
  0xcf, 0x92, // push	r12
  0xdf, 0x92, // push	r13
  0xef, 0x92, // push	r14
  0xff, 0x92, // push	r15
  0x0f, 0x93, // push	r16
  0x1f, 0x93, // push	r17
  0xcf, 0x93, // push	r28
  0xdf, 0x93, // push	r29
  0xcd, 0xb7, // in	r28, 0x3d
  0xde, 0xb7, // in	r29, 0x3e
  0xca, 0x1b, // sub	r28, r26
  0xdb, 0x0b, // sbc	r29, r27
  0xcd, 0xbf, // out	0x3d, r28
  0xde, 0xbf, // out	0x3e, r29
  0x09, 0x94, // ijmp
};

static Uint8 epilogueTinyPattern[] = {
  0x2a, 0x88, // ldd	r2, Y+18
  0x39, 0x88, // ldd	r3, Y+17
  0x48, 0x88, // ldd	r4, Y+16
  0x5f, 0x84, // ldd	r5, Y+15
  0x6e, 0x84, // ldd	r6, Y+14
  0x7d, 0x84, // ldd	r7, Y+13
  0x8c, 0x84, // ldd	r8, Y+12
  0x9b, 0x84, // ldd	r9, Y+11
  0xaa, 0x84, // ldd	r10, Y+10
  0xb9, 0x84, // ldd	r11, Y+9
  0xc8, 0x84, // ldd	r12, Y+8
  0xdf, 0x80, // ldd	r13, Y+7
  0xee, 0x80, // ldd	r14, Y+6
  0xfd, 0x80, // ldd	r15, Y+5
  0x0c, 0x81, // ldd	r16, Y+4
  0x1b, 0x81, // ldd	r17, Y+3
  0xaa, 0x81, // ldd	r26, Y+2
  0xd9, 0x81, // ldd	r29, Y+1
  0xce, 0x0f, // add	r28, r30
  0xcd, 0xbf, // out	0x3d, r28
  0xca, 0x2f, // mov	r28, r26
  0x08, 0x95, // ret
};

static Uint8 epiloguePattern[] = {
  0x2a, 0x88, // ldd	r2, Y+18
  0x39, 0x88, // ldd	r3, Y+17
  0x48, 0x88, // ldd	r4, Y+16
  0x5f, 0x84, // ldd	r5, Y+15
  0x6e, 0x84, // ldd	r6, Y+14
  0x7d, 0x84, // ldd	r7, Y+13
  0x8c, 0x84, // ldd	r8, Y+12
  0x9b, 0x84, // ldd	r9, Y+11
  0xaa, 0x84, // ldd	r10, Y+10
  0xb9, 0x84, // ldd	r11, Y+9
  0xc8, 0x84, // ldd	r12, Y+8
  0xdf, 0x80, // ldd	r13, Y+7
  0xee, 0x80, // ldd	r14, Y+6
  0xfd, 0x80, // ldd	r15, Y+5
  0x0c, 0x81, // ldd	r16, Y+4
  0x1b, 0x81, // ldd	r17, Y+3
  0xaa, 0x81, // ldd	r26, Y+2
  0xb9, 0x81, // ldd	r27, Y+1
  0xce, 0x0f, // add	r28, r30
  0xd1, 0x1d, // adc	r29, r1
  0x0f, 0xb6, // in	r0, 0x3f
  0xf8, 0x94, // cli
  0xde, 0xbf, // out	0x3e, r29
  0x0f, 0xbe, // out	0x3f, r0
  0xcd, 0xbf, // out	0x3d, r28
  0xed, 0x01, // movw	r28, r26
  0x08, 0x95, // ret
};

static Uint8 epilogueXmegaPattern[] = { // FIX140402A
  0x2a, 0x88, // ldd	r2, Y+18
  0x39, 0x88, // ldd	r3, Y+17
  0x48, 0x88, // ldd	r4, Y+16
  0x5f, 0x84, // ldd	r5, Y+15
  0x6e, 0x84, // ldd	r6, Y+14
  0x7d, 0x84, // ldd	r7, Y+13
  0x8c, 0x84, // ldd	r8, Y+12
  0x9b, 0x84, // ldd	r9, Y+11
  0xaa, 0x84, // ldd	r10, Y+10
  0xb9, 0x84, // ldd	r11, Y+9
  0xc8, 0x84, // ldd	r12, Y+8
  0xdf, 0x80, // ldd	r13, Y+7
  0xee, 0x80, // ldd	r14, Y+6
  0xfd, 0x80, // ldd	r15, Y+5
  0x0c, 0x81, // ldd	r16, Y+4
  0x1b, 0x81, // ldd	r17, Y+3
  0xaa, 0x81, // ldd	r26, Y+2
  0xb9, 0x81, // ldd	r27, Y+1
  0xce, 0x0f, // add	r28, r30
  0xd1, 0x1d, // adc	r29, r1
  0xcd, 0xbf, // out	0x3d, r28
  0xde, 0xbf, // out	0x3e, r29
  0xed, 0x01, // movw	r28, r26
  0x08, 0x95, // ret
};

enum {
  ArchPatternType_none = 0,
  ArchPatternType_setjmp,
  ArchPatternType_longjmp,
  ArchPatternType_tablejump2,
};

static Bool arch_isPatternMatch(ElfSymbol* s, Uint8* data, unsigned size) {
  if (s->addr + size < cpu.bProgSize)
    if (memcmp(cpu.prog + s->addr, data, size) == 0)
      return true;
  return false;
}

static void arch_registerFuncPattern(Arch* h,
				     ElfSymbol* s, Uint8* data,
				     unsigned size, unsigned type) {
  if (arch_isPatternMatch(s, data, size)) {
    ArchPattern* rp = h->pattern + h->numPatterns++;
    if (h->numPatterns >= ARRAYSIZE(h->pattern)) RRR();
    rp->addr = s->addr;
    rp->size = size;
    //rp->flags = flags;
    rp->type = type;
  }
}

static Bool arch_registerPattern(ElfSymbol* s, ArchPattern* p,
				 Uint8* data, unsigned size) {
  Bool retval = false;
  p->addr = s->addr;
  p->size = size;
  if (arch_isPatternMatch(s, data, size)) {
    p->defined = true;
    retval = true;
  }
  return retval;
}

#define M(h,x,y) arch_registerPattern(s, &h->x, y##Pattern, sizeof y##Pattern)
static void arch_registerTablejump2(Arch* h, ElfSymbol* s) {
  M(h, tablejump2, tablejump2);
}
static void arch_registerPrologue(Arch* h, ElfSymbol* s) {
  if (! M(h, prologue, prologue))
    if (! M(h, prologue, prologueXmega))
      M(h, prologue, prologueTiny);
}
static void arch_registerEpilogue(Arch* h, ElfSymbol* s) {
  if (! M(h, epilogue, epilogue))
    if (! M(h, epilogue, epilogueXmega))
      if (M(h, epilogue, epilogueTiny))
	h->epilogueIsTiny = true;
}
#undef M

static void arch_markReached(Arch* h, ArchPattern* p) {
  unsigned i;
  for (i = 0; i < h->numReachedPatterns; i++)
    if (h->reachedPattern[i] == p)
      return;
  if (h->numReachedPatterns >= ARRAYSIZE(h->reachedPattern)) RRR();
  h->reachedPattern[h->numReachedPatterns++] = p;
}

static Bool arch_isPcInsidePattern(ArchPattern* p, unsigned pc) {
  unsigned addr = pc * CPU_minInstrSize;
  return p->addr <= addr && addr < p->addr + p->size;
}

static Bool arch_isPrologueJumpx(Arch* h) {
  return arch_isPcInsidePattern(&h->prologue, cpu.pc);
}
static Bool arch_isEpilogueJumpx(Arch* h) {
  return arch_isPcInsidePattern(&h->epilogue, cpu.pc);
}

static Bool arch_isTablejump2(Arch* h) {
  unsigned addr = cpu.pc * CPU_minInstrSize;
  return h->tablejump2.defined && addr == h->tablejump2.addr;
}

static void arch_ijmp(unsigned tableSize,
		      unsigned offsetLow,
		      unsigned offsetHigh,
		      Bool rjmp) {

  unsigned offset = 0x10000 - ((offsetHigh << 8) | offsetLow);
  unsigned numEntries = tableSize;
  unsigned i;

  //printf("tableSize = %d offset=%x\n", tableSize, offset * 2);
  if (tableSize == 0) RRR();

  cpu.flags |= CPU_F_ijmp;
  if (numEntries >= ARRAYSIZE(cpu.jumpTo2)) RRR();
  cpu.ijmp.tableSize = numEntries;
  cpu.ijmp.addr = offset;
  cpu.ijmp.dataSize = rjmp ? 0 : tableSize;

  for (i = 0; i < tableSize; i++) {
    unsigned addr = offset + i;
    if (addr >= cpu.iProgSize) RRR();
    if (rjmp) {

    }
    else {

      cpu.pc = addr; /* We need to set the PC because that is the only way we
			know how to fetch a value from prog mem (100515). */
      addr = fetch16();
      if (addr >= cpu.iProgSize) RRR();
    }
    cpu.jumpTo2[i] = addr;
  }

  cpu.pc = cpu.jumpTo2[0];
}

static Bool arch_parseJumpOverIjmp(CpuAddr addr, CpuAddr* endAddrPtr) {
  Bool retval = true;
  if (cpu_isInstr_rjmp(addr - 0, NULL)) {
    /*
      -1:	08 f0       	brcs	.+2
      -0:	43 c0       	rjmp	.+134
    */
    if (cpu_isInstr_jmp(addr - 1, NULL)) RRR(); // LNK.prevInstr16Or32
    if (! cpu_isInstr_brcs(addr - 1, NULL)) RRR();
    *endAddrPtr = addr - 2;
  }
  else if (cpu_isInstr_jmp(addr - 1, NULL)) { // FIX140119A: Added this.
    if (! cpu_isInstr_brcs(addr - 2, NULL)) RRR();
    *endAddrPtr = addr - 3;
  }
  else if (cpu_isInstr_brcc(addr - 0, NULL)) {
    // -0:	98 f7       	brcc	.-26
    *endAddrPtr = addr - 1;
  }
  else {
    retval = false;
  }
  return retval;
}

static void arch_parseIjmpTableSize(CpuAddr addr, unsigned* tableSizePtr) {
  if (cpu_isInstr_cpc(addr - 0, 31, 1)) {
    /*
      -1:	e4 31       	cpi	r30, 0x14
      -0:	f1 05       	cpc	r31, r1
    */
    if (! cpu_isInstr_cpi(addr - 1, 30, tableSizePtr)) RRR();
  }
  else if (cpu_isInstr_cpc(addr - 0, 25, 1)) {
    /*
      -2:	fc 01       	movw	r30, r24
      -1:	87 32       	cpi	r24, 0x27
      -0:	91 05       	cpc	r25, r1
    */
    if (! cpu_isInstr_cpi(addr - 1, 24, tableSizePtr)) RRR();
    if (! cpu_isInstr_movw(addr - 2, 30, 24)) RRR();
  }
  else {
    RRR();
  }
}

static void arch_parseTablejump2(CpuAddr addr,
				 unsigned* tableSizePtr,
				 unsigned* offsetLowPtr,
				 unsigned* offsetHighPtr) {
    
  CpuAddr tableSizeAddr;

  if (cpu_isInstr_sbci(addr - 1, 31, offsetHighPtr)) {
    /*
      -2:	ea 5b       	subi	r30, 0xBA
      -1:	ff 4f       	sbci	r31, 0xFF
    */
    if (! cpu_isInstr_subi(addr - 2, 30, offsetLowPtr)) RRR();
    if (arch_parseJumpOverIjmp(addr - 3, &tableSizeAddr))
      arch_parseIjmpTableSize(tableSizeAddr, tableSizePtr);
    else {
      unsigned reg;
      if (! cpu_isInstr_movw_rrx(addr - 3, 30, &reg)) CPURRRA(addr - 3);
      if (! arch_parseJumpOverIjmp(addr - 4, &tableSizeAddr))
	CPURRRA(addr - 4);
      if (! cpu_isInstr_cpc(tableSizeAddr - 0, reg + 1, 1)) RRR();
      if (! cpu_isInstr_cpi(tableSizeAddr - 1, reg, tableSizePtr)) RRR();
      /*
	-6:	88 30       	cpi	r24, 0x08
	-5:	91 05       	cpc	r25, r1
	-4:	78 f4       	brcc	.+30
	-3:	fc 01       	movw	r30, r24
      */
    }
  }
  else { // FIX130406A: Added this, for EEC69.
    unsigned reg;
    /*
      -7:	83 32       	cpi	r24, 0x23
      -6:	91 05       	cpc	r25, r1
      -5:	08 f0       	brcs	.+2
      -4:	9c c0       	rjmp	.+312
      -3:	82 50       	subi	r24, 0x02
      -2:	9f 4f       	sbci	r25, 0xFF
      -1:	fc 01       	movw	r30, r24
    */
    if (! cpu_isInstr_movw_rrx(addr - 1, 30, &reg)) CPURRRA(addr - 1);
    if (! cpu_isInstr_sbci(addr - 2, reg + 1, offsetHighPtr)) RRR();
    if (! cpu_isInstr_subi(addr - 3, reg, offsetLowPtr)) RRR();
    if (! arch_parseJumpOverIjmp(addr - 4, &tableSizeAddr)) CPURRRA(addr - 4);
    if (! cpu_isInstr_cpc(tableSizeAddr - 0, reg + 1, 1)) RRR();
    if (! cpu_isInstr_cpi(tableSizeAddr - 1, reg, tableSizePtr)) RRR();
  }
}

static unsigned arch_tablejump2(Arch* h, unsigned retval) {
  unsigned offsetHigh;
  unsigned offsetLow;
  unsigned tableSize = 0;
  unsigned pc = cpu.pc;
  arch_markReached(h, &h->tablejump2);
  arch_parseTablejump2(cpu.pcPrev, &tableSize, &offsetLow, &offsetHigh);
  cpu.pc = pc;
  arch_ijmp(tableSize, offsetLow, offsetHigh, false);
  return retval;
}

static unsigned arch_prologue(Arch* h, unsigned retval) {

  unsigned iAddr = cpu.pcPrev;
  unsigned destH, destL, dest;
  unsigned frameH, frameL, frame; // frame size
  unsigned nPushes;
  unsigned pc = cpu.pc;
  unsigned pcPrev = cpu.pcPrev;
  unsigned flags = cpu.flags;

  arch_markReached(h, &h->prologue);
  /*
    -4:	ab e0       	ldi	r26, 0x0B	; 11
    -3:	b0 e0       	ldi	r27, 0x00	; 0
    -2:	e3 e6       	ldi	r30, 0x63	; 99
    -1:	f0 e0       	ldi	r31, 0x00	; 0
  */
  if (! cpu_isInstr_ldi(iAddr - 1, 31, &destH)) CPURRR();
  if (! cpu_isInstr_ldi(iAddr - 2, 30, &destL)) CPURRR();
  if (! cpu_isInstr_ldi(iAddr - 3, 27, &frameH)) CPURRR();
  if (! cpu_isInstr_ldi(iAddr - 4, 26, &frameL)) CPURRR();
  dest = destH * 256 + destL;
  frame = frameH * 256 + frameL;

  // How many push-es we skip.
  //printf("pc %x %x\n", pc * CPU_minInstrSize, h->prologue.addr);
  nPushes = pc - h->prologue.addr / CPU_minInstrSize;
  //printf("nPushes=%u\n", nPushes);
  if (nPushes > 16) RRR();

  cpu.stackChange = 18 - nPushes + frame;
  cpu.flags = flags & ~CPU_F_uncondJump;
  cpu.flags |= CPU_F_stack;
  cpu.pc = pcPrev + retval / CPU_minInstrSize;
  //printf("pc %x %x\n", cpu.pc * 2, dest * 2);
  if (cpu.pc != dest) {
    /* I guess this is possible. I just do not want to do this until
       I see this. If this needs to be done, then in maze we will need
       to support cases when both F_*jump & F_stack is set. */
    RRR();
  }

  return retval;
}

static unsigned arch_epilogue(Arch* h, unsigned retval) {

  unsigned iAddr = cpu.pcPrev;
  unsigned nPops; /* This normally matches the number of pushes
		     done in prologue. */
  unsigned frame; // This normally matches 'frame' in prologue.
  unsigned nPopsSkipped;
  unsigned pc = cpu.pc;
  unsigned flags = cpu.flags;

  arch_markReached(h, &h->epilogue);

  /*
    -3:	02 d0       	rcall	printf
    -2:	20 96       	adiw	r28, 0x00	; 0
    -1:	e2 e0       	ldi	r30, 0x02	; 2
  */
  if (! cpu_isInstr_ldi(iAddr - 1, 30, &nPops)) CPURRR();
  if (cpu_isInstr_call(iAddr - 3, NULL) ||
      cpu_isInstr_rcall(iAddr - 2, NULL)) {
    /* FIX140402C: It looks that the pointless "adiw R28,0x00" is gone
       in GNU_Toolchain_3.4.3. */
    frame = 0;
  }
  else if (! cpu_isInstr_adiw(iAddr - 2, 28, &frame)) {
    /*
      -3:	c2 5a       	subi	r28, 0xA2	; 162
      -2:	df 4f       	sbci	r29, 0xFF	; 255
    */
    unsigned high;
    unsigned low;
    if (! cpu_isInstr_sbci(iAddr - 2, 29, &high)) {
      if (h->epilogueIsTiny) {
	/*
	  -3: cd b7       	in	r28, 0x3d
	  -2: dd 27       	eor	r29, r29
	*/
	if (! cpu_isInstr_eor(iAddr - 2, 29, 29))
	  CPURRRA(iAddr- 2);
      }
      else {
	/*
	  -3: cd b7       	in	r28, 0x3d
	  -2: de b7       	in	r29, 0x3e
	*/
	if (! cpu_isInstr_in(iAddr - 2, 29, CPU_stackPort + 1))
	  CPURRRA(iAddr- 2);
      }
      if (! cpu_isInstr_in(iAddr - 3, 28, CPU_stackPort)) RRR();
      frame = 0;
    }
    else {
      if (! cpu_isInstr_subi(iAddr - 3, 28, &low)) CPURRR();
      frame = 0x10000 - ((high << 8) | low);
    }
  }

  // How many pop-es we skip.
  //printf("pc %x %x\n", pc * CPU_minInstrSize, h->epilogue.addr);
  nPopsSkipped = pc - h->epilogue.addr / CPU_minInstrSize;
  //printf("nPushes=%u\n", nPushes);
  if (nPopsSkipped > 16) RRR();
  if (nPops != 18 - nPopsSkipped) RRR();

  cpu.stackChange = - (int) nPops - (int) frame;
  cpu.flags = flags & ~CPU_F_uncondJump;
  cpu.flags |= CPU_F_stack | CPU_F_ret;
  cpu.pc = 0; // We do not really care.
  return retval;
}

static Bool arch_isVectorSymbol(ElfSymbol* sym) {
  Bool match = strcmp(sym->name, "__bad_interrupt") == 0;
  if (match) badInterrupt = sym->addr;
  if (! match) {
    static const char vector[] = "__vector_";
    if (strncmp(sym->name, vector, sizeof vector - 1) == 0) {
      char* p = sym->name + sizeof vector - 1;
      while (isdigit(*p)) p++;
      match = *p == 0;
    }
  }
  return match;
}

static void arch_buildIsrFunctionList(Arch* h, unsigned* countPtr) {
  ElfSymbol** list;
  unsigned n = 0;
  unsigned i;
  if (! elfIsAvr()) RRR();
  // RRR(); // fix #if 0 above and below
  for (i = 0; i < elfGetNumSymbols(); i++) {
    ElfSymbol* s = elfGetSymbol(i);
    if (arch_isVectorSymbol(s))
      n++;
  }

  if (n == 0) RRR();

  list = myMalloc0(n * sizeof list[0]);
  for (n = 0, i = 0; i < elfGetNumSymbols(); i++) {
    ElfSymbol* s = elfGetSymbol(i);
    if (arch_isVectorSymbol(s))
      list[n++] = s;
  }

  *countPtr = n;
  h->isr = list;
}

static unsigned arch_guessVectorSize(void) {
  unsigned addr1 = 0;
  unsigned n1 = cpuParse(addr1);
  unsigned addr2 = addr1 + n1;
  if (! elfIsAvr()) RRR();
  if (! cpuInstrIsUncondJump()) RRR();
  while (true) {
    unsigned n = cpuParse(addr2);
    if (cpuInstrIsUncondJump()) {
      unsigned pc = cpuGetPC();
      ElfSymbol* sym = elfGetSymbolByAddr(pc);
      if (sym == NULL) RRR();
      if (! arch_isVectorSymbol(sym)) RRR();
      return addr2 - addr1;
    }
    addr2 += n;
  }
  RRR();
}

void archGuessNumInterruptVectors(Arch* h) {

  unsigned isrCount;
  CpuAddr minDataAddr = elfGetMinDataAddr();
  Bool* isrReached;
  unsigned v;

  if (! elfIsAvr()) RRR();

  arch_buildIsrFunctionList(h, &isrCount);
  isrReached = myMalloc0(isrCount * sizeof *isrReached);

  h->vectorSize = arch_guessVectorSize();

  for (v = 1; ; v++) {
    unsigned addr = v * h->vectorSize;
    ElfSymbol* sym;
    unsigned pc;
    unsigned i;
    if (addr >= minDataAddr) // FIX130816A: Added this.
      break;
    cpuParse(addr);
    if (! cpuInstrIsUncondJump())
      break;
    pc = cpuGetPC();
    if ((sym = elfGetSymbolByAddr(pc)) == NULL)
      break;
    if (! arch_isVectorSymbol(sym))
      break;
    for (i = 0; i < isrCount; i++) {
      if (h->isr[i] == sym) {
	isrReached[i] = true;
	break;
      }
    }
  }

  h->numInterruptVectors = v - 1;

  {
    unsigned i;
    for (i = 0; i < isrCount; i++) {
      if (! isrReached[i]) {
	printf("isr %s\n", h->isr[i]->name);
	RRR();
      }
    }
  }

  h->numIsrs = isrCount;
  myFree(isrReached);
}

void archParseStandardPatterns(Arch* h) {
  ElfSymbol* s;
#define M(x) x##Pattern, sizeof x##Pattern
  if ((s = elfFindSymbolByName("setjmp")) != NULL)
    arch_registerFuncPattern(h, s, M(setjmp), ArchPatternType_setjmp);
  if ((s = elfFindSymbolByName("longjmp")) != NULL)
    arch_registerFuncPattern(h, s, M(longjmp), ArchPatternType_longjmp);
#undef M
  if ((s = elfFindSymbolByName("__prologue_saves__")) != NULL)
    arch_registerPrologue(h, s);
  if ((s = elfFindSymbolByName("__epilogue_restores__")) != NULL)
    arch_registerEpilogue(h, s);
  if ((s = elfFindSymbolByName("__tablejump2__")) != NULL)
    arch_registerTablejump2(h, s);
}

unsigned archGetNumReachedPatterns(Arch* h) {
  return h->numReachedPatterns;
}

ArchPattern* archGetReachedPattern(Arch* h, unsigned i) {
  if (i >= h->numReachedPatterns) RRR();
  return h->reachedPattern[i];
}

static void arch_cpuIjmp(void) {

  CpuAddr addr = cpu.pcPrev;
  unsigned offsetHigh;
  unsigned offsetLow;
  unsigned tableSize = 0;
  Bool rjmp = false;

  

  

  /*
    -5:	ee 0f       	add	r30, r30
    -4:	ff 1f       	adc	r31, r31
    -3:	05 90       	lpm	r0, Z+
    -2:	f4 91       	lpm	r31, Z+ - there should be no '+'! (bug in objdump?)
    -1:	e0 2d       	mov	r30, r0
    -0:	09 94       	ijmp
  */

  CpuAddr ps0 = cpu.parseHistory[0];
  CpuAddr ps1 = cpu.parseHistory[1];
  CpuAddr ps2 = cpu.parseHistory[2];

  if (! cpu_isInstr(addr - 0, "ijmp")) RRR();
  if (cpu_isInstr_mov(addr - 1, 30, 0)) {
    if (! cpu_isInstr_lpm(addr - 2, 31)) RRR();
    if (! cpu_isInstr_lpmP(addr - 3, 0)) RRR();
    if (! cpu_isInstr_adc(addr - 4, 31, 31)) RRR();
    if (! cpu_isInstr_add(addr - 5, 30, 30)) RRR();
    arch_parseTablejump2(addr - 5, &tableSize, &offsetLow, &offsetHigh);
  }
  else {
    CpuAddr tableSizeAddr;
    /*
      -2:	e6 5e       	subi	r30, 0xE6	; 230
      -1:	ff 4f       	sbci	r31, 0xFF	; 255
      -0:	09 94       	ijmp
    */
    unsigned off = 0;
    if (! cpu_isInstr_sbci(addr - off - 1 , 31, &offsetHigh)) {
      /* FIX110810A: switch in ecp3Handler in wdui has a couple of
	 instructions between sbci and ijmp. */
      if (ps0 != addr) RRR();
      if (ps1 != addr - 1) RRR();
      if (ps2 != addr - 2) RRR();
      if (! cpu_isInstrDoesNotTouchZ(addr - 1)) CPURRRA(addr - 1);
      if (! cpu_isInstrDoesNotTouchZ(addr - 2)) CPURRRA(addr - 2);
      /*
	127a:	8f 2d       	mov	r24, r15
	127c:	81 56       	subi	r24, 0x61	; 97
      */
      off =  2;
      if (! cpu_isInstr_sbci(addr - off - 1 , 31, &offsetHigh))
	CPURRRA(addr - 1);
    }
    if (! cpu_isInstr_subi(addr - off - 2, 30, &offsetLow)) RRR();
    if (! arch_parseJumpOverIjmp(addr - off - 3, &tableSizeAddr))
      CPURRRA(addr - off - 3);
    arch_parseIjmpTableSize(tableSizeAddr, &tableSize);
    rjmp = true;
  }

  if (! cpu_isInstr(addr - 0, "ijmp")) RRR(); // This restores cpu.pc!
  arch_ijmp(tableSize, offsetLow, offsetHigh, rjmp);
}

static void arch_cpuRet(void) {

  CpuAddr addr = cpu.pcPrev;
  unsigned regHigh;
  unsigned regLow;

  /* FIX130831A: ret is used as ijmp
     -7:	88 30       	cpi	r24, 0x08
     -6:	91 05       	cpc	r25, r1
     -5:	28 f4       	brcc	.+10
     -4:	86 5e       	subi	r24, 0xE6
     -3:	9f 4f       	sbci	r25, 0xFF
     -2:	8f 93       	push	r24
     -1:	9f 93       	push	r25
     -0:	08 95       	ret
  */

  if (cpu.parseHistory[1] == addr - 1 && // 16-bit instruction?
      cpu.parseHistory[2] == addr - 2 && // 16-bit instruction?
      cpu_isInstr_push(addr - 1, &regHigh) &&
      cpu_isInstr_push(addr - 2, &regLow)) {

    CpuAddr tableSizeAddr;
    unsigned tableSize;
    unsigned offsetLow;
    unsigned offsetHigh;

    if (! cpu_isInstr_sbci(addr - 3, regHigh, &offsetHigh)) CPURRRA(addr - 3);
    if (! cpu_isInstr_subi(addr - 4, regLow, &offsetLow)) CPURRRA(addr - 4);
    if (! arch_parseJumpOverIjmp(addr - 5, &tableSizeAddr)) CPURRRA(addr - 5);
    if (! cpu_isInstr_cpc(tableSizeAddr - 0, regHigh, 1)) RRR();
    if (! cpu_isInstr_cpi(tableSizeAddr - 1, regLow, &tableSize)) RRR();

    /* I have a similar call in ijmp. Not sure I really need it,
       but it does not hurt. */ {
      if (! cpu_isInstr(addr - 0, "ret")) RRR();
    }
    cpuStack(-2);
    cpu.flags &= ~CPU_F_ret; // LNK.undoCpuRet
    arch_ijmp(tableSize, offsetLow, offsetHigh, true);
    return;
  }

  /* Do 'parse' one more time because the previous call may have
     altered some variables. */
  cpuParse(addr * CPU_minInstrSize);
}

static Bool arch_ascccs_highFollowedByLow(CpuAddr addr) {
  unsigned reg;
  if (cpu_isInstr_outX(addr + 0, &reg, CPU_stackPort + 1)) {
    if (cpu_isInstr_outX(addr + 1, &reg, CPU_stackPort))
      return true;
    else {
      if (cpu_isInstr_outN(addr + 1, 0, 0x3f) &&
	  cpu_isInstr_outX(addr + 2, &reg, CPU_stackPort))
	return true;
    }
  }
  return false;
}

static Bool arch_ascccs_lowFollowedByHigh(CpuAddr addr) {
  unsigned reg;
  if (cpu_isInstr_outX(addr + 0, &reg, CPU_stackPort)) {
    if (cpu_isInstr_outX(addr + 1, &reg, CPU_stackPort + 1))
      return true;
    else {
      if (cpu_isInstr_outN(addr + 1, 0, 0x3f) &&
	  cpu_isInstr_outX(addr + 2, &reg, CPU_stackPort + 1))
	return true;
    }
  }
  return false;
}

static Bool arch_ascccs_oneFollowedByAnother(CpuAddr addr) {
  return 0
    || arch_ascccs_highFollowedByLow(addr)
    || arch_ascccs_lowFollowedByHigh(addr)
    ;
}

/*
  -5:	2d b7       	in	r18, 0x3d	; 61
  -4:	3e b7       	in	r19, 0x3e	; 62
  -3:	28 50       	subi	r18, 0x08	; 8
  -2:	30 40       	sbci	r19, 0x00	; 0
  -1:	2d bf       	out	0x3d, r18	; 61
  0:	3e bf       	out	0x3e, r19	; 62
*/
static Bool arch_isXmegaSubiSbciStackSequence(CpuAddr addr, int* changePtr) {
  unsigned reg;
  unsigned u16;
  unsigned bigK;
  int change;
  if (! cpu_isInstr_outX(addr - 0, &reg, CPU_stackPort + 1)) return false;
  if (! cpu_isInstr_outN(addr - 1, reg - 1, CPU_stackPort)) return false;
  if (! cpu_isInstr_sbci(addr - 2, reg, &u16)) return false;
  if (! cpu_isInstr_subi(addr - 3, reg - 1, &bigK)) return false;
  u16 = (u16 << 8) + bigK;
  if (u16 & 0x8000)
    change = - (int) (0x10000 - u16);
  else {
    change = u16;
    if (! cpu_isInstr_in(addr - 4, reg, CPU_stackPort + 1)) return false;
    if (! cpu_isInstr_in(addr - 5, reg - 1, CPU_stackPort)) return false;
  }
  *changePtr = change;
  return true;
}

/*
  -4:	ed b7       	in	r30, 0x3d	; 61
  -3:	fe b7       	in	r31, 0x3e	; 62
  -2:	38 96       	adiw	r30, 0x08	; 8
  -1:	ed bf       	out	0x3d, r30	; 61
  0:	fe bf       	out	0x3e, r31	; 62
*/
static Bool arch_isXmegaAdiwStackSequence(CpuAddr addr, int* changePtr) {
  unsigned reg;
  unsigned bigK;
  int change;
  if (! cpu_isInstr_outX(addr - 0, &reg, CPU_stackPort + 1)) return false;
  if (! cpu_isInstr_outN(addr - 1, reg - 1, CPU_stackPort)) return false;
  if (! cpu_isInstr_adiw(addr - 2, reg - 1, &bigK)) return false;
  change = - (int) bigK;
  if (! cpu_isInstr_in(addr - 3, reg, CPU_stackPort + 1)) return false;
  if (! cpu_isInstr_in(addr - 4, reg - 1, CPU_stackPort)) return false;
  *changePtr = change;
  return true;
}

// This is similar to cpu_isXmegaAdiwStackSequence
static Bool arch_isXmegaSbiwStackSequence(CpuAddr addr, int* changePtr) {
  unsigned reg;
  unsigned bigK;
  int change;
  if (! cpu_isInstr_outX(addr - 0, &reg, CPU_stackPort + 1)) return false;
  if (! cpu_isInstr_outN(addr - 1, reg - 1, CPU_stackPort)) return false;
  if (! cpu_isInstr_sbiw(addr - 2, reg - 1, &bigK)) return false;
  change = (int) bigK;
  if (! cpu_isInstr_in(addr - 3, reg, CPU_stackPort + 1)) return false;
  if (! cpu_isInstr_in(addr - 4, reg - 1, CPU_stackPort)) return false;
  *changePtr = change;
  return true;
}

static int arch_analyzeStackChangeCodeSection(CpuAddr addr) {

  unsigned bigK;
  unsigned reg;
  int change;

  /* The very first stack out must be stack initialization. We will take
     care of that in LNK.processFirstStackOut. */
  if (0
      || addr == cpu.pcAtFirstStackOut
      || addr == cpu.pcAtFirstStackOut + 1
      || addr == cpu.pcAtFirstStackOut + 2 // FIX140118A
      )
    return 0;

  if (arch_ascccs_oneFollowedByAnother(addr))
    return 0; /* We will take care of the whole thing when we get to
		 the "other" instruction. */

  

  if (arch_isXmegaSubiSbciStackSequence(addr, &change) ||
      arch_isXmegaSbiwStackSequence(addr, &change) ||
      arch_isXmegaAdiwStackSequence(addr, &change))
    /* nothing else to do */;
  else if (! cpu_isInstr_outN(addr - 1, 0, 0x3f)) {
    /* Allocate small frame without disabling interrupts (from OS_main,
       for example:
       -4:	cd b7       	in	r28, 0x3d	; 61
       -3:	de b7       	in	r29, 0x3e	; 62
       -2:	64 97       	sbiw	r28, 0x14	; 20
       -1:	de bf       	out	0x3e, r29	; 62
        0:	cd bf       	out	0x3d, r28	; 61
    */
    if (! cpu_isInstr_outN(addr - 1, 29, CPU_stackPort + 1)) {
      // FIX120325A: xmega
      /*
	-1:	cd bf       	out	0x3d, r28	; 61
	 0:	de bf       	out	0x3e, r29	; 62
      */
      if (! cpu_isInstr_outN(addr - 1, 28, CPU_stackPort)) CPURRRA(addr);
      if (! cpu_isInstr_outN(addr + 0, 29, CPU_stackPort + 1)) RRR();
      if (! cpu_isInstr_sbiw(addr - 2, 28, &bigK)) {
	if (! cpu_isInstr_adiw(addr - 2, 28, &bigK)) {
	  /* FIX141003A: Added this. */ {
	    unsigned low;
	    if (! cpu_isInstr_sbc(addr - 2, 29, 1)) CPURRRA(addr);
	    if (! cpu_isInstr_subi(addr - 3, 28, &low)) CPURRRA(addr);
	    change = low;
	  }
	}
	else {
	  // FIX120325A: xmega
	  change = - (int) bigK;
	}
	}
      else {
	change = bigK;
	if (! cpu_isInstr_in(addr - 3, 29, CPU_stackPort + 1)) RRR();
	if (! cpu_isInstr_in(addr - 4, 28, CPU_stackPort)) RRR();
      }
    }
    else {
      if (! cpu_isInstr_outN(addr + 0, 28, CPU_stackPort)) RRR();
      if (! cpu_isInstr_sbiw(addr - 2, 28, &bigK)) RRR();
      change = bigK;
      if (! cpu_isInstr_in(addr - 3, 29, CPU_stackPort + 1)) RRR();
      if (! cpu_isInstr_in(addr - 4, 28, CPU_stackPort)) RRR();
    }
  }
  else {
    /* Allocate or free small frame (note that r24,r25 and r30,r31 can
       also be used instead of r28,r29):
       -4:	0f b6       	in	r0, 0x3f	; 63
       -3:	f8 94       	cli
       -2:	de bf       	out	0x3e, r29	; 62
       -1:	0f be       	out	0x3f, r0	; 63
        0:	cd bf       	out	0x3d, r28	; 61
    */
    if (! cpu_isInstr_outX(addr - 2, &reg, CPU_stackPort + 1)) RRR();
    if (! cpu_isInstr_outN(addr + 0, reg - 1, CPU_stackPort)) RRR();
    if (! cpu_isInstr_cli(addr - 3)) RRR();
    //printf("addr=%x\n", addr * 2);
    if (! cpu_isInstr_in(addr - 4, 0, 0x3f)) RRR();

    if (cpu_isInstr_adiw(addr - 5, reg - 1, &bigK)) {
      /* Free:
	 -5:	64 96       	adiw	r28, 0x14	; 20
      */
      change = - (int) bigK;
    }
    else if (cpu_isInstr_sbiw(addr - 5, reg - 1, &bigK)) {
      /* Allocate:
	 -7:	cd b7       	in	r28, 0x3d	; 61
	 -6:	de b7       	in	r29, 0x3e	; 62
	 -5:	64 97       	sbiw	r28, 0x14	; 20
      */
      change = bigK;
      if (! cpu_isInstr_in(addr - 6, reg, CPU_stackPort + 1)) RRR();
      if (! cpu_isInstr_in(addr - 7, reg - 1, CPU_stackPort)) RRR();
    }
    else {
      unsigned u16;
      /* Allocate large frame, the following is instead of sbiw:
	 c0 50       	subi	r28, 0x00	; 0
	 d2 40       	sbci	r29, 0x02	; 2
      */
      /* Free large frame, the following is instead of adiw:
	 c0 50       	subi	r28, 0x00	; 0
	 de 4f       	sbci	r29, 0xFE	; 254
      */
      //printf("addr=%x\n", addr * 2);
      if (! cpu_isInstr_sbci(addr - 5, reg, &u16)) CPURRRA(addr - 5);
      if (! cpu_isInstr_subi(addr - 6, reg - 1, &bigK)) RRR();
      u16 = (u16 << 8) + bigK;
      if (u16 & 0x8000)
	change = - (int) (0x10000 - u16);
      else {
	if (! cpu_isInstr_in(addr - 7, reg, CPU_stackPort + 1)) RRR();
	if (! cpu_isInstr_in(addr - 8, reg - 1, CPU_stackPort)) RRR();
	change = u16;
      }
    }
  }

  if (change == 0) RRR();
  return change;
}

unsigned archParse(Arch* h, unsigned addr) {

  unsigned i;
  unsigned retval;

  for (i = 0; i < h->numPatterns; i++) {
    ArchPattern* e = h->pattern + i;
    //printf("cmp %x %x\n", addr, e->addr);
    if (e->addr <= addr && addr < e->addr + e->size) {
      if (addr != e->addr) RRR();
      switch (e->type) {
      case ArchPatternType_setjmp:
      case ArchPatternType_longjmp:
	cpu.pc = addr / CPU_minInstrSize;
	cpu.pcPrev = cpu.pc;
	if (e->type == ArchPatternType_setjmp)
	  cpu.flags = CPU_F_ret | CPU_F_instr;
	else {
	  //printf("pc=%x prev=%x\n", cpu.pc * 2, cpu.pcPrev * 2);
	  cpu.flags = CPU_F_uncondJump | CPU_F_instr | CPU_F_longjmp;
	  cpu.pc = cpu.pcPrev; // Make it look like an infinite loop.
	}
	return e->size;
      default:
	RRR();
	return 0;
      }
    }
  }

  retval = cpuParse(addr);

  if (cpuInstrIsStackChange() && cpu.stackChange == 0) {
    int change = arch_analyzeStackChangeCodeSection(cpu.pcPrev);
    /* Do 'parse' one more time because the previous call may have
       altered some variables. */
    retval = cpuParse(addr);
    cpu.stackChange = change;
  }

  if (cpuInstrIsRet()) {
    arch_cpuRet();
    return retval;
  }
  else if (cpuInstrIsIjmp()) {
    arch_cpuIjmp();
    return retval;
  }
  else if (cpuInstrIsUncondJump()) {
    if (arch_isTablejump2(h))
      return arch_tablejump2(h, retval);
    if (h->prologue.defined && h->epilogue.defined) {
      //printf("pc = %x\n", cpu.pc * 2);
      if (arch_isPrologueJumpx(h))
	return arch_prologue(h, retval);
      else if (arch_isEpilogueJumpx(h))
	return arch_epilogue(h, retval);
    }
  }

  return retval;
}

unsigned archGetRamSize(void) {

  unsigned ramSizeGuess;
  unsigned spl = 0;
  unsigned sph = 0;
  CpuAddr iAddr;
  CpuAddr sp;

  /* LNK.processFirstStackOut: The first stack output instructions sets
     the stack pointer to point to the end of RAM. Something like this:

     -2:	cf ef       	ldi	r28, 0xFF
     -1:	d4 e0       	ldi	r29, 0x04
     0:		de bf       	out	0x3e, r29
     1:		cd bf       	out	0x3d, r28

     Or, if no SPH:
     1:		cf ed       	ldi	r28, 0xDF
     0:		cd bf       	out	0x3d, r28

     Or (FIX140118A: GNU_Toolchain_3.4.3_1072 4.8.1 for xmega):
     -1:	cf ef       	ldi	r28, 0xFF
     0:		cd bf       	out	0x3d, r28
     1:		df e2       	ldi	r29, 0x2F
     2:		de bf       	out	0x3e, r29
  */

  if ((iAddr = cpu.pcAtFirstStackOut) == 0) RRR();
  if (iAddr < 2 || iAddr + 1 >= cpu.iProgSize) RRR();

  if (cpu_isInstr_outN(iAddr + 0, 29, CPU_stackPort + 1)) {
    // This looks like an AVR with SPH
    if (! cpu_isInstr_ldi(iAddr - 2, 28, &spl)) CPURRR();
    if (! cpu_isInstr_ldi(iAddr - 1, 29, &sph)) CPURRR();
    if (! cpu_isInstr_outN(iAddr + 1, 28, CPU_stackPort)) RRR();
  }
  else {
    // This looks like an AVR without SPH ...
    
    if (! cpu_isInstr_ldi(iAddr - 1, 28, &spl)) RRR();
    if (! cpu_isInstr_outN(iAddr + 0, 28, CPU_stackPort)) RRR();
    if (cpu_isInstr_outN(iAddr + 2, 29, CPU_stackPort + 1)) {
      /* FIX140118A: On second thought, it appears that we do have an SPH */ {
	if (! cpu_isInstr_ldi(iAddr + 1, 29, &sph)) CPURRR();
      }
    }
  }
  sp = spl + (sph << 8);

  ramSizeGuess = sp + 1;
  if (ramSizeGuess < cpu.ramStart) RRR();
  ramSizeGuess -= cpu.ramStart;
  return ramSizeGuess;
}

Bool archIsAddrInVectorArea(Arch* h, unsigned addr) {
  return addr <= (h->numInterruptVectors + 1) * h->vectorSize;
}

Arch* archInit(void) {
  Arch* h = myMalloc0(sizeof *h);
  return h;
}

typedef unsigned MazeAddr;

typedef struct {
  unsigned count;
  MazeAddr addr[1];
} MazeAddrList;

typedef struct {
  unsigned firstAddr;
  unsigned lastAddr;
  unsigned index; // Index in the maze.codeBlock array.
} MazeBlock; 

typedef struct {
  MazeAddr nextAddr;
  MazeAddr prevAddr;
  MazeAddr stack[200];

  MazeBlock** block;
  MazeBlock* blockArray;
  unsigned numBlocks;

  MazeAddr* ijmp;
  unsigned* destAddr; /* For unconditional jumps - the destination;
			 For condition jumps - the conditional destination;
			 For calls - the destination;
			 For ijmps - an index in the "branch array". */
  unsigned ijmpSize;
  unsigned ijmpUsed;

  Uint16* flags; 

  unsigned progSize;
  unsigned minInstrSize;
  unsigned stackSize;
  unsigned lastCallFromAddr;

  struct {
    Uint8* instrSize;
    int* stackChange;
  } c;

  Arch* arch;
} Maze;

#define MAZE_F_data		0x0001
#define MAZE_F_code		0x0002 // This is code and it is reached.
#define MAZE_F_isr		0x0004
#define MAZE_F_stack		0x0008
#define MAZE_F_callFrom		0x0010 
#define MAZE_F_jumpFrom		0x0020 
#define MAZE_F_uncondJump	0x0040
#define MAZE_F_condJump		0x0080
#define MAZE_F_callTo		0x0100
#define MAZE_F_ret		0x0200
#define MAZE_F_ijmp		0x0400
#define MAZE_F_pattern		0x0800
#define MAZE_F_longjmpCall	0x1000
#define MAZE_F_callUnknown	0x2000

static unsigned maze_a2c(Maze* h, unsigned addr) {
  return addr / h->minInstrSize;
}

static unsigned mazeGetInstrSize(Maze* h, unsigned addr) {
  return h->c.instrSize[maze_a2c(h, addr)];
}

static void mazeSetInstrSize(Maze* h, unsigned addr, unsigned size) {
  if (size > 0xFF) RRR();
  h->c.instrSize[maze_a2c(h, addr)] = (Uint8) size;
}

unsigned mazeGetStackChange(Maze* h, unsigned addr) {
  return h->c.stackChange[maze_a2c(h, addr)];
}

unsigned mazeGetNumBlocks(Maze* h) {
  return h->numBlocks;
}

static void mazePush(Maze* h, MazeAddr addr) {
  if (h->stackSize >= ARRAYSIZE(h->stack)) RRR();
  h->stack[h->stackSize++] = addr;
}

static void mazeJump(Maze* h, MazeAddr from, MazeAddr to) {
  h->destAddr[from] = to;
  h->flags[to] |= MAZE_F_jumpFrom;
}

static void mazeCall(Maze* h) {
  MazeAddr from = h->prevAddr;
  MazeAddr to = cpuGetDestAddr();
  h->lastCallFromAddr = from;
  h->destAddr[from] = to;
  h->flags[from] |= MAZE_F_callTo;
  //printf("call from %x to %x\n", from, to);
  if (cpuInstrIsCallUnknown())
    h->flags[from] |= MAZE_F_callUnknown;
  else {
    h->flags[to] |= MAZE_F_callFrom;
  /* 100521: I used to push the call destination and proceed with
     the instruction following the call. I had to change the order
     to make longjmp to work (LNK.mazeLongjmp). */
    mazePush(h, h->nextAddr);
    h->nextAddr = to;
  }
}

static void mazeRet(Maze* h) {
  h->flags[h->prevAddr] |= MAZE_F_ret;
  /* What we want here is to pop the next PC from stack. To do that,
     we set PC to an address that has been definitely reached, so that
     we will do the 'pop' at the beginning of the loop. */
  h->nextAddr = h->prevAddr;
}

MazeAddr mazeGetCallDestAddr(Maze* h, MazeAddr src) {
  return h->destAddr[src];
}

static void mazeUncondJump(Maze* h) {
  h->flags[h->prevAddr] |= MAZE_F_uncondJump;
  mazeJump(h, h->prevAddr, h->nextAddr);
}

static void mazeIjmpAlloc(Maze* h, unsigned tableSize) {
  unsigned ijmpSizeRequired = h->ijmpUsed + tableSize + 1;
  if (ijmpSizeRequired > h->ijmpSize) {
    h->ijmpSize = (ijmpSizeRequired + 255) & ~255;
    h->ijmp = myRealloc(h->ijmp, h->ijmpSize * sizeof h->ijmp[0]);
  }
}

static void mazeIjmp(Maze* h) {
  unsigned tableSize = cpuGetIjmpTableSize();
  unsigned dataSize;
  unsigned i;
  if (tableSize == 0) RRR();
  h->flags[h->prevAddr] |= MAZE_F_ijmp;
  h->destAddr[h->prevAddr] = h->ijmpUsed;
  mazeIjmpAlloc(h, tableSize);
  h->ijmp[h->ijmpUsed++] = tableSize;
  if ((dataSize = cpuGetIjmpTableDataSize()) != 0) {
    unsigned dataAddr = cpuGetIjmpTableDataAddr();
    for (i = 0; i < dataSize; i++) {
      if (h->flags[dataAddr + i] & MAZE_F_code) RRR();
      h->flags[dataAddr + i] |= MAZE_F_data;
    }
  }
  for (i = 0; i < tableSize; i++) {
    MazeAddr to = cpuGetIjmpDestAddr(i);
    //printf("to %x\n", to);
    h->ijmp[h->ijmpUsed++] = to;
    h->flags[to] |= MAZE_F_jumpFrom;
    if (i != 0)
      mazePush(h, to);
    else if (to != cpuGetPC())
      RRR();
  }
}

static void mazeCondJump(Maze* h) {
  MazeAddr addr2 = cpuGetDestAddr();
  h->flags[h->prevAddr] |= MAZE_F_condJump;
  mazeJump(h, h->prevAddr, addr2);
  mazePush(h, addr2);
}

unsigned mazeBlockGetSize(Maze* h, MazeBlock* b) {
  return b->lastAddr - b->firstAddr + mazeGetInstrSize(h, b->lastAddr);
}

unsigned mazeBlockGetNumChildren(Maze* h, MazeBlock* b) {
  unsigned flags = h->flags[b->lastAddr];
  if (flags & (MAZE_F_ret | MAZE_F_longjmpCall))
    return 0;
  if (flags & MAZE_F_uncondJump)
    return 1;
  if (flags & MAZE_F_condJump)
    return 2;
  if (flags & MAZE_F_ijmp)
    return h->ijmp[h->destAddr[b->lastAddr]];
  // printf("b=%x %x\n", b->firstAddr, b->lastAddr);
  return 1; // Fall through.
}

static MazeBlock* mazeBlockGetChild(Maze* h, MazeBlock* parent,
				    unsigned childIndex) {
  MazeAddr addr = parent->lastAddr;
  unsigned flags = h->flags[addr];
  MazeBlock* retval = NULL;
  if (flags & MAZE_F_uncondJump) {
    if (childIndex != 0) RRR();
    addr = h->destAddr[addr];
  }
  else if (flags & MAZE_F_ijmp) {
    MazeAddr* table = h->ijmp + h->destAddr[addr];
    unsigned numChildren = *table++;
    if (childIndex >= numChildren) RRR();
    addr = table[childIndex];
  }
  else if (flags & MAZE_F_condJump) {
    if (childIndex == 0)
      addr = parent->lastAddr + mazeGetInstrSize(h, parent->lastAddr);
    else if (childIndex == 1)
      addr = h->destAddr[addr];
    else
      RRR();
  }
  else { // Fall through.
    addr = parent->lastAddr + mazeGetInstrSize(h, parent->lastAddr);
  }
  //printf("addr=%x\n", addr);
  retval = h->block[addr];
  if (retval == NULL) RRR();
  return retval;
}

void mazeRegisterDataBlock(Maze* h, unsigned addr, unsigned size) {
  while (size-- != 0) {
    if (addr >= h->progSize) RRR();
    h->flags[addr] |= MAZE_F_data;
    addr++;
  }
}

void mazeRegisterReachedBlock(Maze* h, unsigned addr, unsigned size) {
  if (size == 0) RRR();
  while (size-- != 0) {
    if (addr >= h->progSize) RRR();
    if (h->flags[addr] & (MAZE_F_data | MAZE_F_code)) RRR();
    h->flags[addr] |= MAZE_F_code | MAZE_F_pattern;
    addr++;
  }
}

void mazeRegisterIsr(Maze* h, unsigned addr) {
  h->flags[addr] |= MAZE_F_isr;
}

typedef struct {
  struct MazeBlockIteratorStack {
    MazeBlock* block;
    unsigned branchIndex;
  } stack[1000];
  MazeBlock* block;
  unsigned stackSize;
  Bool* reached;
} MazeBlockIterator;

static struct MazeBlockIteratorStack* mazeBtPush(Maze* h,
						 MazeBlockIterator* bt,
						 MazeAddr addr) {
  struct MazeBlockIteratorStack* s = NULL;
  if (bt->stackSize >= ARRAYSIZE(bt->stack)) RRR();
  s = bt->stack + bt->stackSize++;
  s->branchIndex = 1;
  s->block = h->block[addr];
  if (s->block == NULL) RRR();
  return s;
}

MazeBlock* mazeGetBlockByAddr(Maze* h, unsigned addr) {
  MazeBlock* b = h->block[addr];
  if (addr >= h->progSize) RRR();
  if (b == NULL) RRR();
  return b;
}

static struct MazeBlockIteratorStack* mazeBtPop(MazeBlockIterator* bt) {
  if (--bt->stackSize == 0)
    return NULL;
  return bt->stack + bt->stackSize - 1;
}

MazeBlockIterator* mazeBtInit(Maze* h, MazeAddr addr) {
  MazeBlockIterator* bt = myMalloc0(sizeof *bt);
  bt->reached = myMalloc0(h->numBlocks * sizeof bt->reached[0]);
  mazeBtPush(h, bt, addr)->branchIndex = 0;
  return bt;
}

void mazeBtDestroy(MazeBlockIterator* bt) {
  myFree(bt->reached);
  myFree(bt);
}

static Bool mazeBtReached(MazeBlockIterator* bt, MazeBlock* b) {
  return bt->reached[b->index];
}

Bool mazeBtGet(Maze* h, MazeBlockIterator* bt) {

  if (bt->stackSize == 0) RRR();
  else {
    struct MazeBlockIteratorStack* s = bt->stack + bt->stackSize - 1;
    MazeBlock* b = s->block;
    if (s->branchIndex == 0) {
      s->branchIndex++;
      //printf("btGet1 %x\n", s->block->addr * 2);
    }
    else {
      unsigned numChildren = mazeBlockGetNumChildren(h, b);
      s = NULL;
      if (numChildren != 0) {
	unsigned i;
	for (i = 0; i < numChildren; i++) {
	  MazeBlock* c = mazeBlockGetChild(h, b, i);
	  if (! mazeBtReached(bt, c)) {
	    s = mazeBtPush(h, bt, c->firstAddr);
	    //printf("btGet2 %x\n", s->block->addr * 2);
	    break;
	  }
	}
      }
      if (s == NULL) {
	while (true) {
	  s = mazeBtPop(bt);
	  if (s == NULL)
	    return false;
	  b = s->block;
	  numChildren = mazeBlockGetNumChildren(h, b);
	  if (s->branchIndex < numChildren) {
	    unsigned i;
	    for (i = s->branchIndex; i < numChildren; i++) {
	      MazeBlock* c = mazeBlockGetChild(h, b, i);
	      if (! mazeBtReached(bt, c)) {
		s->branchIndex = i + 1;
		s = mazeBtPush(h, bt, c->firstAddr);
		//printf("btGet3 %x\n", s->block->addr * 2);
		break;
	      }
	    }
	    if (i < numChildren)
	      break;
	  }
	}
      }
    }

    bt->block = s->block;
    bt->reached[bt->block->index] = true;
  }

  return true;
}

static void mazeFlowOrStack(Maze* h, unsigned addr) {

  if (cpuInstrIsStackChange()) {
    h->flags[addr] |= MAZE_F_stack;
    h->c.stackChange[maze_a2c(h, addr)] = cpuGetStackChange();
  }

  if (false) {

  }
  else if (cpuInstrIsRet())
    mazeRet(h); 
  else if (cpuInstrIsUncondJump())
    mazeUncondJump(h);
  else if (cpuInstrIsIjmp())
    mazeIjmp(h);
  else if (cpuInstrIsCondJump())
    mazeCondJump(h);

  else if (cpuInstrIsCall()) {
    mazeCall(h);

  }
  else if (cpuInstrIsStackChange()) {

  }
  else {
    RRR();
  }
}

void mazeSolve(Maze* h, unsigned startAddr) {

  unsigned addr = startAddr;

  if (h->flags[addr] & MAZE_F_data) RRR();
  if (h->flags[addr] & MAZE_F_code) RRR();

  while (true) {
    if (h->flags[addr] & MAZE_F_code) {
      if (h->stackSize == 0)
	break;
      addr = h->stack[--h->stackSize];
      continue;
    }
    else {
      unsigned n = archParse(h->arch, addr);
      unsigned i;
      if (! cpuIsInstr()) RRR();
      //printf("parse %x\n", addr);
      h->prevAddr = addr;
      h->nextAddr = cpuGetPC();
      //printf("parse %x -> %x\n", addr, h->nextAddr);
      if (h->nextAddr >= h->progSize) RRR();
      mazeSetInstrSize(h, addr, n);
      for (i = 0; i < n; i++) {
	if (h->flags[addr + i] & MAZE_F_data) RRR();
	if (h->flags[addr + i] & MAZE_F_code) RRR();
	h->flags[addr + i] |= MAZE_F_code;
      }
      if (cpuInstrIsFlowControl() || cpuInstrIsStackChange()) {
	mazeFlowOrStack(h, addr);
	if (cpuInstrIsLongjmp()) {
	  unsigned addrAfterCall;
	  unsigned callFrom;
	  if (h->stackSize == 0) RRR();
	  // LNK.mazeLongjmp
	  addrAfterCall = h->stack[--h->stackSize];
	  callFrom = h->lastCallFromAddr;
	  if ((h->flags[callFrom] & MAZE_F_code) == 0) RRR();
	  if (addrAfterCall != callFrom + mazeGetInstrSize(h, callFrom)) RRR();
	  h->flags[callFrom] |= MAZE_F_longjmpCall;
	  /* FIX131114A: Commented out the following statement. (I had a typo,
	     fixem9. There was something that required immediate attention,
	     but because of the typo I missed that. No idea what I was trying
	     to do here. But whatever it was, this leftover statement
	     certainly had to go.)
	     h->stack[--h->stackSize]; */
	}
      }
      addr = h->nextAddr;
    }
  }
}

static Bool maze_getCduBlock(Maze* h, unsigned addr) {
  unsigned size = 0;
  if (addr < h->progSize) {
    unsigned flags = h->flags[addr];
    while (h->flags[addr] == flags) {
      size++;
      addr++;
    }
  }
  return size;
}

static void maze_reportUnreachedBlocks(Maze* h, Arch* arch, Bool totalOnly) {

  Bool prevWasDataBlock = false;
  unsigned startAddr = 0;
  unsigned size;

  while ((size = maze_getCduBlock(h, startAddr)) != 0) {
    unsigned flags = h->flags[startAddr];
    Bool isDataBlock = (flags & MAZE_F_data) != 0;
    if ((flags & MAZE_F_code) == 0) {
      Bool isUnreachedBlock = ! isDataBlock;
      if (0
	  || isDataBlock
	  || size > 2
	  || ! archIsAddrInVectorArea(arch, startAddr)
	  ) {
	Bool singleByteAtTheEndOfDataBlock = 1
	  && isUnreachedBlock
	  && size == 1
	  && prevWasDataBlock
	  ;
	if (! totalOnly || isUnreachedBlock) {
	  if (! singleByteAtTheEndOfDataBlock) {
	    printf("%s block 0x%x - 0x%x (size=%u)\n",
		   isUnreachedBlock ? "Unreached" : "Data",
		   startAddr,
		   startAddr + size - 1,
		   size);
	  }
	}
      }
    }
    startAddr += size;
    prevWasDataBlock = isDataBlock;
  }
}

static void mazeBuildBlockList(Maze* h) {
  unsigned pass;
  for (pass = 0; pass < 2; pass++) {
    unsigned numBlocks = 0;
    unsigned nextAddr = 0;
    while (nextAddr < h->progSize) {
      unsigned flags = h->flags[nextAddr];
      if ((flags & (MAZE_F_code | MAZE_F_pattern)) != MAZE_F_code)
	nextAddr++;
      else {
	MazeBlock dummy;
	MazeBlock* b = h->blockArray + numBlocks;
	if (pass == 0)
	  b = &dummy;
	h->block[nextAddr] = b;
	b->index = numBlocks++;
	b->firstAddr = nextAddr;
	while (true) {
	  unsigned addr = b->lastAddr = nextAddr;
	  flags = h->flags[addr];
	  //printf("addr=%x\n", addr);
	  if ((flags & MAZE_F_code) == 0) {
	    RRRA(addr);
	  }
	  nextAddr += mazeGetInstrSize(h, addr);
	  if ((flags & (MAZE_F_stack | MAZE_F_ret)) == MAZE_F_stack)
	    /* nothing */;
	  else if ((flags & MAZE_F_longjmpCall) != 0)
	    break;
	  else if ((flags & MAZE_F_uncondJump) != 0)
	    break;
	  else if ((flags & MAZE_F_condJump) != 0)
	    break;
	  else if ((flags & MAZE_F_ijmp) != 0)
	    break;

	  else if ((flags & MAZE_F_ret) != 0) {

	    break;
	  }
	  if (nextAddr >= h->progSize) RRR();
	  if (h->flags[nextAddr] & (0
				    | MAZE_F_callFrom
				    | MAZE_F_jumpFrom
				    | MAZE_F_isr))
	    break;
	}
      }
    }
    if (pass == 0) {
      if (numBlocks == 0) RRR();
      h->blockArray = myMalloc0(numBlocks * sizeof h->blockArray[0]);
      h->numBlocks = numBlocks;
    }
  }
}

void mazeFinalize(Maze* h) {
  mazeBuildBlockList(h);
}

void mazeDump(Maze* h, Arch* arch, Bool totalOnly) {
  maze_reportUnreachedBlocks(h, arch, totalOnly);
}

Maze* mazeInit(Arch* arch) {
  Maze* h = myMalloc0(sizeof *h);
  unsigned size = cpuGetProgSize();
  unsigned n;
  h->progSize = size;
  h->flags = myMalloc0(size * sizeof h->flags[0]);
  h->minInstrSize = 2; 
  h->arch = arch;

  n = size;
  //n = size / h->minInstrSize;
#define M(field) h->field = myMalloc0(n * sizeof h->field[0])
  M(destAddr);
  M(block);
#undef M

  n = size / h->minInstrSize;
#define M(field) h->c.field = myMalloc0(n * sizeof h->c.field[0])
  M(instrSize);
  M(stackChange);
#undef M
  return h;
}

static Maze* maze;

typedef struct {
  struct TreeFunction* func;
  unsigned stackDepth;
  unsigned srcAddr;
} TreeCall;

typedef struct {
  int startDepth;
  int depthChange;
  int maxDepth;
  Bool ret;
} TreeBlock;

typedef struct TreeFunction {
  unsigned addr;
  unsigned stackDepth; 
  TreeCall* call;
  unsigned numCalls;
  struct TreeFunction** child;
  unsigned numChildren;
  unsigned callLevel;
  char* name;
  Bool isStackDepthSet;
} TreeFunction;

struct {
  TreeFunction* mainFunction;
  TreeFunction* function;
  TreeFunction unknownFunction;
  TreeBlock* block;
  ElfSymbol** isr;
  unsigned numFunctions;
  unsigned callLevelMax;
  unsigned numIsrs;
  Bool ignoreUnknownFunctions;
} tree;

unsigned treeGetNumFunctions(void) {
  return tree.numFunctions;
}

TreeFunction* treeGetFuncByIndex(unsigned i) {
  return tree.function + i;
}

TreeFunction* treeFindFuncByAddr(unsigned addr) {
  unsigned i;
  for (i = 0; i < tree.numFunctions; i++) {
    if (tree.function[i].addr == addr)
      return tree.function + i;
  }
  printf("addr=%u %x\n", addr, addr);
  RRR();
  return NULL;
}

static TreeFunction* treeFindFuncByName(char* name) {
  unsigned i;
  for (i = 0; i < tree.numFunctions; i++) {
    TreeFunction* func = tree.function + i;
    if (strcmp(func->name, name) == 0)
      return func;
  }
  return NULL;
}

TreeFunction* treeFindFuncByCallAddr(unsigned addr) {
  if (maze->flags[addr] & MAZE_F_callUnknown) {
    if (1
	&& ! tree.ignoreUnknownFunctions
	&& ! cpuIsUnknownICall(addr) 
	) {
      TreeFunction* fputc = treeFindFuncByName("fputc");
      if (fputc != NULL) {
	unsigned offset = addr - fputc->addr;
	if (offset == 0x36
	    || offset == 0x44 // FIX140402B
	    ) {
	  printf("suggest -ignoreICall=fputc+0x%x or\n", offset);
	  printf("-iCall=fputc+0x%x:<your-putchar-name> options\n", offset);
	}
      }
      else {
	printf("suggest -ignoreICall or -iCall options\n");
      }
      RRRA(addr);
    }
    return &tree.unknownFunction;
  }
  else {
    return treeFindFuncByAddr(mazeGetCallDestAddr(maze, addr));
  }
}

static void treeBuildFuncList(void) {
  unsigned pass;
  for (pass = 1; pass <= 2; pass++) {
    unsigned count = 0;
    unsigned pi;
    for (pi = 0; pi < maze->progSize; pi++) {
      if (maze->flags[pi] & (MAZE_F_callFrom | MAZE_F_isr)) {
	TreeFunction* f = tree.function + count++;
	if (pass == 2) {
	  f->addr = pi;
	  f->name = elfAddrToName(f->addr);
	}
      }
    }
    if (pass == 1) {
      if (count == 0) RRR();
      tree.numFunctions = count;
      tree.function = myMalloc0(count * sizeof tree.function[0]);
    }
  }
}

static void treeFindMainFunction(void) {
  TreeFunction* func = treeFindFuncByName("main");
  if (func == NULL) RRR();
  tree.mainFunction = func;
}

static void treeBuildFuncCallLists(void) {
  unsigned fi;
  for (fi = 0; fi < tree.numFunctions; fi++) {
    TreeFunction* func = tree.function + fi;
    unsigned pass;
    for (pass = 1; pass <= 2; pass++) {
      MazeBlockIterator* bt = mazeBtInit(maze, func->addr);
      unsigned count = 0;
      while (mazeBtGet(maze, bt)) {
	MazeBlock* mb = bt->block;
	unsigned size = mazeBlockGetSize(maze, mb);
	unsigned bi;
	for (bi = 0; bi < size; bi++) {
	  MazeAddr srcAddr = mb->firstAddr + bi;
	  if (maze->flags[srcAddr] & MAZE_F_callTo) {
	    if (pass == 2) {
	      TreeCall* c = func->call + count;
	      c->func = treeFindFuncByCallAddr(srcAddr);
	      c->srcAddr = srcAddr;
	    }
	    count++;
	  }
	}
      }
      mazeBtDestroy(bt);
      if (pass == 1) {
	if (count != 0) {
	  func->numCalls = count;
	  func->call = myMalloc0(count * sizeof func->call[0]);
	}
      }
    }
  }
}

static void treeSetCallStackDepths(void) {
  unsigned fi;
  for (fi = 0; fi < tree.numFunctions; fi++) {
    TreeFunction* func = tree.function + fi;
    MazeBlockIterator* bt = mazeBtInit(maze, func->addr);
    unsigned count = 0;
    while (mazeBtGet(maze, bt)) {
      MazeBlock* mb = bt->block;
      TreeBlock* tb = tree.block + mb->index;
      unsigned size = mazeBlockGetSize(maze, mb);
      unsigned bi;
      int depth = 0;
      for (bi = 0; bi < size; bi++) {
	MazeAddr srcAddr = mb->firstAddr + bi;
	unsigned flags = maze->flags[srcAddr];
	if (flags & MAZE_F_stack)
	  depth += mazeGetStackChange(maze, srcAddr);
	if (maze->flags[srcAddr] & MAZE_F_callTo) {
	  TreeCall* c = func->call + count++;
	  c->stackDepth = tb->startDepth + depth;
	}
      }
    }
    mazeBtDestroy(bt);
  }
}

static void treeBuildFuncChildLists(void) {
  unsigned fi;
  for (fi = 0; fi < tree.numFunctions; fi++) {
    TreeFunction* func = tree.function + fi;
    if (func->numCalls != 0) {
      unsigned pass;
      for (pass = 1; pass <= 2; pass++) {
	unsigned numChildren = 0;
	unsigned ci;
	for (ci = 0; ci < func->numCalls; ci++) {
	  TreeCall* c = func->call + ci;
	  /* Check to see if the call is to a function that is referenced
	     in a previous call. */
	  unsigned pi;
	  for (pi = 0; pi < ci; pi++) {
	    TreeCall* p = func->call + pi;
	    if (p->func == c->func)
	      break;
	  }
	  if (pi == ci) { // New function.
	    if (pass == 2)
	      func->child[numChildren] = c->func;
	    numChildren++;
	  }
	}
	if (pass == 1) {
	  func->child = myMalloc0(numChildren * sizeof func->child[0]);
	  func->numChildren = numChildren;
	}
      }
    }
  }
}

static void treeCheckForRecursionsFunc(TreeFunction* func) {
  unsigned stackSizeMax = 200;
  unsigned level = 0;

  struct {
    TreeFunction* func;
    unsigned index;
  }* stack = myMalloc(stackSizeMax * sizeof stack[0]);

  stack[0].func = func;
  stack[0].index = 0;

  while (true) {
    TreeFunction* func = stack[level].func;
    unsigned index = stack[level].index;
    if (index == 0 && level != 0) {
      unsigned i;
      for (i = 0; i < level; i++) {
	if (stack[i].func == func) {
	  unsigned ri;
	  printf("Recursion:\n");
	  for (ri = 0; ri <= level; ri++)
	    printf("  %u: %s%s\n",
		   ri + 1,
		   stack[ri].func->name,
		   ri == level || ri == i ? " (!)" : "");
	  fePrintf(FE_recursion, NULL);
	}
      }
    }
    index++;
    if (func->numChildren == 0 || index > func->numChildren) {
      if (level == 0)
	break;
      level--;
      //printf("--level = %u\n", level);
    }
    else {
      stack[level].index = index;
      if (++level >= stackSizeMax) RRR();
      stack[level].func = func->child[index - 1];
      //printf("++ %u = %s -> %s\n", level, func->name, stack[level].func->name);
      stack[level].index = 0;
    }
  }

  myFree(stack);
}

static void treeCheckForRecursions(void) {
  treeCheckForRecursionsFunc(tree.mainFunction);
  if (tree.numIsrs) {
    unsigned i;
    for (i = 0; i < tree.numIsrs; i++)
      treeCheckForRecursionsFunc(treeFindFuncByAddr(tree.isr[i]->addr));
  }
}

/* This starts from "leaf" functions that do not call anything and
   goes up to top level functions. If there are recursions, this
   will fail? */
static void treeSetFuncCallLevel(void) {

  unsigned doneCount = 0;
  unsigned level = 0;

  while (doneCount < tree.numFunctions) {
    unsigned fi;
    Bool doneAtLeastOneNew = false;
    for (fi = 0; fi < tree.numFunctions; fi++) {
      TreeFunction* func = tree.function + fi;
      Bool doItNow = false;
      if (func->numChildren == 0) {
	// We handle all functions without children at level = 0.
	if (level == 0)
	  doItNow = true;
      }
      else if (func->callLevel == 0) { // Not yet set?
	unsigned ci;
	doItNow = level != 0;
	for (ci = 0; ci < func->numChildren; ci++) {
	  TreeFunction* c = func->child[ci];
	  if (c->numChildren != 0) {
	    if (c->callLevel == 0 || c->callLevel == level) {
	      doItNow = false;
	      break;
	    }
	  }
	}
      }
      if (doItNow) {
	func->callLevel = level;
	doneAtLeastOneNew = true;
	doneCount++;
      }
    }
    if (! doneAtLeastOneNew) RRR();
    tree.callLevelMax = level;
    level++;
  }
}

static void treeBlockSetStackChangeAndMaxDepth(MazeBlock* mb) {

  TreeBlock* tb = tree.block + mb->index;
  MazeAddr nextAddr = mb->firstAddr;
  unsigned blockSize = mazeBlockGetSize(maze, mb);
  unsigned endAddr = nextAddr + blockSize;

  tb->depthChange = 0;
  tb->maxDepth = 0;

  while (nextAddr < endAddr) {

    MazeAddr addr = nextAddr;
    unsigned flags = maze->flags[addr];
    nextAddr += mazeGetInstrSize(maze, addr);

    if ((flags & MAZE_F_code) == 0) RRR();

    if (flags & MAZE_F_ret)
      tb->ret = true;

    if (flags & MAZE_F_stack) {
      int change = mazeGetStackChange(maze, addr);
      tb->depthChange += change;
      if (tb->maxDepth < tb->depthChange)
	tb->maxDepth = tb->depthChange;
    }
    else if (flags & MAZE_F_callTo) {
      TreeFunction* func = treeFindFuncByCallAddr(addr);
      int depth;
      if (func == NULL) RRR();
      if (! func->isStackDepthSet) {
	printf("func=%x mb=%x size=%u addr=%x\n", func->addr, mb->firstAddr, blockSize, addr);
	RRR();
      }
      depth = tb->depthChange + (cpuGetCallStackDepth() + func->stackDepth);
      if (tb->maxDepth < depth)
	tb->maxDepth = depth;
    }
    //printf("mb %x set %x depth = %d\n", mb->firstAddr, addr, tb->maxDepth);
  }

  //printf("mb %x depth = %d\n", mb->firstAddr, tb->maxDepth);
}

static void treeBlockSetChildrenDepth(MazeBlockIterator* bt) {
  MazeBlock* mb = bt->block;
  TreeBlock* tb = tree.block + mb->index;
  int startDepth = tb->startDepth + tb->depthChange;
  unsigned nc = mazeBlockGetNumChildren(maze, mb);
  unsigned i;
  for (i = 0; i < nc; i++) {
    MazeBlock* mc = mazeBlockGetChild(maze, mb, i);
    TreeBlock* tc = tree.block + mc->index;
    if (! mazeBtReached(bt, mc))
      tc->startDepth = startDepth;
    else if (tc->startDepth != startDepth) {

      fePrintf(FE_stackChangeLoop,
	       ": %x -> %x\n",
	       mb->firstAddr,
	       mc->firstAddr);
      RRR();
    }
  }
}

static void treeSetFuncStackDepthOne(TreeFunction* func) {

  MazeBlockIterator* bt = mazeBtInit(maze, func->addr);

  func->isStackDepthSet = true;
  if (! args.includeBadInterrupt && (func->addr == badInterrupt)) return;

  while (mazeBtGet(maze, bt)) {
    MazeBlock* mb = bt->block;
    TreeBlock* tb = tree.block + mb->index;
    int depth;
    treeBlockSetStackChangeAndMaxDepth(mb);
    depth = tb->startDepth + tb->maxDepth;
    if (depth > 0)
      if (func->stackDepth < (unsigned) depth)
	func->stackDepth = depth;
    treeBlockSetChildrenDepth(bt);
    if (tb->ret) {
      if (tb->startDepth < 0) RRR();
      if (tb->depthChange > 0) RRR();
      if (tb->startDepth + tb->depthChange != 0) {
	if (tb->startDepth + tb->depthChange < 0)
	  fe(FE_negativeStackChange, mb->firstAddr);
	else {
	  printf("mb %x tbStart=%d tbChange=%d\n",
		 mb->firstAddr,
		 tb->startDepth,
		 tb->depthChange);
	  RRR();
	}
      }
    }
  }
  //printf("func %x depth = %d\n", func->addr, func->stackDepth);
}

static void treeSetFuncStackDepthAll(void) {
  unsigned level;
  for (level = 0; level <= tree.callLevelMax; level++) {
    unsigned fi;
    for (fi = 0; fi < tree.numFunctions; fi++) {
      TreeFunction* func = tree.function + fi;
      if (func->callLevel == level) {
	if (func->isStackDepthSet) RRR();
	treeSetFuncStackDepthOne(func);
      }
    }
  }
}

static void tree_initUnknownFunc(void) {
  TreeFunction* f = &tree.unknownFunction;
  f->name = "<UnknownFunction>";
  f->isStackDepthSet = true;
}

void treeBuild(unsigned numIsrs, ElfSymbol** isr) {
  unsigned numBlocks = mazeGetNumBlocks(maze);
  tree.numIsrs = numIsrs;
  tree.isr = isr;
  if (numBlocks == 0) RRR();
  tree.block = myMalloc0(numBlocks * sizeof tree.block[0]);
  tree_initUnknownFunc();
  treeBuildFuncList();
  treeFindMainFunction();
  treeBuildFuncCallLists();
  treeBuildFuncChildLists();
  treeCheckForRecursions();
  treeSetFuncCallLevel();
  treeSetFuncStackDepthAll();
  treeSetCallStackDepths();
}

static struct {
  TreeFunction** funcListSortedByName;
  unsigned numFunctions;

  TreeFunction** isrSortedByDepthAndName;

  Arch* arch;
  Bool thereAreCallsFromInterrupts;
} data;

#define SIM_callDepth 2 

static int getTotalCallDepth(TreeCall* c) {
  return c->stackDepth + SIM_callDepth + c->func->stackDepth;
}

static int compareCallListEntry(const void* obj1, const void* obj2) {
  TreeCall* c1 = (void*) obj1;
  TreeCall* c2 = (void*) obj2;
  int retval = getTotalCallDepth(c2) - getTotalCallDepth(c1);
  if (retval == 0)
    retval = strcmp(c1->func->name, c2->func->name);
  if (retval == 0)
    retval = c1->srcAddr < c2->srcAddr ? -1 : 1;
  return retval;
}

static void sortCallLists(void) {
  unsigned fi;
  for (fi = 0; fi < tree.numFunctions; fi++) {
    TreeFunction* func = tree.function + fi;
    if (func->numCalls != 0) {
      qsort(func->call,
	    func->numCalls,
	    sizeof func->call[0],
	    compareCallListEntry);
    }
  }
}

static int compareIsrByDepthAndName(const void* obj1, const void* obj2) {
  TreeFunction* f1 = *(void**) obj1;
  TreeFunction* f2 = *(void**) obj2;
  int retval;
  if (f1 == NULL) RRR();
  if (f2 == NULL) RRR();
  retval = (int) f2->stackDepth - (int) f1->stackDepth;
  if (retval == 0)
    retval = strcmp(f1->name, f2->name);
  return retval;
}

static int compareIsrByName(const void* obj1, const void* obj2) {
  TreeFunction* f1 = *(void**) obj1;
  TreeFunction* f2 = *(void**) obj2;
  if (f1 == NULL) RRR();
  if (f2 == NULL) RRR();
  return strcmp(f1->name, f2->name);
}

static void sortIsrListByDepthAndName(void) {
  if (data.arch->numIsrs != 0) {
    TreeFunction** list = myMalloc(data.arch->numIsrs * sizeof list[0]);
    unsigned i;
    data.isrSortedByDepthAndName = list;
    if (data.arch->isr == NULL) RRR();
    for (i = 0; i < data.arch->numIsrs; i++) {
      ElfSymbol* s = data.arch->isr[i];
      TreeFunction* func = treeFindFuncByAddr(s->addr);
      list[i] = func;
      func->name = s->name;
    }
    qsort(list, data.arch->numIsrs, sizeof list[0], compareIsrByDepthAndName);
  }
}

static void dumpTotal(unsigned maxMainDepth, unsigned maxIsrDepth) {
  unsigned maxDepth = maxMainDepth + maxIsrDepth;
  unsigned totalRamUsage = maxDepth + elfGetBssAndDataSize();
  unsigned ramSize = archGetRamSize();
  if (! args.totalOnly) {
    printf("\n");
    printf("     Max main depth = %u\n", maxMainDepth);
    printf("Max interrupt depth = %u\n", maxIsrDepth);
    printf("\n");
    printf("Total stack depth = %u bytes\n", maxDepth);
    printf("Data size = %u bytes\n", elfGetBssAndDataSize());
  }
  // FIX121028A: Replaced '=' with ':'
  printf("Total%s %u bytes (%.1f%% Full)\n",
	 args.format <= 19 ? " RAM usage =" : "Data:",
	 totalRamUsage,
	 (double) totalRamUsage / ramSize * 100);
  if (totalRamUsage >= ramSize) RRR();
}

/* Stack depth in V4 did not include the children. This function
   subtracts the children to get the V4-style depth. */
static unsigned fsd4(TreeFunction* func) {
  unsigned retval = func->stackDepth;
  if (func->numCalls != 0) {
    unsigned maxCallDepth = 0;
    unsigned startDepth = 0;
    unsigned i;
    for (i = 0; i < func->numCalls; i++) {
      TreeCall* c = func->call + i;
      if (i == 0) {
	startDepth = c->stackDepth;
	maxCallDepth = c->func->stackDepth;
      }
      else {
	if (c->stackDepth != startDepth) RRR();
	if (maxCallDepth < c->func->stackDepth)
	  maxCallDepth = c->func->stackDepth;
      }
    }
    retval -= maxCallDepth + SIM_callDepth;
  }
  return retval;
}

static void dumpV4StackTree3(unsigned level, unsigned depth,
			     TreeFunction* func) {
  unsigned i;
  printf("%5u %3u ", depth, level);
  for (i = 0; i < level; i++)
    printf("  ");
  printf("%s(%u) at 0x%x\n", func->name, fsd4(func), func->addr);
}

/* NOTE: this works only if middle blocks do not change level and
   calls to children only from middle blocks (i.e., first all pushes,
   then calls, then pops) */
static void dumpV4StackTree2(TreeFunction* func0, unsigned* maxDepthPtr) {

  unsigned stackSizeMax = 100;
  struct {
    TreeFunction* func;
    unsigned index;
  }* stack = myMalloc(stackSizeMax * sizeof stack[0]);

  unsigned level = 0;
  unsigned depth = SIM_callDepth;
  unsigned maxDepth = 0;

  stack[0].func = func0;
  stack[0].index = 0;

  while (true) {
    TreeFunction* func = stack[level].func;
    unsigned index = stack[level].index;
    if (index == 0) {
      depth += fsd4(func);
      if (maxDepth < depth)
	maxDepth = depth;
      dumpV4StackTree3(level, depth, func);
    }
    index++;
    if (func->numChildren == 0 || index > func->numChildren) {
      if (level == 0)
	break;
      depth -= fsd4(func) + SIM_callDepth;
      level--;
    }
    else {
      stack[level].index = index;
      depth += SIM_callDepth;
      if (++level >= stackSizeMax) RRR();
      stack[level].func = func->child[index - 1];
      stack[level].index = 0;
    }
  }

  *maxDepthPtr = maxDepth;
  myFree(stack);
}

static void dumpV4StackTree(void) {

  static char header[] = "Depth Lev Function";
  unsigned maxMainDepth;
  unsigned maxIsrDepth = 0;

  printf("\nMain call tree:\n%s\n", header);
  dumpV4StackTree2(tree.mainFunction, &maxMainDepth);

  if (data.arch->numIsrs != 0) {
    unsigned isrSize = data.arch->numIsrs * sizeof (TreeFunction*);
    TreeFunction** isr = myMalloc(isrSize);
    unsigned maxDepth;
    unsigned i;
    memcpy(isr, data.isrSortedByDepthAndName, isrSize);
    printf("\nInterrupt call tree:\n%s\n", header);
    for (i = 0; i < data.arch->numIsrs; i++)
      isr[i] = data.isrSortedByDepthAndName[i];
    qsort(isr, data.arch->numIsrs, sizeof isr[0], compareIsrByName);
    for (i = 0; i < data.arch->numIsrs; i++) {
      TreeFunction* func = isr[i];
      
      if (args.includeBadInterrupt
	  || strcmp(func->name, "__bad_interrupt") != 0) {
	dumpV4StackTree2(func, &maxDepth);
	if (maxIsrDepth < maxDepth)
	  maxIsrDepth = maxDepth;
      }
    }
    myFree(isr);
  }

  dumpTotal(maxMainDepth, maxIsrDepth);
}

static void markDataBlocks(void) {
  unsigned i;
  for (i = 0; i < elf.numSymbols; i++) {
    ElfSymbol* sym = elf.symbol + i;
    if (sym->type == 'd')
      mazeRegisterDataBlock(maze, sym->addr, sym->size);
  }
}

static void markStandardPatternsReached(void) {
  unsigned i;
  for (i = 0; i < archGetNumReachedPatterns(data.arch); i++) {
    ArchPattern* p = archGetReachedPattern(data.arch, i);
    mazeRegisterReachedBlock(maze, p->addr, p->size);
  }
}

static void doMaze(void) {

  unsigned i;

  maze = mazeInit(data.arch);
  markDataBlocks();
  if (elfIsArm()) mazeSolve(maze, 0x12c); 
  mazeSolve(maze, 0);

  for (i = 0; i < data.arch->numInterruptVectors; i++) {
    mazeSolve(maze, (i + 1) * data.arch->vectorSize);
  }

  for (i = 0; i < data.arch->numIsrs; i++) {
    ElfSymbol* s = data.arch->isr[i];
    mazeRegisterIsr(maze, s->addr);
  }

  markStandardPatternsReached();
  mazeFinalize(maze);
  mazeDump(maze, data.arch, args.totalOnly);
}

static int compareFuncName(const void* obj1, const void* obj2) {
  TreeFunction* f1 = *(void**) obj1;
  TreeFunction* f2 = *(void**) obj2;
  return strcmp(f1->name, f2->name);
}

static void createFuncListSortedByName(void) {
  unsigned n = data.numFunctions = treeGetNumFunctions();
  TreeFunction** list = myMalloc(n * sizeof list[0]);
  unsigned i;
  data.funcListSortedByName = list;
  for (i = 0; i < data.numFunctions; i++) {
    TreeFunction* mf = list[i] = treeGetFuncByIndex(i);
    mf->name = elfAddrToName(mf->addr);
  }
  qsort(list, n, sizeof list[0], compareFuncName);
  if (data.numFunctions == 0) RRR();
}

static void dumpNewStackTree(void) {

  unsigned cpuCallStackDepth = cpuGetCallStackDepth();
  int maxIsrDepth = 0;
  unsigned fi;
  unsigned i;
  char depthString[64];

  if (! args.totalOnly)
    printf("\n");
  if (data.funcListSortedByName == NULL) RRR();
  for (fi = 0; fi < data.numFunctions; fi++) {
    TreeFunction* func = data.funcListSortedByName[fi];
    if (args.includeBadInterrupt
	|| strcmp(func->name, "__bad_interrupt") != 0) {
      if (func->numCalls != 0) {
	unsigned ci;
	if (! args.totalOnly)
	  printf("%s @ 0x%x\n", func->name, func->addr);
	if (func->call == NULL) RRR();
	for (ci = 0; ci < func->numCalls; ci++) {
	  TreeCall* c = func->call + ci;
	  unsigned totalDepth =
	    c->stackDepth
	    + cpuCallStackDepth
	    + c->func->stackDepth;
	  sprintf(depthString, "%u + %u + %u = %u%c"
		  ,c->stackDepth
		  ,cpuCallStackDepth
		  ,c->func->stackDepth
		  ,totalDepth
		  ,c->func->numCalls != 0 ? '*' : ' ');
		  
	  if (! args.totalOnly)
	    printf("%20s  %s (0x%x -> 0x%x)\n"
		   ,depthString
		   ,func->call[ci].func->name
		   ,c->srcAddr
		   ,c->func->addr);
	}
      }
    }
  }

  if (! args.totalOnly)
    printf("\nTop level\n");

  for (i = 0; i <= data.arch->numIsrs; i++) {
    TreeFunction* func = i == 0
      ? tree.mainFunction
      : data.isrSortedByDepthAndName[i - 1];
    if (args.includeBadInterrupt
	|| strcmp(func->name, "__bad_interrupt") != 0) {
      int total = func->stackDepth + SIM_callDepth;
      if (i != 0 && func->numCalls != 0)
	data.thereAreCallsFromInterrupts = true;
      sprintf(depthString, "%u + %u = %u%c"
	      ,SIM_callDepth
	      ,func->stackDepth
	      ,total
	      ,func->numCalls != 0 ? '*' : ' ');
      if (! args.totalOnly)
	printf("%20s  %s\n"
	       ,depthString
	       ,func->name);
      if (i != 0) {
	if (maxIsrDepth < total)
	  maxIsrDepth = total;
      }
    }
  }

  
  dumpTotal(tree.mainFunction->stackDepth + cpuGetCallStackDepth(),
	    maxIsrDepth);
}

static void dumpStackTree(void) {
  if (args.format == 4)
    dumpV4StackTree();
  else
    dumpNewStackTree();
}

static unsigned symbolNameToAddr(char* name) {
  ElfSymbol* s = elfFindSymbolByName(name);
  if (s == NULL) {
    printf("Symbol %s not found\n", name);
    RRR();
  }
  return s->addr;
}

static void initCpuIcallList(void) {
  if (args.iCallListSize != 0) {
    unsigned i;
    cpu.icall = myMalloc0(sizeof * cpu.icall);
    cpu.icall->size = args.iCallListSize;
    cpu.icall->ptr = myMalloc0(args.iCallListSize * sizeof cpu.icall->ptr[0]);
    for (i = 0; i < args.iCallListSize; i++) {
      MainICall* arg = args.iCallList + i;
      CpuICallListEntry* e = cpu.icall->ptr + i;
      e->src = symbolNameToAddr(arg->src) + arg->srcOffset;
      if (arg->dstCount > 1) RRR();
      if ((e->dstCount = arg->dstCount) != 0) {
	e->dst = myMalloc(1 * sizeof e->dst[0]);
	e->dst[0] = symbolNameToAddr(arg->dst[0]);
      }
    }
  }
}

static Bool startsWith(char* str, char* prefix) {
  unsigned prefixLen = strlen(prefix);
  return strncmp(str, prefix, prefixLen) == 0;
}

static char ignoreICallPrefix[] = "-ignoreICall";
static char iCallPrefix[] = "-iCall";

static MainICall* addEntryToICallList(char* src, unsigned srcLen,
				      unsigned offset) {
  MainICall* p;
  args.iCallList =
    myRealloc(args.iCallList,
	      (args.iCallListSize + 1) * sizeof args.iCallList[0]);
  p = args.iCallList + args.iCallListSize++;
  p->src = myMalloc(srcLen + 1);
  memcpy(p->src, src, srcLen);
  p->src[srcLen] = 0;
  p->srcOffset = offset;
  p->dst = NULL;
  p->dstCount = 0;
  return p;
}

static void parseIgnoreICall(char* arg) {
  char* p = arg + strlen(ignoreICallPrefix);
  if (*p == 0)
    args.ignoreICallAll = true;
  else {
    unsigned offset;
    unsigned nameLen;
    char* name;
    if (*p++ != '=') RRR();
    name = p;
    if ((p = strchr(name, '+')) == NULL) RRR();
    nameLen = p - name;
    if (*p++ != '+') RRR();
    if (*p++ != '0') RRR();
    if (*p++ != 'x') RRR();
    if (! isxdigit(*p)) RRR();
    offset = strtoul(p, &p, 16);
    if (*p != 0) RRR();
    addEntryToICallList(name, nameLen, offset);
  }
}

static void parseICall(char* arg) {

  MainICall* e;
  unsigned srcLen;
  unsigned srcOffset;
  unsigned dstLen;
  char* p = arg + strlen(iCallPrefix);
  char* src;

  if (*p++ != '=') RRR();
  src = p;
  if ((p = strchr(src, '+')) == NULL) RRR();
  srcLen = p - src;
  if (*p++ != '+') RRR();
  if (*p++ != '0') RRR();
  if (*p++ != 'x') RRR();
  if (! isxdigit(*p)) RRR();
  srcOffset = strtoul(p, &p, 16);
  e = addEntryToICallList(src, srcLen, srcOffset);
  do {
    char* dst;
    if (*p++ != ':') RRR();
    dst = p;
    p = strchr(dst, ':');
    if (p == NULL)
      dstLen = strlen(dst);
    else
      dstLen = p - dst;
    e->dst = myRealloc(e->dst, (e->dstCount + 1) * sizeof e->dst[0]);
    {
      char* tmp = myMalloc(dstLen + 1);
      memcpy(tmp, dst, dstLen);
      tmp[dstLen] = 0;
      e->dst[e->dstCount++] = tmp;
    }
  } while (p != NULL);
}

static void parseArgs(int argc, char** argv) {

  int i = 0;

  args.format = 5; /* FIX121201A: Was 1000. I don't remember what was the idea
		      at the time. But what I want now is something similar
		      to elf2ezmap. I.e., we want it to be 0 by default.
		      Except that in this case we do not really want it
		      below 4. (Well, I guess 0 is fine too. Because the check
		      for 4 is "==4". But it really has to be "<=4".) */

  while (++i < argc) {
    char* arg = argv[i];
    if (*arg != '-') {
      if (args.name != NULL) RRR();
      args.name = arg;
    }
    else {
      if (strcmp(arg, "-format") == 0) {
	if (++i >= argc) RRR();
	arg = argv[i];
	if (strcmp(arg, "v4") == 0)
	  args.format = 4;
	else if (strcmp(arg, "v19") == 0)
	  args.format = 19;
	else
	  args.format = atoi(arg);
      }
      else if (strcmp(arg, "-totalOnly") == 0)
	args.totalOnly = true;
      else if (strcmp(arg, "-allowCallsFromIsr") == 0)
	args.allowCallsFromIsr = true;
      else if (strcmp(arg, "-wrap0") == 0)
	args.wrap0 = true;
      else if (strcmp(arg, "-includeBadInterrupt") == 0)
	args.includeBadInterrupt = true;
      else if (startsWith(arg, ignoreICallPrefix))
	parseIgnoreICall(arg);
      else if (startsWith(arg, iCallPrefix))
	parseICall(arg);
      else {
	printf("arg=%s\n", arg);
	RRR();
      }
    }
  }
  if (args.name == NULL) RRR();
}

int main(int argc, char** argv) {

  if (argc < 2) {
    printf("EZStack version %s\n", VERSION);
  }
  else {
#define M(type,size) if (sizeof(type) != size) RRR();
    M(Uint32, 4);
    M(Int32, 4);
    M(Uint16, 2);
    M(Int16, 2);
    M(Uint8, 1);
    M(Int8, 1);
#undef M

    { Uint16 s = 1; if (((Uint8*) &s)[0] != 1) RRR(); } // big endian?

    parseArgs(argc, argv);
    elfReadFile(args.name);
    if (! args.totalOnly)
      printf("Text size = %u\n", elfGetTextSize());
    cpuInit(elfGetText(), elfGetTextSize(), elfGetRamStart());
    cpu.wrap0 = args.wrap0;
    initCpuIcallList();
    data.arch = archInit();
    archParseStandardPatterns(data.arch);
    archGuessNumInterruptVectors(data.arch);
    doMaze();
    tree.ignoreUnknownFunctions = args.ignoreICallAll;
    treeBuild(data.arch->numIsrs, data.arch->isr);
    if (! args.totalOnly)
      printf("Number of interrupt vectors = %u\n",
	     data.arch->numInterruptVectors + 1);
    createFuncListSortedByName();
    sortCallLists();
    sortIsrListByDepthAndName();
    dumpStackTree();
    if (data.thereAreCallsFromInterrupts && ! args.allowCallsFromIsr)
      fePrintf(FE_callFromIsr, ": There are calls from interrupts!");
    if (! args.totalOnly)
      printf("Done\n");
  }

  return EXIT_SUCCESS;
}
