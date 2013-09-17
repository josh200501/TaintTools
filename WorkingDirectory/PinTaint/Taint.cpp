// Simple example of tainting memory from a system call
#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>



// Will want to use taint structure instead
// Byte range of tainted memory
struct range{
	// Start of tainted memory
	UINT64 start;
	// End of tainted memory
	UINT64 end;
};

// Prototype structure to maintain status of taint
struct taintStat{
	// Check if tainted at all
	bool isTainted;
	// Tainted by environment
	bool envTaint;
	// Tainted by file
	bool fileTaint;
	// Tainted by user input
	bool userTaint;
	// Tainted by network input
	bool netTaint;
};

// Entry point for main executable
UINT64 entryPoint;
bool passedEntryPoint = false;

// List to manage tainted bytes
// Don't need now, replaced by addressTainted
std::list<struct range> bytesTainted;

// List to manage tainted addresses
std::list<UINT64> addressTainted;
// List to manage tainted registers
// NOTE: the REG enum type is provided by Pin
std::list<REG> taintedRegs;

// Function to check if a register is tainted
bool regAllReadyTainted(REG reg){
	// Create iterator
	list<REG>::iterator i;
	// Check all registers
	for (i = taintedRegs.begin(); i != taintedRegs.end(); i++){
		// Check for matching register (means it is in the list and tainted)
		if (*i == reg)
			return true;
	}
	// Register is not tainted
	return false;
}

// Function to taint a register
// NOTE: This will change. More detailed tainting will be done here instead of just
// adding the register to a tainting list.
bool taintReg(REG reg){
	if (regAllReadyTainted(reg)){
		cout << "\t\t\t " <<REG_StringShort(reg) << " is already tainted." << endl;
	}

	// Switch to evaluate each register and its' sub-registers
	switch(reg){
		// A-family of registers
		case REG_RAX:	taintedRegs.push_front(REG_RAX);
		case REG_EAX:	taintedRegs.push_front(REG_EAX);
		case REG_AX:	taintedRegs.push_front(REG_AX);
		case REG_AH:	taintedRegs.push_front(REG_AH);
		case REG_AL:	taintedRegs.push_front(REG_AL);
			break;

		// B-family of registers
		case REG_RBX:	taintedRegs.push_front(REB_RBX);
		case REG_EBX:	taintedRegs.push_front(REB_EBX);
		case REG_BX:	taintedRegs.push_front(REB_BX);
		case REG_BH:	taintedRegs.push_front(REB_BH);
		case REG_BL:	taintedRegs.push_front(REB_BL);

	}

}

// Pin function to print the usage of this Pin Tool
INT32 Usage(){
	cerr << "Simple memory tainting from system call." << endl;
	return -1;
}

// Function to call when memory is read
VOID ReadMem(UINT64 insAddr, std::string insDis, UINT64 memOp){
	
	//std::cout << "READ MEM: " << insAddr << " : " << insDis << endl;
	// Create iterator
	list<struct range>::iterator i;
	UINT64 addr = memOp;
	for (i = bytesTainted.begin(); i != bytesTainted.end(); i++){
		if (addr >= i->start && addr < i->end){
			std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
		}
	}
}

// Function to call when memory is written to
VOID WriteMem(UINT64 insAddr, std::string insDis, UINT64 memOp){
	
	//std::cout << "WRITE MEM: " << insAddr << " : " << insDis << endl;
	// Creat iterator
	list<struct range>::iterator i;
	UINT64 addr = memOp;
	for (i = bytesTainted.begin(); i != bytesTainted.end(); i++){
		if (addr >= i->start && addr < i->end){
			std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
		}
	}
}

/*
// Register a function to call when an image is loaded
VOID image(IMG img, VOID *v){
	if (IMG_IsMainExecutable(img)) {
		entryPoint = IMG_Entry(img);
		cout << "Entry point for main executable: " << entryPoint << endl;
	}

	// Print out the name of every symbol in a particular image
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
		cout << "Symbol: " << SYM_Name(sym) << endl;
	}

	cout << "Symobl: " << SYM_Name(IMG_RegsymHead(img)) << endl;
}*/

// Check what type of instruction we have
VOID Instruction(INS ins, VOID *v){
	
	// Print out ASM instructions if we have passed the entry point
	/*
	if (!passedEntryPoint && INS_Address(ins))
		passedEntryPoint = true;
	if (passedEntryPoint){
		string instruction = string(INS_Disassemble(ins));
		cout <<  INS_Address(ins) << " : " << instruction << endl;
	}*/
	// Print out every instruction
	//cout << (INS_Address(ins)) << " : " << (INS_Disassemble(ins)) << endl;

	if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
	//cout << "Calling read instruction evaluation." << endl;
	INS_InsertCall(
	    ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
	    IARG_ADDRINT, INS_Address(ins),
	    IARG_PTR, new string(INS_Disassemble(ins)),
	    IARG_MEMORYOP_EA, 0,
	    IARG_END);
	}
	else if (INS_MemoryOperandIsWritten(ins, 0)){
	//cout << "Calling write instruction evaluation." << endl;
	INS_InsertCall(
	    ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
	    IARG_ADDRINT, INS_Address(ins),
	    IARG_PTR, new string(INS_Disassemble(ins)),
	    IARG_MEMORYOP_EA, 0,
	    IARG_END);
	}
}

// The first thing the Pin tool will do is read open and we want to skip this
static unsigned int voidFirstOpen;
static unsigned int numSysCalls = 0;
#define VOIDFIRSTOPEN(){if (voidFirstOpen++ == 0) return;}

// Create an entry point for all system calls
VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	// Create structure to store our taint
	struct range taint;
	numSysCalls++;
	//cout << "SysCall # " << PIN_GetSyscallNumber(ctx, std) << endl;
	//cout << "SysCall Count - " << std::dec << numSysCalls << endl;
	
	switch (PIN_GetSyscallNumber(ctx, std)){

		// System call is read (__NR_read == 0)
		case __NR_read:
			// Void the first open
			VOIDFIRSTOPEN()
			cout << "[SYSCALL] read Syscall detected!" << endl;
			// Get the arguments from the system call
			// Argument 0 is the system call value
			// Argument 1 is the memory address to start reading from 
			taint.start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
			// Argument 2 is the memory address where to stop reading from 
			taint.end = taint.start + static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
			// Store the taint
			bytesTainted.push_back(taint);

			std::cout << "[TAINT]\t\t\tBytes tainted from " << std::hex << "0x" << taint.start << " to 0x" << taint.end << endl;
			std::cout << "\t\t\t\tTainting done by read() system call." << endl;
			std::cout << "Total of " << dec << static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2))) << " bytes tainted." << endl;  
			break;
		
		// System call is write (__NR_write == 0)
		case __NR_write:
			cout << "[SYSCALL] write Syscall detected!" << endl;
			break;
		
		// System call is open (__NR_open == 2)
		case __NR_open:
			cout << "[SYSCALL] open Syscall detected!" << endl;
			break;
		
		// System call is close (__NR_open == 3)
		case __NR_close:
			cout << "[SYSCALL] close Syscall detected!" << endl;
			break;

		// System call is fstat (__NR_open == 5)
		case __NR_fstat:
			cout << "[SYSCALL] fstat Syscall detected!" << endl;
			break;

		// System call is mmap (__NR_mmap == 9)
		case __NR_mmap:
			cout << "[SYSCALL] mmap Syscall detected!" << endl;
			break;
		
		// System call is mprotect (__NR_mprotect == 10)
		case __NR_mprotect:
			cout << "[SYSCALL] mprotect Syscall detected!" << endl;
			break;

		// System call is munmap (__NR_munmap == 11)
		case __NR_munmap:
			cout << "[SYSCALL] munmap Syscall detected!" << endl;
			break;

		// System call is brk (__NR_brk == 12)
		case __NR_brk:
			cout << "[SYSCALL] brk Syscall detected!" << endl;
			break;

		// System call is access (__NR_access == 21)
		case __NR_access:
			cout << "[SYSCALL] access Syscall detected!" << endl;
			break;

		// System call is arch_prctl (__NR_arch_prctl == 158)
		case __NR_arch_prctl:
			cout << "[SYSCALL] arch_prctl Syscall detected!" << endl;
			break;

		// System call is exit_group (__NR_exit_group == 231)
		case __NR_exit_group:
			cout << "[SYSCALL] exit_group Syscall detected!" << endl;
			break;

		// Default action for other system calls
		default:
			cout << "Syscall made but we don't know what it is: " << std::dec << PIN_GetSyscallNumber(ctx, std) << endl;
			break;
	}
}

/* Pin calls this functino every time a new img is loaded.
It can instrumnet the image, but this implementation currently
does not. Note that imgs (including shared libraries) are loaded lazily. */
VOID ImageLoad(IMG img, VOID *v){
	// Print out the name of the image currently being loaded
	cout << "Loading " << IMG_Name(img).c_str() << " Image id = " << IMG_Id(img) << endl;

	// Check to see if our image is the main image (will be the name of the executable being traced)
	if (IMG_IsMainExecutable(img)) {
		entryPoint = IMG_Entry(img);
		cout << "Entry point for main executable: " << entryPoint << endl;
	}

	// Print out the name of every symbol in a particular image
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
		//cout << "Symbol: " << SYM_Name(sym) << endl;
	}

	//cout << "Symobl: " << SYM_Name(IMG_RegsymHead(img)) << endl;

	// Attempt to find the main() function
	RTN mainFunc = RTN_FindByName(img, MAIN);
	if (RTN_Valid(mainFunc))
		cout << "Main is valid! " << RTN_Address(mainFunc) << endl;
}

/* Pin calls this function every time a new img is unloaded.
After this point, the img can not be instrumented. */
VOID ImageUnload(IMG img, VOID *v){
	cout << "Unloading " << IMG_Name(img).c_str() << endl;
}

// Main function
int main(int argc, char *argv[]){
	
	// Initialze pin
	if (PIN_Init(argc, argv)) return Usage();
	// Initialize the symbol table
	PIN_InitSymbols();
	// Set syntax to Intel style
	PIN_SetSyntaxIntel();
	// Register ImageLoad to be called when an image is loaded
	IMG_AddInstrumentFunction(ImageLoad, 0);
	// Register ImageUnload to be called when an image is unloaded
	IMG_AddUnloadFunction(ImageUnload, 0);
	// Register Instruction to be called for every instruction
	INS_AddInstrumentFunction(Instruction, 0);
	// Register Syscall_entry to be called when a system call is made
	PIN_AddSyscallEntryFunction(Syscall_entry, 0);
	// Start Pin, never return
	PIN_StartProgram();

	return 0;

}


