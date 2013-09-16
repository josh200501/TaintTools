// Simple example of tainting memory from a system call
#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

// Byte range of tainted memory
struct range{
	// Start of tainted memory
	UINT64 start;
	// End of tainted memory
	UINT64 end;
};

// Entry point for main executable
UINT64 entryPoint;
bool passedEntryPoint = false;

// List to manage tainted bytes
std::list<struct range> bytesTainted;

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

// Register a function to call when an image is loaded
VOID image(IMG img, VOID *v){
	if (IMG_IsMainExecutable(img)) {
		entryPoint = IMG_Entry(img);
		cout << "Entry point for main executable: " << entryPoint << endl;
	}

}

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
			// Argument 0 is the system call
			// Argument 1 is the memory address to start reading from for read syscall
			taint.start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
			// Argument 2 is the memory address where to stop reading from read syscall
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

// Main function
int main(int argc, char *argv[]){
	if(PIN_Init(argc, argv)){
		return Usage();
	}

	PIN_SetSyntaxIntel();
	IMG_AddInstrumentFunction(image, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(Syscall_entry, 0);
	PIN_StartProgram();

	return 0;

}


