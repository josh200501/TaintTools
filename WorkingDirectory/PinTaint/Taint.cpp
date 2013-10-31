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


// Lower main bound, upper main bound, and entry point
UINT64 lowerBound, upperBound, entryPoint;

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
		std::cout << "\t\t\t " <<REG_StringShort(reg) << " is already tainted." << endl;
		return false;
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
		case REG_RBX:	taintedRegs.push_front(REG_RBX);
		case REG_EBX:	taintedRegs.push_front(REG_EBX);
		case REG_BX:	taintedRegs.push_front(REG_BX);
		case REG_BH:	taintedRegs.push_front(REG_BH);
		case REG_BL:	taintedRegs.push_front(REG_BL);
			break;

		// C-family of registers
		case REG_RCX:	taintedRegs.push_front(REG_RCX);
		case REG_ECX:	taintedRegs.push_front(REG_ECX);
		case REG_CX:	taintedRegs.push_front(REG_CX);
		case REG_CH:	taintedRegs.push_front(REG_CH);
		case REG_CL:	taintedRegs.push_front(REG_CL);
			break;

		// D-family of registers
		case REG_RDX:	taintedRegs.push_front(REG_RDX);
		case REG_EDX:	taintedRegs.push_front(REG_EDX);
		case REG_DX:	taintedRegs.push_front(REG_DX);
		case REG_DH:	taintedRegs.push_front(REG_DH);
		case REG_DL:	taintedRegs.push_front(REG_DL);
			break;

		// ESI-family of registers
		case REG_RSI:	taintedRegs.push_front(REG_RSI);
		case REG_ESI:	taintedRegs.push_front(REG_ESI);
		case REG_SI:	taintedRegs.push_front(REG_SI);
		case REG_SIL:	taintedRegs.push_front(REG_SIL);
			break;

		// Defualt action to take if we don't match a register
		default:
	      std::cout << "\t\t\t" << REG_StringShort(reg) << " taint has not been implemented." << std::endl;
		      return false;
	  }

	  // Print tainted register information.
	  std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
	  return true;

}



// Pin function to print the usage of this Pin Tool
INT32 Usage(){
	cerr << "Simple memory tainting from system call." << endl;
	return -1;
}

// Function to call when memory is read
VOID ReadMem(UINT64 insAddr, std::string insDis, UINT64 memOp){
	
	//std::cout << "[READ-INS-DEBUG]" << std::hex << insAddr << " : " << insDis << std::endl; 
	
	// Create iterator
	list<struct range>::iterator i;
	UINT64 addr = memOp;
	bool printed = false;
	for (i = bytesTainted.begin(); i != bytesTainted.end(); i++){
		if (addr >= i->start && addr < i->end){
			std::cout << std::hex << "[READ in 0x" << addr << "]\t" << insAddr << " : " << insDis << std::endl;
			printed = true;
		} 
	}

	if (!printed){
		if ((insAddr >= lowerBound) && (insAddr <= upperBound))
			std::cout << "[Taint Not Implemented]" << std::hex << insAddr << " : " << insDis << std::endl;
	}
}

// Function to call when memory is written to
VOID WriteMem(UINT64 insAddr, std::string insDis, UINT64 memOp){
	
	//std::cout << "[WRITE-INS-DEBUG]" << std::hex << insAddr << " : " << insDis << std::endl; 

	// Creat iterator
	list<struct range>::iterator i;
	UINT64 addr = memOp;
	bool printed = false;
	for (i = bytesTainted.begin(); i != bytesTainted.end(); i++){
		if (addr >= i->start && addr < i->end){
			std::cout << std::hex << "[WRITE in 0x" << addr << "]\t" << insAddr << " : " << insDis << std::endl;
			printed = true;
		} 	
	}

	if (!printed){
		if ((insAddr >= lowerBound) && (insAddr <= upperBound))
			std::cout << "[Taint Not Implemented]" << std::hex << insAddr << " : " << insDis << std::endl;
	}
}

// Check what type of instruction we have
/*
VOID Instruction(INS ins, VOID *v){
	

	if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
	//cout << "Calling read instruction evaluation." << endl;
	INS_InsertCall(
	    ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
	    IARG_ADDRINT, INS_Address(ins),
	    IARG_PTR, new string(INS_Disassemble(ins)),
	    IARG_MEMORYOP_EA, 0,
	    IARG_END);
	} else if (INS_MemoryOperandIsWritten(ins, 0)){
	//cout << "Calling write instruction evaluation." << endl;
	INS_InsertCall(
	    ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
	    IARG_ADDRINT, INS_Address(ins),
	    IARG_PTR, new string(INS_Disassemble(ins)),
	    IARG_MEMORYOP_EA, 0,
	    IARG_END);
	} else if ((INS_Address(ins) >= lowerBound) && (INS_Address(ins) <= upperBound)){
		if (INS_Address(ins) == entryPoint)
			std::cout << "[ Main Entry Point ] ";
		string instruction = string(INS_Disassemble(ins));
		std::cout <<  INS_Address(ins) << " : " << instruction << std::endl;
	}
}*/

// Check what type of instruction we have -- trace
VOID InstructionTrace(INS ins, VOID *v){
	
	//std::cout << "[INS-DEBUG]" << std::hex << INS_Address(ins) << " : " << string(INS_Disassemble(ins)) << std::endl; 

	if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
		//cout << "Calling read instruction evaluation." << endl;
		INS_InsertCall(
		    ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
		    IARG_ADDRINT, INS_Address(ins),
		    IARG_PTR, new string(INS_Disassemble(ins)),
		    IARG_MEMORYOP_EA, 0,
		    IARG_END);
	} else if (INS_MemoryOperandIsWritten(ins, 0)){
		//cout << "Calling write instruction evaluation." << endl;
		INS_InsertCall(
		    ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
		    IARG_ADDRINT, INS_Address(ins),
		    IARG_PTR, new string(INS_Disassemble(ins)),
		    IARG_MEMORYOP_EA, 0,
		    IARG_END);
	} else if ((INS_Address(ins) >= lowerBound) && (INS_Address(ins) <= upperBound)){
		if (INS_Address(ins) == entryPoint)
			std::cout << "[ Main Entry Point ] ";
		string instruction = string(INS_Disassemble(ins));
		std::cout <<  std::hex << INS_Address(ins) << " : " << instruction << std::endl;
	} 

	//std::cout << "[INS-DEBUG-POST]" << std::hex << INS_Address(ins) << " : " << string(INS_Disassemble(ins)) << std::endl;
	
}

// The first thing the Pin tool will do is read open and we want to skip this
static unsigned int voidFirstOpen;
static unsigned int numSysCalls = 0;
#define VOIDFIRSTOPEN(){if (voidFirstOpen++ == 0) return;}

// Create an entry point for all system calls
/*
NOTE: The ENUM types used to identify the system call numbers do not actually correspond to the
actual system call number. 
*/
VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	// Create structure to store our taint
	struct range taint;
	numSysCalls++;
	//cout << "SysCall # " << PIN_GetSyscallNumber(ctx, std) << endl;
	//cout << "SysCall Count - " << std::dec << numSysCalls << endl;
	
	// Pretty sure it should be unsigned
	unsigned int systemCallNum = PIN_GetSyscallNumber(ctx, std);
	switch (systemCallNum){

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

			// Print out syscall information for debugger
			std::cout << "\tSystem Call #" << systemCallNum << std::endl;
			// Need to figure out how to handle file descriptors, this is returning -1 which is an error but the file is read
			std::cout << "\tParam 1 (File Descriptor)-------------------> " << std::dec << static_cast<int>(PIN_GetSyscallArgument(ctx, std, 0)) << std::endl;
			std::cout << "\tParam 2 (Memory to Start Reading From)------> 0x" << std::hex << PIN_GetSyscallArgument(ctx, std, 1) << std::endl;
			std::cout << "\tParam 3 (Number of Bytes to Read)-----------> 0x" << std::hex << PIN_GetSyscallArgument(ctx, std, 2);
			std::cout << " (" << std::dec << PIN_GetSyscallArgument(ctx, std, 2) << " bytes)" << std::endl;
			// Needs to be on syscall exit (all should be implemented again on exit)
			//std::cout << "\tReturn Value (Number of Byte Actually Read)-> " << std::hex << PIN_GetSyscallReturn(ctx, std) << std::endl;

			std::cout << "[TAINT]\t\t\tBytes tainted from " << std::hex << "0x" << taint.start << " to 0x" << taint.end << endl;
			std::cout << "\t\t\t\tTainting done by read() system call." << endl;
			std::cout << "Total of " << dec << static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2))) << " bytes tainted." << endl;  
			
			// Consider including read range (from + total)

			break;
		
		// System call is write (__NR_write == 1)
		case __NR_write:
			cout << "[SYSCALL] write Syscall detected!" << endl;
			// Print out syscall information for debugger
			std::cout << "\tSystem Call #" << systemCallNum << std::endl;
			// Need to figure out how to handle file descriptors
			std::cout << "\tParam 1 (File Descriptor)----------------------> " << std::dec << static_cast<int>(PIN_GetSyscallArgument(ctx, std, 0)) << std::endl;
			std::cout << "\tParam 2 (Address of Buffer to Write From)------> 0x" << std::hex << PIN_GetSyscallArgument(ctx, std, 1) << std::endl;
			std::cout << "\tParam 3 (Number of Bytes to Write)-------------> 0x" << std::hex << PIN_GetSyscallArgument(ctx, std, 2);
			std::cout << " (" << std::dec << PIN_GetSyscallArgument(ctx, std, 2) << " bytes)" << std::endl;
			
			// Consider including write range (from + total)

			break;
		
		// System call is open (__NR_open == 2)
		case __NR_open:
			cout << "[SYSCALL] open Syscall detected!" << endl;
			// Print out syscall information for debugger
			// DOES NOT WORK CORRECTLY AT ALL
			std::cout << "\tSystem Call #" << systemCallNum << std::endl;
			std::cout << "\tParam 1 (Address of File Path)--------------> 0x" << std::hex << PIN_GetSyscallArgument(ctx, std, 1) << std::endl;
			std::cout << "\tParam 2 (File Access Bits)------------------> 0x" << std::hex << PIN_GetSyscallArgument(ctx, std, 2) << std::endl;
			std::cout << "\tParam 3 (Permission Mode)-------------------> " << std::hex << PIN_GetSyscallArgument(ctx, std, 3) << std::endl;
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
	std::cout << "Loading " << IMG_Name(img).c_str() << " Image id = " << IMG_Id(img) << std::endl;

	// Check to see if our image is the main image (will be the name of the executable being traced)
	if (IMG_IsMainExecutable(img)) {
		entryPoint = IMG_Entry(img);
		std::cout << std::hex << "-->	Entry point for main executable: 0x" << entryPoint << std::endl;
		lowerBound = IMG_LowAddress(img);
		upperBound = IMG_HighAddress(img);
	}	

	// Print out the name of every symbol in a particular image
	// This is a lot of information, best to leave it commented out
	/*
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
		std::cout << "Symbol: " << SYM_Name(sym) << std::endl;
	}*/

	std::cout << "-->	Image loaded at address offset: 0x" << std::hex << IMG_LoadOffset(img) << std::endl;
	std::cout << "--> 	Image start address: 0x" << std::hex << IMG_StartAddress(img) << std::endl;
	std::cout << "-->	Image low address: 0x" << std::hex << IMG_LowAddress(img) << std::endl;
	std::cout << "-->	Image high address: 0x" << std::hex <<IMG_HighAddress(img) << std::endl;
	

	
}

// Function to manage traces
/*
VOID Trace(TRACE trace, VOID *v){
	UINT64 addrOfBbl;
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        addrOfBbl = BBL_Address(bbl);
        if ((addrOfBbl >= lowerBound) && (addrOfBbl <= upperBound)){
	        std::cout << "======================================\n\n\n" << std::endl;
	        std::cout << "========  Basic Block @ Address: 0x" << addrOfBbl << "  ========" << std::endl;
	        std::cout << std::dec << "Number of instructions: " << BBL_NumIns(bbl) << std::endl;
	        
	        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
	          	InstructionTrace(ins);
	          	//std::cout << localInst << std::endl;  
	          	//std::cout << "[ DEBUG ]" << std::hex << INS_Address(ins) << " : " << string(INS_Disassemble(ins)) << endl;
	        }  
	    }   
    }	
}*/

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
	INS_AddInstrumentFunction(InstructionTrace, 0);
	
	// Register Syscall_entry to be called when a system call is made
	PIN_AddSyscallEntryFunction(Syscall_entry, 0);
	
	// Add an instrumentation for traces
	/* Prints instructions out of order? Not working correctly
	TRACE_AddInstrumentFunction(Trace, 0);*/
	
	// Start Pin, never return
	PIN_StartProgram();

	return 0;

}


