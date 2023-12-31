#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <iomanip>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>

using namespace std;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE, "pintool", "prof", "0", "profiling mode");

KNOB<BOOL> KnobOpt(KNOB_MODE_WRITEONCE, "pintool", "opt", "0", "translation mode");

KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// OURS - for processing profiling data
// -----------------------------------------------------
vector<pair<ADDRINT, ADDRINT>> hot_calls;
vector<pair<ADDRINT, ADDRINT>> hot_calls_to_inline;
const int MAX_HOT_CALLS = 10;
const int MIN_CALLS = 100;

struct bbl_data {
    ADDRINT bbl_tail;
    ADDRINT next_taken;
    ADDRINT next_not_taken;
    int hotter_next; // 0 when branch is more likely to be taken, otherwise 1
};

map<ADDRINT, bbl_data> bbl_map; // key is bbl_head

string PROBLEM_CASE = "sendMTFValues";
// -----------------------------------------------------

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct {
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int targ_map_entry;
} instr_map_t;


instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;


// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct {
	ADDRINT rtn_addr;
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;



/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }

  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;

}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {
				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << "\n" << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		cerr << "    ";
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);
	}
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].targ_map_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }

	  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */

/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, bool is_added_jmp)
{

    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

    if (xed_decoded_inst_get_length (xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);

    xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
      orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    // add a new entry in the instr_map:

    if (is_added_jmp) {
        instr_map[num_of_instr_map_entries].orig_ins_addr = 0;
    }
    else {
        instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    }
    instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

    num_of_instr_map_entries++;

    // update expected size of tc:
    tc_cursor += new_size;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }


    // debug print new encoded instr:
    if (KnobVerbose) {
        cerr << "[" << dec << num_of_instr_map_entries - 1 << "]    new instr:";
        dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
    }

    return new_size;
}


/* ============================================================= */
/* Our Auxiliaries                                               */
/* ============================================================= */

bool decode_ins(ADDRINT ins_addr, xed_decoded_inst_t* xedd) {
	xed_error_enum_t xed_code;
	xed_decoded_inst_zero_set_mode(xedd,&dstate);

	xed_code = xed_decode(xedd, reinterpret_cast<UINT8*>(ins_addr), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << dec << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
		return false;
	}

	return true;
}

bool create_jmp(ADDRINT tail, ADDRINT fallthrough, xed_decoded_inst_t* new_xedd) {
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;
    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];		
    xed_int32_t disp = fallthrough - tail - 5; // 5 should be the jmp instruction's size
    xed_encoder_instruction_t enc_instr;

    xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_JMP, 64,
            xed_relbr(disp, 32));
                            
    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return false;
    }

    xed_error_enum_t xed_error = xed_encode (&enc_req, enc_buf, max_size, &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;				
        return false;
    }

    xed_error_enum_t xed_code = xed_decode(new_xedd, enc_buf, XED_MAX_INSTRUCTION_BYTES);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed" << endl;
        return false;
    }

    char buf[2048];
    xed_format_context(XED_SYNTAX_INTEL, new_xedd, buf, 2048, tail, 0, 0);
    if (KnobVerbose)
		cerr << "newly added uncond jump: " << std::hex << tail << " " << buf << endl;
    return true;
}

bool revert_branch(ADDRINT tail, ADDRINT fallthrough, xed_decoded_inst_t* xedd, xed_decoded_inst_t* new_xedd) {
    xed_category_enum_t category_enum = xed_decoded_inst_get_category(xedd);

    if (category_enum != XED_CATEGORY_COND_BR) {
        cerr << "not a branch!" << endl;
        return false;
    }

    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(xedd);

    if (iclass_enum == XED_ICLASS_JRCXZ) {
        cerr << "invalid branch type" << endl;
        return false;    // do not revert JRCXZ
    }

    xed_iclass_enum_t retverted_iclass;

    switch (iclass_enum) {

        case XED_ICLASS_JB:
            retverted_iclass = XED_ICLASS_JNB;		
            break;

        case XED_ICLASS_JBE:
            retverted_iclass = XED_ICLASS_JNBE;
            break;

        case XED_ICLASS_JL:
            retverted_iclass = XED_ICLASS_JNL;
            break;
    
        case XED_ICLASS_JLE:
            retverted_iclass = XED_ICLASS_JNLE;
            break;

        case XED_ICLASS_JNB: 
            retverted_iclass = XED_ICLASS_JB;
            break;

        case XED_ICLASS_JNBE: 
            retverted_iclass = XED_ICLASS_JBE;
            break;

        case XED_ICLASS_JNL:
        retverted_iclass = XED_ICLASS_JL;
            break;

        case XED_ICLASS_JNLE:
            retverted_iclass = XED_ICLASS_JLE;
            break;

        case XED_ICLASS_JNO:
            retverted_iclass = XED_ICLASS_JO;
            break;

        case XED_ICLASS_JNP: 
            retverted_iclass = XED_ICLASS_JP;
            break;

        case XED_ICLASS_JNS: 
            retverted_iclass = XED_ICLASS_JS;
            break;

        case XED_ICLASS_JNZ:
            retverted_iclass = XED_ICLASS_JZ;
            break;

        case XED_ICLASS_JO:
            retverted_iclass = XED_ICLASS_JNO;
            break;

        case XED_ICLASS_JP: 
            retverted_iclass = XED_ICLASS_JNP;
            break;

        case XED_ICLASS_JS: 
            retverted_iclass = XED_ICLASS_JNS;
            break;

        case XED_ICLASS_JZ:
            retverted_iclass = XED_ICLASS_JNZ;
            break;

        default:
            cerr << "branch type not recognized" << endl;
            return false;
    }

    // compute new disp
    xed_uint_t disp_width = xed_decoded_inst_get_branch_displacement_width(xedd);
    xed_uint_t instr_width = xed_decoded_inst_get_length(xedd);
    xed_int32_t disp = fallthrough - tail - instr_width; // the extra 1 is for the instruction itself

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(xedd);

    // set the reverted opcode;
    xed_encoder_request_set_iclass(xedd, retverted_iclass);

    // set new disp
    xed_encoder_request_set_branch_displacement(xedd, disp, disp_width);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode(xedd, enc_buf, max_size, &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return false;
    }

    xed_error_enum_t xed_code = xed_decode(new_xedd, enc_buf, XED_MAX_INSTRUCTION_BYTES);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed" << endl;
        return false;
    }

    char buf[2048];
    xed_format_context(XED_SYNTAX_INTEL, new_xedd, buf, 2048, tail, 0, 0);
    if (KnobVerbose)
        cerr << "reverted branch: " << std::hex << tail << " " << buf << endl;
    return true;
}


bool add_decoded_ins_to_map(ADDRINT ins_addr, xed_decoded_inst_t* xedd, bool is_added_jmp) {
	int rc = add_new_instr_entry(xedd, ins_addr, xed_decoded_inst_get_length(xedd), is_added_jmp);
	if (rc < 0) {
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
		return false;
	}

	return true;
}


bool is_hot_call_to_inline(ADDRINT call_addr, ADDRINT called_addr) {
	return count(hot_calls_to_inline.begin(), hot_calls_to_inline.end(), make_pair(call_addr, called_addr));
}


bool is_rtn_inline_valid(ADDRINT call_addr, ADDRINT called_addr) {
	// Find the called rtn
	RTN rtn = RTN_FindByAddress(called_addr);
	RTN_Open(rtn);
	// Check called addr is head of its function
	if (INS_Address(RTN_InsHead(rtn)) != called_addr) {
		// cerr << "err: not head of function" << endl;
		return false;
	}

	int count_rets = 0;
	bool last_seen_is_ret = false;
	bool is_valid = true;

	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
		last_seen_is_ret = false;

		// Check no access to the stack of the caller, that is - access RBP+<positive_offset>
		if (INS_MemoryBaseReg(ins) == REG_RBP && INS_MemoryDisplacement(ins) > 0) {
			// cerr << "err: rbp+pos" << endl;
			is_valid = false;
			break;
		}

		// Check no access to the stack of the caller, that is - access RSP+<negative_offset>
		if (INS_MemoryBaseReg(ins) == REG_RSP && INS_MemoryDisplacement(ins) < 0) {
			// cerr << "err: rsp-pos" << endl;
			is_valid = false;
			break;
		}

		// Check no direct jumps outside the function's scope
		if (!INS_IsRet(ins) && INS_IsDirectControlFlow(ins)) {
			ADDRINT jmp_target = RTN_Address(RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins)));
			if (jmp_target != RTN_Address(rtn)) {
				// cerr << "err: direct jmp ouside scope" << endl;
				is_valid = false;
				break;
			}
		}

		// Check function doesn't have indirect calls/jmps
		if (!INS_IsRet(ins) && INS_IsIndirectControlFlow(ins)) {
			// cerr << "err: indirect" << endl;
			is_valid = false;
			break;
		}

		// Check function is not recursive (no call to itself)
		if (INS_IsDirectCall(ins)) {
			ADDRINT target_addr = INS_DirectControlFlowTargetAddress(ins);
			if (target_addr == RTN_Address(rtn)) { // the function calls itself
				// cerr << "err: recursive" << endl;
				is_valid = false;
				break;
			}
		}

		if (INS_IsRet(ins)) {
			count_rets += 1;
			last_seen_is_ret = true; // MAYBE REMOVE
		}
	}

	if (count_rets != 1 || !last_seen_is_ret) {
		// cerr << "err: ret problem" << endl;
		is_valid = false;
	}

	// cerr << "VALID" << endl;
	RTN_Close(rtn);
	return is_valid;
}

/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
    for (int i=0; i < num_of_instr_map_entries; i++) {

        if (instr_map[i].orig_targ_addr == 0)
            continue;

        if (instr_map[i].hasNewTargAddr)
            continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
               continue;

            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true;
                instr_map[i].targ_map_entry = j;
                break;
            }
        }
    }

    return 0;
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry)
{
    //debug print:
    //dump_instr_map_entry(instr_map_entry);

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    //cerr << "Memory Operands" << endl;
    bool isRipBase = false;
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    xed_int64_t disp = 0;
    for(unsigned int i=0; i < memops ; i++)   {

        base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
        disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }

    }

    if (!isRipBase)
        return 0;


    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

    if(!instr_map[instr_map_entry].orig_ins_addr) {
        cerr << "uh oh" << endl;
    }

    // modify rip displacement. use direct addressing mode:
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
    xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

    //Set the memory displacement using a bit length
    xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {

        cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: "
              << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // check for cases of direct jumps/calls back to the orginal target address:
    if (instr_map[instr_map_entry].targ_map_entry >= 0) {
        cerr << "ERROR: Invalid jump or call instruction" << endl;
        return -1;
    }

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;


    xed_encoder_instruction_t  enc_instr;

    ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
                       instr_map[instr_map_entry].new_ins_addr -
                       xed_decoded_inst_get_length (&xedd);

    if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

    if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_JMP, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }


    xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // handle the case where the original instr size is different from new encoded instr:
    if (olen != xed_decoded_inst_get_length (&xedd)) {

        new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
                   instr_map[instr_map_entry].new_ins_addr - olen;

        if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

        if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_JMP, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
        xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
        if (!convert_ok) {
            cerr << "conversion to encode request failed" << endl;
            return -1;
        }

        xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
        if (xed_error != XED_ERROR_NONE) {
            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
            dump_instr_map_entry(instr_map_entry);
            return -1;
        }
    }


    // debug prints:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    instr_map[instr_map_entry].hasNewTargAddr = true;
    return olen;
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry)
{

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_int32_t  new_disp = 0;
    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;


    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: unrecognized branch displacement" << endl;
        return -1;
    }

    // fix branches/calls to original targ addresses:
    if (instr_map[instr_map_entry].targ_map_entry < 0) {
       int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
       return rc;
    }

    ADDRINT new_targ_addr;
    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

    xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

    // the max displacement size of loop instructions is 1 byte:
    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
    if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
      new_disp_byts = 1;
    }

    // the max displacement size of jecxz instructions is ???:
    xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
    if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
      new_disp_byts = 1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;

    xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        char buf[2048];
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
          return -1;
    }

    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    //debug print of new instruction in tc:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;

    do {

        size_diff = 0;

        if (KnobVerbose) {
            cerr << "starting a pass of fixing instructions displacements: " << endl;
        }

        for (int i=0; i < num_of_instr_map_entries; i++) {

            instr_map[i].new_ins_addr += size_diff;

            int new_size = 0;

            // fix rip displacement:
            new_size = fix_rip_displacement(i);
            if (new_size < 0)
                return -1;

            if (new_size > 0) { // this was a rip-based instruction which was fixed.

                if (instr_map[i].size != (unsigned int)new_size) {
                   size_diff += (new_size - instr_map[i].size);
                   instr_map[i].size = (unsigned int)new_size;
                }

                continue;
            }

            // check if it is a direct branch or a direct call instr:
            if (instr_map[i].orig_targ_addr == 0) {
                continue;  // not a direct branch or a direct call instr.
            }


            // fix instr displacement:
            new_size = fix_direct_br_call_displacement(i);
            if (new_size < 0)
                return -1;

            if (instr_map[i].size != (unsigned int)new_size) {
               size_diff += (new_size - instr_map[i].size);
               instr_map[i].size = (unsigned int)new_size;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

   return 0;
 }

// OURS
int load_profiling_data(vector<RTN>& callers_to_emit) {
    ifstream call_prof_file;
    ifstream branch_prof_file;
    call_prof_file.open("call-count.csv");
    if (!call_prof_file) {
        cerr << "failed to open profiling data file" << endl;
        return 0;
    }
    branch_prof_file.open("branch-count.csv");
    if (!branch_prof_file) {
        cerr << "failed to open profiling data file" << endl;
        return 0;
    }

    string call_addr_str;
    string call_num_str;
    string call_targ_str;
    ADDRINT hot_call_addr;
    ADDRINT hot_target_addr;

    // go over loop profiling until we've found all hot call sites
    while(true) {
        getline(call_prof_file, call_addr_str, ','); // read hot call address
        hot_call_addr = AddrintFromString(call_addr_str);
        getline(call_prof_file, call_num_str, ','); // read number of times call has been invoked
        if (atoi(call_num_str.c_str()) < MIN_CALLS) {
            break;
        }
        getline(call_prof_file, call_targ_str); // read target of hot call
        hot_target_addr = AddrintFromString(call_targ_str);

        if (is_rtn_inline_valid(hot_call_addr, hot_target_addr)) {
            if (RTN_Name(RTN_FindByAddress(hot_call_addr)) != PROBLEM_CASE) { // problematic case we couldn't figure out
                hot_calls_to_inline.push_back(make_pair(hot_call_addr, hot_target_addr)); // mark call as hot
                callers_to_emit.push_back(RTN_FindByAddress(hot_call_addr));
                if (hot_calls_to_inline.size() == MAX_HOT_CALLS) { // we want to limit the number of inlines
                    break;
                }
            }
        }

        if (!call_prof_file) { // reached end of file
            break;
        }
    }

    string line;
    ADDRINT bbl_addr;
    // go over branch profiling until we loaded all info
    while(true) {
        bbl_data curr;
        getline(branch_prof_file, line, ','); // read bbl address
        bbl_addr = AddrintFromString(line);
        getline(branch_prof_file, line, ','); // read bbl tail address
        curr.bbl_tail = AddrintFromString(line);
        getline(branch_prof_file, line, ','); // read taken address
        curr.next_taken = AddrintFromString(line);
        getline(branch_prof_file, line, ','); // read not taken address
        curr.next_not_taken = AddrintFromString(line);
        getline(branch_prof_file, line); // hotter next
        curr.hotter_next = atoi(line.c_str());
        bbl_map[bbl_addr] = curr;

        if (!branch_prof_file) { // reached end of file
            break;
        }
    }

    return 1;
}

/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
// new version
int find_candidate_rtns_for_translation(IMG img)
{
    vector<RTN> callers_to_emit;
    if(!load_profiling_data(callers_to_emit)) {
        return 0;
    }

    map<ADDRINT, xed_decoded_inst_t> local_instrs_map;
    local_instrs_map.clear();

    // go over routines and check if they are candidates for translation and mark them for translation:

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            if (rtn == RTN_Invalid()) {
              cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
                continue;
            }

            translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);
            translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);

            // Open the RTN.
            RTN_Open( rtn );

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                ADDRINT addr = INS_Address(ins);
                xed_decoded_inst_t xedd;
				if (!decode_ins(addr, &xedd))
					break;
                // Save xed and addr into a map to be used later.
                local_instrs_map[addr] = xedd;
            } // end for INS...

            // Close the RTN.
            RTN_Close( rtn );

            translated_rtn_num++;

         } // end for RTN..
    } // end for SEC...

    vector<pair<ADDRINT, xed_decoded_inst_t>> local_instrs_vec;
    for (map<ADDRINT, xed_decoded_inst_t>::iterator iter = local_instrs_map.begin(); iter != local_instrs_map.end(); iter++) {
        local_instrs_vec.push_back(make_pair(iter->first, iter->second));
    }

    // Perform code reorder
    vector<pair<ADDRINT, ADDRINT>> swaps_performed;
    vector<pair<ADDRINT, xed_decoded_inst_t>> temp_taken;
    vector<pair<ADDRINT, xed_decoded_inst_t>> temp_non_taken;
    unsigned int j;
    int taken_start_index;
    int taken_end_index;
    int non_taken_start_index;
    int non_taken_end_index;
    int flag;

    for (auto const & block : bbl_map) {
    // When needing to reorder, splice the vector and physically swap the location of the taken block instructions with
    // the not-taken block instructions.
        taken_start_index = -1;
        taken_end_index = -1;
        non_taken_start_index = -1;
        non_taken_end_index = -1;

        if (RTN_FindByAddress(block.first) == RTN_Invalid()) {
            continue;
        }

        if (
            (!block.second.hotter_next && // need to reorder
            RTN_FindByAddress(block.first) == RTN_FindByAddress(block.second.next_taken)) && 
            (RTN_FindByAddress(block.first) == RTN_FindByAddress(block.second.next_not_taken)) && // main block and the two possible paths in the same 
            find(swaps_performed.begin(), swaps_performed.end(), 
                make_pair(block.second.next_not_taken, block.second.next_taken)) == swaps_performed.end() &&
            find(swaps_performed.begin(), swaps_performed.end(), 
                make_pair(block.second.next_taken, block.second.next_not_taken)) == swaps_performed.end() // this reorder has not already been performed
            ) { 
            bbl_data taken_block = bbl_map[block.second.next_taken];
            bbl_data not_taken_block = bbl_map[block.second.next_not_taken];
            if (!(taken_block.bbl_tail && not_taken_block.bbl_tail)) { // some sort of profiling error - skip
                continue;
            }
            xed_category_enum_t category_enum_taken = xed_decoded_inst_get_category(&local_instrs_map[taken_block.bbl_tail]);
            xed_category_enum_t category_enum_not_taken = xed_decoded_inst_get_category(&local_instrs_map[not_taken_block.bbl_tail]);
		    if (category_enum_taken == XED_CATEGORY_CALL || category_enum_not_taken == XED_CATEGORY_CALL 
                || category_enum_taken == XED_CATEGORY_RET || category_enum_not_taken == XED_CATEGORY_RET) { // special cases we can't handle (time constraints)
                continue;
            }
            // save instructions of non-taken block in temp vector
            flag = 0;

            for (j = 0; j < local_instrs_vec.size(); j++) {
                if (!flag) {
                    if (local_instrs_vec[j].first != block.second.next_not_taken) {
                        continue;
                    }
                    else {
                        temp_non_taken.push_back(local_instrs_vec[j]);
                        non_taken_start_index = j;
                        if (local_instrs_vec[j].first == not_taken_block.bbl_tail) { // check for single-instruction blocks
                            break;
                        }
                        flag = 1;
                    }
                }
                else {
                    if (local_instrs_vec[j].first == block.second.next_taken) {
                        break;
                    }
                    temp_non_taken.push_back(local_instrs_vec[j]);
                    if(local_instrs_vec[j].first == not_taken_block.bbl_tail) {
                        flag = 0;
                        break;
                    }
                }
            }
            if (non_taken_start_index < 0 || flag) { // could not locate both ends of the block
                temp_non_taken.clear();
                continue;
            }
            non_taken_end_index = j+1;
            // save instructions of taken block in temp vector
            flag = 0;
            for (j = 0; j < local_instrs_vec.size(); j++) {
                if (!flag) {
                    if (local_instrs_vec[j].first != block.second.next_taken) {
                        continue;
                    }
                    else {
                        temp_taken.push_back(local_instrs_vec[j]);
                        taken_start_index = j;
                        if (local_instrs_vec[j].first == taken_block.bbl_tail) { // check for single-instruction blocks
                            break;
                        }
                        flag = 1;
                    }
                }
                else {
                    temp_taken.push_back(local_instrs_vec[j]);
                    if(local_instrs_vec[j].first == taken_block.bbl_tail) {
                        flag = 0;
                        break;
                    }
                }
            }
            if (taken_start_index < 0 || flag) { // could not locate both ends of the block
                temp_non_taken.clear();
                temp_taken.clear();
                continue;
            }
            taken_end_index = j+1;
    
            // performs the reorder:
            // * revert conditional branch at the end of main block
            // * switch the taken and non-taken paths from main block
            // * add unconditional jmp to the end of each of the three blocks (main, taken, non-taken)
            for (j = local_instrs_vec.size()-1; j >= 0 ; j--) { // change vector from end to beginning so we won't shift the indices
                if (j == 0) {
                    break;
                }
                if (local_instrs_vec[j].first == block.second.bbl_tail) { // end of main block
                    // revert conditional branch
                    xed_decoded_inst_t br_instr;
                    xed_decoded_inst_zero_set_mode(&br_instr, &dstate);
                    if (revert_branch(local_instrs_vec[j].first, block.second.next_not_taken, &local_instrs_vec[j].second, &br_instr)) {
                        local_instrs_vec[j].second = br_instr;
                    }
                    // add uncoditional jmp
                    xed_decoded_inst_t jmp_instr;
                    xed_decoded_inst_zero_set_mode(&jmp_instr, &dstate);
                    if (create_jmp(local_instrs_vec[j].first, block.second.next_taken, &jmp_instr)) {
                        local_instrs_vec.insert(local_instrs_vec.begin()+j+1, make_pair(0, jmp_instr));
                    }
                    continue;
                }
                if (j == (unsigned)taken_start_index) { // taken block
                    // add jmp after non taken block
                    if (not_taken_block.next_not_taken) { // block has fallthrough
                        xed_decoded_inst_t jmp_instr;
                        xed_decoded_inst_zero_set_mode(&jmp_instr, &dstate);
                        if (create_jmp(not_taken_block.bbl_tail, not_taken_block.next_not_taken, &jmp_instr)) {
                            temp_non_taken.push_back(make_pair(0, jmp_instr));
                        }
                    }
                    // remove instructions of taken block from original vector
                    local_instrs_vec.erase(local_instrs_vec.begin()+taken_start_index, local_instrs_vec.begin()+taken_end_index);
                    // insert instructions of non-taken block at index of taken block
                    local_instrs_vec.insert(local_instrs_vec.begin()+taken_start_index, temp_non_taken.begin(), temp_non_taken.end());
                    continue;
                }
                if (j == (unsigned)non_taken_start_index) { // non taken block
                    // add jmp after taken block
                    if (taken_block.next_not_taken) { // block has fallthrough
                        xed_decoded_inst_t jmp_instr;
                        xed_decoded_inst_zero_set_mode(&jmp_instr, &dstate);
                        if (create_jmp(taken_block.bbl_tail, taken_block.next_not_taken, &jmp_instr)) {
                            temp_taken.push_back(make_pair(0, jmp_instr));
                        }
                    }
                    // remove instructions of non-taken block from original vector
                    local_instrs_vec.erase(local_instrs_vec.begin()+non_taken_start_index, local_instrs_vec.begin()+non_taken_end_index);
                    // insert instructions of taken block at index of non-taken block
                    local_instrs_vec.insert(local_instrs_vec.begin()+non_taken_start_index, temp_taken.begin(), temp_taken.end());
                }
                
            }
            
            swaps_performed.push_back(make_pair(block.second.next_not_taken, block.second.next_taken));
            temp_non_taken.clear();
            temp_taken.clear();
            continue;
        }
    }

    cout << "after code reordering" << endl;

    // Go over local_instrs_vec, perform inlining and add instruction to global instrs_map:
    int rtn_num = 0;
    bool is_added_jmp;
    for (vector<pair<ADDRINT, xed_decoded_inst_t>>::iterator iter = local_instrs_vec.begin(); iter != local_instrs_vec.end(); iter++) {
		ADDRINT addr = iter->first;
		xed_decoded_inst_t xedd = iter->second;
        is_added_jmp = false;

        // Check is instr is a jmp we added
        if (!addr) {
            addr = (iter-1)->first;
            is_added_jmp = true;
        }

		// Check if we are at a routine header:
		if (translated_rtn[rtn_num].rtn_addr == addr) {
			rtn_num++;
		}

		if (find(callers_to_emit.begin(), callers_to_emit.end(), RTN_FindByAddress(addr)) != callers_to_emit.end()) { // do not emit this caller
			if (translated_rtn[rtn_num-1].rtn_addr == addr) {
                translated_rtn[rtn_num-1].instr_map_entry = num_of_instr_map_entries;
				translated_rtn[rtn_num-1].isSafeForReplacedProbe = true;
			}
		}
		else {
            if (translated_rtn[rtn_num-1].rtn_addr == addr)
                translated_rtn[rtn_num-1].instr_map_entry = -1;
			continue;
		}

		// Check if this is a direct call instr:
		xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
		if (category_enum == XED_CATEGORY_CALL) {
			xed_int64_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
			ADDRINT target_addr = addr + xed_decoded_inst_get_length (&xedd) + disp;
			RTN rtn = RTN_FindByAddress(target_addr);
			RTN_Open(rtn);

			// Check Function call is to the beginning of a valid function
			if (is_hot_call_to_inline(addr, target_addr)) {
				// Do inline
				cout << "start inlining rtn " << RTN_Name(rtn) << " at 0x" << hex << instr_map[num_of_instr_map_entries-1].new_ins_addr << dec << endl;

				for (INS ins_callee = RTN_InsHead(rtn); INS_Valid(ins_callee); ins_callee = INS_Next(ins_callee)) {
					if (KnobVerbose)
						cerr << "Original inst: " << INS_Disassemble(ins_callee) << endl;

					if (INS_IsRet(ins_callee)) {
						break;
					}
					else {
						xed_decoded_inst_t xedd_callee = local_instrs_map[INS_Address(ins_callee)];
						if (!add_decoded_ins_to_map(INS_Address(ins_callee), &xedd_callee, false)) { // failed to encode / add to instr_map
							break;
						}

					}
				}

				cout << "end inlining rtn " << RTN_Name(rtn) << endl;
			}

			else {
				// Add instr into local_instrs_vec vector:
                if (!add_decoded_ins_to_map(addr, &xedd, false))
					break;
			}

			RTN_Close(rtn);
		}

		else {
			// Add instr into local_instrs_vec vector:
			if (!add_decoded_ins_to_map(addr, &xedd, is_added_jmp))
                break;
		}
    }

    cout << "after function inlining and translation" << endl;

    return 0;
}


/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
	int cursor = 0;
	if (KnobVerbose) {
		cerr << "\nStart printing instrs to copy" << endl;
	}

	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }

	  if (KnobVerbose) {
		cerr << "[" << dec << i << "] ";
		dump_instr_from_mem((ADDRINT *)instr_map[i].encoded_ins, instr_map[i].new_ins_addr);
	  }
	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	if (KnobVerbose) {
		cerr << "\nDone printing instrs to copy\n" << endl;
	}


	return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines()
{
	// Commit the translated functions:
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc

		if (translated_rtn[i].instr_map_entry >= 0) {

			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:
				if (KnobVerbose) {
					if (rtn == RTN_Invalid()) {
						cerr << "committing rtN: Unknown";
					} else {
						cerr << "committing rtN: " << RTN_Name(rtn);
					}
					cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;
				}

				if (RTN_IsSafeForProbedReplacement(rtn)) {

					AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);

					if (KnobVerbose) {
						if (origFptr == NULL) {
							cerr << "RTN_ReplaceProbed failed.";
						} else {
							cerr << "RTN_ReplaceProbed succeeded. ";
						}
						cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
								<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;
						dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
					}

				}
			}
		}
	}
}


/****************************/
/* allocate_and_init_memory */
/****************************/
int allocate_and_init_memory(IMG img)
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.

	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}

	tc = (char *)addr;
	return 0;
}



/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
	// debug print of all images' instructions
	//dump_all_image_instrs(img);


    // Step 0: Check the image and the CPU:
	if (!IMG_IsMainExecutable(img))
		return;

	int rc = 0;

	// step 1: Check size of executable sections and allocate required memory:
	rc = allocate_and_init_memory(img);
	if (rc < 0)
		return;

	cout << "after memory allocation" << endl;


	// Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
	rc = find_candidate_rtns_for_translation(img);
	if (rc < 0)
		return;

	cout << "after identifying candidate routines" << endl;

	// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
	rc = chain_all_direct_br_and_call_target_entries();
	if (rc < 0 )
		return;

	cout << "after calculate direct br targets" << endl;

	// Step 4: fix rip-based, direct branch and direct call displacements:
	rc = fix_instructions_displacements();
	if (rc < 0 )
		return;

	cout << "after fix instructions displacements" << endl;


	// Step 5: write translated routines to new tc:
	rc = copy_instrs_to_tc();
	if (rc < 0 )
		return;

	cout << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
	//    cerr << "Translation Cache dump:" << endl;
    //    dump_tc();  // dump the entire tc

	   cerr << endl << "instructions map dump:" << endl;
	   dump_entire_instr_map();     // dump all translated instructions in map_instr
   }


	// Step 6: Commit the translated routines:
	//Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
	  commit_translated_routines();
	  cout << "after commit translated routines" << endl;
    }
}

/* ===================================================================== */
/* OUR ADDITIONS														 */
/* ===================================================================== */

map<ADDRINT, UINT64> call_count_map;
map<ADDRINT, ADDRINT> call_target_map;

map<ADDRINT, UINT64> taken_map;
map<ADDRINT, UINT64> not_taken_map;

// // count iterations for loop
// VOID docount_seen(ADDRINT target_addr, INT32 taken) {
//     if (taken) {
// 	seen_map[target_addr]++;
// 	curr_map[target_addr]++;
//     }
// }

VOID docount_call(ADDRINT call_addr) {
    call_count_map[call_addr]++;
}

VOID docount_branch(INT32 isTaken, ADDRINT branchAddr) {
    if (isTaken) {
        taken_map[branchAddr]++;
    }
    else {
        not_taken_map[branchAddr]++;
    }
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID* v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        INS head = BBL_InsHead(bbl);
        INS tail = BBL_InsTail(bbl);
        
        ADDRINT head_addr = INS_Address(head);
        ADDRINT tail_addr = INS_Address(tail);
        bbl_data curr_bbl = {tail_addr, 0, 0, 0};
        bbl_map[head_addr] = curr_bbl;

        if (INS_HasFallThrough(tail)) {
            bbl_map[head_addr].next_not_taken = INS_NextAddress(tail);
        }

        if (INS_IsDirectBranch(tail)) {
            bbl_map[head_addr].next_taken = INS_DirectControlFlowTargetAddress(tail);
            INS_InsertCall( // count number of times the branch was taken or not taken
                tail, IPOINT_BEFORE,
                (AFUNPTR)docount_branch,
                IARG_BRANCH_TAKEN,
                IARG_ADDRINT, tail_addr,
                IARG_END
            );
        }
    }
}

VOID Instruction(INS ins, VOID* v) {
     RTN rtn = INS_Rtn(ins);
     ADDRINT rtn_addr = RTN_Address(rtn);

     // skip routines outside of MainExecutable image
     IMG img = IMG_FindByAddress(rtn_addr);
     if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
	 return;
     }

//     INS_InsertCall( // count instructions in routine
//	 ins, IPOINT_BEFORE,
//         (AFUNPTR)docount_call,
//         IARG_FAST_ANALYSIS_CALL,
//         IARG_ADDRINT, rtn_addr,
//         IARG_END
//     );

    if (INS_IsDirectCall(ins)) {
        ADDRINT target_addr = INS_DirectControlFlowTargetAddress(ins); // address of the routine
        ADDRINT call_addr = INS_Address(ins);
        call_target_map[call_addr] = target_addr; // save target of call
        INS_InsertCall( // count number of times the call is made
            ins, IPOINT_BEFORE,
                (AFUNPTR)docount_call,
                IARG_FAST_ANALYSIS_CALL,
                IARG_ADDRINT, call_addr,
                IARG_END
        );
    }

//     if (INS_IsDirectBranch(ins)) { // if ins is a jump command (conditional/unconditional)
//         ADDRINT target_addr = INS_DirectControlFlowTargetAddress(ins); // address of the jump target (head of loop?)
//	       ADDRINT curr_addr = INS_Address(ins);
//         if (target_addr < curr_addr) { // jumps backwards - found a loop
//	     // add to number of iterations for current loop (identified by the target addr)
//	            INS_InsertCall(
//	 	         ins, IPOINT_BEFORE,
//             	(AFUNPTR)docount_seen,
//             	IARG_FAST_ANALYSIS_CALL,
//             	IARG_ADDRINT, target_addr,
//             	IARG_BRANCH_TAKEN,
//             	IARG_END
//	     );
//
//	     // get name of rtn that contains the loop
//             if (RTN_Valid(rtn) && rtn_name_map[rtn_addr] == "") { // if name of rtn was not found yet, update it in name map
//                 rtn_name_map[rtn_addr] = RTN_Name(rtn); // update name of rtn that contains the loop
//             }
//
//	     // get address of rtn that contains the loop
//             rtn_addr_map[target_addr] = rtn_addr;
//
//
//             if (INS_IsValidForIpointAfter(ins)) { // if current ins is conditional jmp, then after it the loop is over - inc invoked
//                 INS_InsertCall(ins, IPOINT_AFTER,
//                     (AFUNPTR)docount_invoked,
//                     IARG_FAST_ANALYSIS_CALL,
//                     IARG_ADDRINT, target_addr,
//                     IARG_END);
//             }
//
//             else {
//	 	RTN_Open(rtn);
//                 for(INS ins2 = RTN_InsHead(rtn); INS_Valid(ins2); ins2 = INS_Next(ins2)) {
//                     if (INS_Address(ins2) >= target_addr && INS_Address(ins2) < curr_addr
//                         && INS_IsDirectBranch(ins2) && INS_DirectControlFlowTargetAddress(ins2) > curr_addr) { //find branches inside the loop
//                         INS_InsertCall(ins2, IPOINT_BEFORE,
//                             (AFUNPTR)docount_invoked2,
//                             IARG_FAST_ANALYSIS_CALL,
//                             IARG_ADDRINT, target_addr,
//                             IARG_BRANCH_TAKEN,
//                             IARG_END);
//                     }
//                 }
//	 	RTN_Close(rtn);
//             }
//         }
//     }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    std::vector<std::pair<ADDRINT, UINT64>> vector_ins(call_count_map.begin(), call_count_map.end()); // call address -> #invocations map
    std::sort(vector_ins.begin(), vector_ins.end(),
        [](const auto & lhs, const auto & rhs)
        { return lhs.second > rhs.second; }
    ); // sort by call invocation number - hottest calls first

    std::ofstream call_file;
    call_file.open("call-count.csv");

    map<ADDRINT, UINT64> seen_rtn_map;
    for (const auto & item : vector_ins) { // for each call
     if (seen_rtn_map[call_target_map[item.first]]) {
         continue;
     }
     else {
         seen_rtn_map[call_target_map[item.first]] = 1;
     }
     //0x<call address>, <count invoked>
     call_file << "0x" << std::hex << item.first << std::dec << ',' << item.second << ',';
     // 0x<rtn addr>
     call_file << "0x" << std::hex << call_target_map[item.first] << std::endl;
    }
    call_file.close();

    std::ofstream branch_file;
    branch_file.open("branch-count.csv");
    int flag;

    for (const auto & item : bbl_map) { // for each bbl
        flag = 0;
        if (taken_map[item.second.bbl_tail] < not_taken_map[item.second.bbl_tail]) {
            flag = 1;
        }

        //0x<bbl address>, <bbl tail address>
        branch_file << "0x" << std::hex << item.first << std::dec << ",0x" << std::hex << item.second.bbl_tail << std::dec << ',';
        // 0x<taken address> 0x<not taken address> (0 when irrelevant)
        branch_file << "0x" << std::hex << item.second.next_taken << std::dec << ",0x" << std::hex << item.second.next_not_taken << std::dec << ',';
        // <hotter next> (0 when taken more, 1 when not taken more)
        branch_file << flag << std::endl;
    }
    branch_file.close();

	std::cout << "Reached FINI" << std::endl;
}


/* ===================================================================== */

INT32 Usage()
{
    std::cerr << "This tool prints out the number of dynamic instructions executed in each routine.\n"
            "\n";

    std::cerr << KNOB_BASE::StringKnobSummary();

    std::cerr << std::endl;

    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    PIN_InitSymbols();

    bool prof = KnobProf.Value();
    bool opt = KnobOpt.Value();
    if (prof && opt) {
	return Usage();
    }

    if (prof) {
	    INS_AddInstrumentFunction(Instruction, 0);
        TRACE_AddInstrumentFunction(Trace, 0);
    	PIN_AddFiniFunction(Fini, 0);

    	// Never returns
    	PIN_StartProgram();
    }

    if (opt) {
	// Register ImageLoad
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Start the program, never returns
	PIN_StartProgramProbed();
    }

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */