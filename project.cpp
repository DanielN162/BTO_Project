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
const int NUM_HOT_CALLS = 10;
const int MIN_CALLS = 100;

struct bbl_data {
    ADDRINT bbl_tail;
    ADDRINT next_taken;
    ADDRINT next_not_taken;
    int hotter_next; // 0 when branch is more likely to be taken, otherwise 1
};

map<ADDRINT, bbl_data> bbl_map; // key is bbl_head
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
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size)
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

    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
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


bool add_decoded_ins_to_map(ADDRINT ins_addr, xed_decoded_inst_t* xedd) {
	int rc = add_new_instr_entry(xedd, ins_addr, xed_decoded_inst_get_length(xedd));
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



// ************* OLD AUX

bool add_nop_at_addr(ADDRINT nop_addr) {
	if (KnobVerbose)
		cerr << "Adding a NOP command" << endl;

	xed_decoded_inst_t xedd_nop;
	UINT8 nop_arr[1] = { 0x90 };
	if (decode_ins(reinterpret_cast<ADDRINT>(&nop_arr), &xedd_nop))
		return false;
	if (!add_decoded_ins_to_map(-1, &xedd_nop))
		return false;
	return true;
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
int load_profiling_data(vector<RTN> callers_to_emit) {
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
    while(true) { // TODO: change condition?
        getline(call_prof_file, call_addr_str, ','); // read hot call address
        hot_call_addr = AddrintFromString(call_addr_str);
        getline(call_prof_file, call_num_str, ','); // read number of times call has been invoked
        if (atoi(call_num_str.c_str()) < MIN_CALLS) { // TODO: change condition?
            // cerr << "not enough calls";
            break;
        }
        // cerr << "enough calls" << endl;
        getline(call_prof_file, call_targ_str); // read target of hot call
        hot_target_addr = AddrintFromString(call_targ_str);

        if (is_rtn_inline_valid(hot_call_addr, hot_target_addr)) {
            // hot_calls_to_inline.push_back(make_pair(hot_call_addr, hot_target_addr)); // mark call as hot
            // callers_to_emit.push_back(RTN_FindByAddress(hot_call_addr));
            std::cout << "Hot call found at 0x" << hex << hot_call_addr << " to addr 0x" << hot_target_addr << dec << ", num invocations: " << call_num_str << std::endl;
            int x;
            cin >> x; // Get user input from the keyboard
            if (x != 0) {
                hot_calls_to_inline.push_back(make_pair(hot_call_addr, hot_target_addr)); // mark call as hot
                callers_to_emit.push_back(RTN_FindByAddress(hot_call_addr));
            }
        }
        else {
            // cerr << "illegal" << endl;
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

    // TODO: go over bbl_map. For each bbl where !bbl.hotter_next, revert jump

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

	if (KnobVerbose)
		cerr << "Finished translation.\n" << endl;

    // Go over the local_instrs_map map and perform inlining (still not changing the global instr_map):
    int rtn_num = 0;
    vector<pair<ADDRINT, xed_decoded_inst_t>> local_instrs_inlined;
	
    for (map<ADDRINT, xed_decoded_inst_t>::iterator iter = local_instrs_map.begin(); iter != local_instrs_map.end(); iter++) {
		ADDRINT addr = iter->first;
		xed_decoded_inst_t xedd = iter->second;

		// Check if we are at a routine header:
		if (translated_rtn[rtn_num].rtn_addr == addr) {
			rtn_num++;
		}

		if (find(callers_to_emit.begin(), callers_to_emit.end(), RTN_FindByAddress(addr)) != callers_to_emit.end()) { // do not emit this caller
			if (translated_rtn[rtn_num-1].rtn_addr == addr) {
				cerr << "\nEntered function no. [" << dec << rtn_num - 1 << "]: " << RTN_Name(RTN_FindByAddress(addr)) << endl;
				translated_rtn[rtn_num-1].instr_map_entry = num_of_instr_map_entries;
				translated_rtn[rtn_num-1].isSafeForReplacedProbe = true;
			}
		}
		else {
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
				cerr << "Start inlining rtn " << RTN_Name(rtn) << " at 0x" << hex << instr_map[num_of_instr_map_entries-1].new_ins_addr << dec << endl;

				for (INS ins_callee = RTN_InsHead(rtn); INS_Valid(ins_callee); ins_callee = INS_Next(ins_callee)) {
					if (KnobVerbose)
						cerr << "Original inst: " << INS_Disassemble(ins_callee) << endl;

					// if (!add_nop_at_addr(addr)) { // TODO: just an attempt to insert nops
					// 	break;
					// }

					if (INS_IsRet(ins_callee)) {
						break;
					}
					else {
						xed_decoded_inst_t xedd_callee = local_instrs_map[INS_Address(ins_callee)];
						// if (!add_decoded_ins_to_map(INS_Address(ins_callee), &xedd_callee)) { // failed to encode / add to instr_map
						// 	break;
						// }
                        local_instrs_inlined.push_back(make_pair(INS_Address(ins_callee), xedd_callee));

					}
				}

				cerr << "End inlining rtn " << RTN_Name(rtn) << endl;
			}

			else {
				// Add instr into local_instrs_inlined vector:
				// if (!add_decoded_ins_to_map(addr, &xedd))
				// 	break;
                local_instrs_inlined.push_back(make_pair(addr, xedd));
			}

			RTN_Close(rtn);
		}

		else {
			// Add instr into local_instrs_inlined vector:
			// if (!add_decoded_ins_to_map(addr, &xedd))
			// 	break;
            local_instrs_inlined.push_back(make_pair(addr, xedd));
		}
    } // end for map<...

    ADDRINT start_reorder = 0;
    map<pair<ADDRINT, ADDRINT>, pair<ADDRINT, ADDRINT>> swaps; // key - scope of taken route block, value - scope of non-taken route block
    // Perform code reorder and add instructions to global instr_map
    for (auto & iter : local_instrs_inlined) { 
    // TODO: go over vector using indices instead of foreach loop. 
    // When needing to reorder, splice the vector and physically swap the location of the taken block instructions with
    // the not-taken block instructions.
        if (bbl_map[start_reorder].bbl_tail == iter.first) { // reached a conditional branch we need to revert
            if (!add_decoded_ins_to_map(iter.first, &iter.second))
                break;

            bbl_data curr_block = bbl_map[start_reorder];
            bbl_data taken_block = bbl_map[curr_block.next_taken];
            bbl_data not_taken_block = bbl_map[curr_block.next_not_taken];
            // 1. revert conditional branch in the final instruction of the block and commit
            // 2. commit block in taken route
            // 3. add jmp
            // 4. save swap in map
            swaps[make_pair(curr_block.next_taken, taken_block.bbl_tail)] = make_pair(curr_block.next_not_taken, not_taken_block.bbl_tail);
            // 5. when reaching the taken route address, instead commit non-taken route and add jmp
        }
        // while we haven't reached a block needing reoreder, keep adding instructions to instr_map
        if (bbl_map.find(iter.first) == bbl_map.end()) { // instruction not start of bbl
            // Add instr into global instr_map map:
            if (!add_decoded_ins_to_map(iter.first, &iter.second))
                break;
        }
        else {
            if (bbl_map[iter.first].hotter_next) { // no need to reorder the block's "children"
                if (!add_decoded_ins_to_map(iter.first, &iter.second))
                    break;
                continue;
            }
            else { // need to reorder the block's "children"
                if (iter.first == bbl_map[iter.first].bbl_tail) { // block has only one instruction
                    if (!add_decoded_ins_to_map(iter.first, &iter.second))
                        break;

                    bbl_data curr_block = bbl_map[start_reorder];
                    bbl_data taken_block = bbl_map[curr_block.next_taken];
                    bbl_data not_taken_block = bbl_map[curr_block.next_not_taken];
                    // 1. revert conditional branch in the final instruction of the block and commit
                    // 2. commit block in taken route
                    // 3. add jmp
                    // 4. save swap in map
                    swaps[make_pair(curr_block.next_taken, taken_block.bbl_tail)] = make_pair(curr_block.next_not_taken, not_taken_block.bbl_tail);
                    // 5. when reaching the taken route address, instead commit non-taken route and add jmp
                }
                else {
                    start_reorder = iter.first;
                }
            }
        }

    }

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

// // count invocations (ignore iterations) and update diffs, for two different types of loops
// // runs when we EXIT an invocation (prepares vector for the next one)
// VOID docount_invoked(ADDRINT target_addr) {
//     invoked_map[target_addr]++;
//
//     if (last_map[target_addr] != 0) {
// 	diff_map[target_addr] += (last_map[target_addr] != curr_map[target_addr]);
//     }
//     last_map[target_addr] = curr_map[target_addr];
//     curr_map[target_addr] = 0;
// }
//
// VOID docount_invoked2(ADDRINT target_addr, INT32 taken) {
//     if (taken) {
// 	invoked_map[target_addr]++;
//         if (last_map[target_addr] != 0) {
// 	    diff_map[target_addr] += (last_map[target_addr] != curr_map[target_addr]);
//         }
//         last_map[target_addr] = curr_map[target_addr];
//         curr_map[target_addr] = 0;
//     }
// }
//
// // count instructions in rtn
// VOID docount(ADDRINT rtn_addr) { rtn_ins_map[rtn_addr]++; }
//
// // count calls to rtn
// VOID docount_rtn(ADDRINT rtn_addr) { rtn_count_map[rtn_addr]++; }

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

	std::cout << "Reached FINI!" << std::endl;
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