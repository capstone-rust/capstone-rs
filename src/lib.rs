//! # libcapstone.so.3 bindings
//!
//! If you want to compile this for another target,  `wasm32-unknown-emscripten`, for example,
//! it is currently recommended that pass the two feature flags `build_src` and `use_cmake`.
//! This has seen some (limited) testing and has been seen to work on the `wasm32-unknown-emscripten` target at least.
//!
//! Compiling on windows has not been tested.

#![allow(non_camel_case_types)]
extern crate libc;

/// Handle using with all API
pub type csh = libc::size_t;

/// Architecture type
pub type cs_arch = u16;
/// ARM architecture (including Thumb, Thumb-2)
pub const CS_ARCH_ARM: cs_arch = 0;
/// ARM-64, also called AArch64
pub const CS_ARCH_ARM64: cs_arch = 1;
/// Mips architecture
pub const CS_ARCH_MIPS: cs_arch = 2;
/// X86 architecture (including x86 & x86-64)
pub const CS_ARCH_X86: cs_arch = 3;
/// PowerPC architecture
pub const CS_ARCH_PPC: cs_arch = 4;
/// Sparc architecture
pub const CS_ARCH_SPARC: cs_arch = 5;
/// SystemZ architecture
pub const CS_ARCH_SYSZ: cs_arch = 6;
/// XCore architecture
pub const CS_ARCH_XCORE: cs_arch = 7;
pub const CS_ARCH_MAX: cs_arch = 8;
/// All architectures - for cs_support()
pub const CS_ARCH_ALL: cs_arch = 0xFFFF;

/// Mode type
pub type cs_mode = u32;
/// little-endian mode (default mode)
pub const CS_MODE_LITTLE_ENDIAN: cs_mode = 0;
/// 32-bit ARM
pub const CS_MODE_ARM: cs_mode = 0;
/// 16-bit mode (X86)
pub const CS_MODE_16: cs_mode = 1 << 1;
/// 32-bit mode (X86)
pub const CS_MODE_32: cs_mode = 1 << 2;
/// 64-bit mode (X86, PPC)
pub const CS_MODE_64: cs_mode = 1 << 3;
/// ARM's Thumb mode, including Thumb-2
pub const CS_MODE_THUMB: cs_mode = 1 << 4;
/// ARM's Cortex-M series
pub const CS_MODE_MCLASS: cs_mode = 1 << 5;
/// ARMv8 A32 encodings for ARM
pub const CS_MODE_V8: cs_mode = 1 << 6;
/// MicroMips mode (MIPS)
pub const CS_MODE_MICRO: cs_mode = 1 << 4;
/// Mips III ISA
pub const CS_MODE_MIPS3: cs_mode = 1 << 5;
/// Mips32r6 ISA
pub const CS_MODE_MIPS32R6: cs_mode = 1 << 6;
/// General Purpose Registers are 64-bit wide (MIPS)
pub const CS_MODE_MIPSGP64: cs_mode = 1 << 7;
/// SparcV9 mode (Sparc)
pub const CS_MODE_V9: cs_mode = 1 << 4;
/// big-endian mode
pub const CS_MODE_BIG_ENDIAN: cs_mode = 1 << 31;
/// Mips32 ISA (Mips)
pub const CS_MODE_MIPS32: cs_mode = CS_MODE_32;
/// Mips64 ISA (Mips)
pub const CS_MODE_MIPS64: cs_mode = CS_MODE_64;

/// Runtime option for the disassembled engine
pub type cs_opt_type = u8;
pub const CS_OPT_SYNTAX: cs_opt_type = 1;
/// Break down instruction structure into details
pub const CS_OPT_DETAIL: cs_opt_type = 2;
/// Change engine's mode at run-time
pub const CS_OPT_MODE: cs_opt_type = 3;
/// User-defined dynamic memory related functions
pub const CS_OPT_MEM: cs_opt_type = 4;
/// Skip data when disassembling. Then engine is in SKIPDATA mode.
pub const CS_OPT_SKIPDATA: cs_opt_type = 5;
/// Setup user-defined function for SKIPDATA option
pub const CS_OPT_SKIPDATA_SETUP: cs_opt_type = 6;

// TODO: must verify these values manually very likely
/// Runtime option value (associated with option type above)
pub type cs_opt_value = libc::size_t;
/// Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA.
pub const CS_OPT_OFF: cs_opt_value = 0;
/// Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
pub const CS_OPT_ON: cs_opt_value = 3;
/// Default asm syntax (CS_OPT_SYNTAX).
pub const CS_OPT_SYNTAX_DEFAULT: cs_opt_value = 0;
/// X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
pub const CS_OPT_SYNTAX_INTEL: cs_opt_value = 1;
/// X86 ATT asm syntax (CS_OPT_SYNTAX).
pub const CS_OPT_SYNTAX_ATT: cs_opt_value = 2;
/// Prints register name with only number (CS_OPT_SYNTAX)
pub const CS_OPT_SYNTAX_NOREGNAME: cs_opt_value = 4;

/// Common instruction operand types - to be consistent across all architectures.
pub type cs_op_type = u8;
/// uninitialized/invalid operand.
pub const CS_OP_INVALID: cs_op_type = 0;
/// Register operand.
pub const CS_OP_REG: cs_op_type = 1;
/// Immediate operand.
pub const CS_OP_IMM: cs_op_type = 2;
/// Memory operand.
pub const CS_OP_MEM: cs_op_type = 3;
/// Floating-Point operand.
pub const CS_OP_FP: cs_op_type = 4;

/// Common instruction groups - to be consistent across all architectures.
pub type cs_group_type = u8;
/// uninitialized/invalid group.
pub const CS_GRP_INVALID: cs_group_type = 0;
/// all jump instructions (conditional+direct+indirect jumps)
pub const CS_GRP_JUMP: cs_group_type = 1;
/// all call instructions
pub const CS_GRP_CALL: cs_group_type = 2;
/// all return instructions
pub const CS_GRP_RET: cs_group_type = 3;
/// all interrupt instructions (int+syscall)
pub const CS_GRP_INT: cs_group_type = 4;
/// all interrupt return instructions
pub const CS_GRP_IRET: cs_group_type = 5;

/// All type of errors encountered by Capstone API.
/// These are values returned by cs_errno()
pub type cs_err = u8;
/// No error: everything was fine
pub const CS_ERR_OK: cs_err = 0;
/// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
pub const CS_ERR_MEM: cs_err = 1;
/// Unsupported architecture: cs_open()
pub const CS_ERR_ARCH: cs_err = 2;
/// Invalid handle: cs_op_count(), cs_op_index()
pub const CS_ERR_HANDLE: cs_err = 3;
/// Invalid csh argument: cs_close(), cs_errno(), cs_option()
pub const CS_ERR_CSH: cs_err = 4;
/// Invalid/unsupported mode: cs_open()
pub const CS_ERR_MODE: cs_err = 5;
/// Invalid/unsupported option: cs_option()
pub const CS_ERR_OPTION: cs_err = 6;
/// Information is unavailable because detail option is OFF
pub const CS_ERR_DETAIL: cs_err = 7;
/// Dynamic memory management uninitialized (see CS_OPT_MEM)
pub const CS_ERR_MEMSETUP: cs_err = 8;
/// Unsupported version (bindings)
pub const CS_ERR_VERSION: cs_err = 9;
/// Access irrelevant data in "diet" engine
pub const CS_ERR_DIET: cs_err = 10;
/// Access irrelevant data for "data" instruction in SKIPDATA mode
pub const CS_ERR_SKIPDATA: cs_err = 11;
/// X86 AT&T syntax is unsupported (opt-out at compile time)
pub const CS_ERR_X86_ATT: cs_err = 12;
/// X86 Intel syntax is unsupported (opt-out at compile time)
pub const CS_ERR_X86_INTEL: cs_err = 13;

/// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
#[repr(C)]
pub struct cs_detail {
    /// list of implicit registers read by this insn
    pub regs_read: [libc::uint8_t; 12],
    /// number of implicit registers read by this insn
    pub regs_read_count: libc::uint8_t,
    /// list of implicit registers modified by this insn
    pub regs_write: [libc::uint8_t; 20],
    /// number of implicit registers modified by this insn
    pub regs_write_count: libc::uint8_t,
    /// list of group this instruction belong to
    pub groups: [libc::uint8_t; 8],
    /// number of groups this insn belongs to
    pub groups_count: libc::uint8_t,
    /// Architecture-specific instruction info
    /// **NOTE** this is not implemented right now, because it's tedious, boring and very specific
    /// size in bytes:
    /// cs_detail: 1528
    /// cs_detail_minus_arch_specific: 43
    /// cs_x86: 432
    /// cs_arm64: 392
    /// cs_arm: 1480
    /// cs_mips: 200
    /// cs_ppc: 140
    /// cs_sparc: 60
    /// cs_sysz: 200
    /// cs_xcore: 132
    // we need to add an extra 5 bytes to make the 1528, as rust doesn't pad like C's unions do. i think ;)
    _unused: [libc::uint8_t; 1485],
    /* go ahead and implement these if you like, i'm not interested right now ;)
    // union
    cs_x86 x86; // X86 architecture, including 16-bit, 32-bit & 64-bit mode
    cs_arm64 arm64; // ARM64 architecture (aka AArch64)
    cs_arm arm; // ARM architecture (including Thumb/Thumb2)
    cs_mips mips; // MIPS architecture
    cs_ppc ppc; // PowerPC architecture
    cs_sparc sparc; // Sparc architecture
    cs_sysz sysz; // SystemZ architecture
    cs_xcore xcore; // XCore architecture
    */
}

/// Detail information of disassembled instruction
#[repr(C)]
pub struct cs_insn {
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
    /// Find the instruction id in the '[ARCH]_insn' enum in the header file
    /// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    /// 'x86_insn' in x86.h for X86, etc...
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    /// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    pub id: libc::c_uint,
    /// Address (EIP) of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    pub address: libc::uint64_t,
    /// Size of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    pub size: libc::uint16_t,
    /// Machine bytes of this instruction, with number of bytes indicated by @size above
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    pub bytes: [libc::uint8_t; 16],
    /// Ascii text of instruction mnemonic
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    pub mnemonic: [libc::c_char; 32],
    /// Ascii text of instruction operands
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    pub op_str: [libc::c_char; 160],
    /// Pointer to cs_detail.
    /// NOTE: detail pointer is only valid when both requirements below are met:
    /// (1) CS_OP_DETAIL = CS_OPT_ON
    /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    ///
    /// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
    ///     is not NULL, its content is still irrelevant.
    pub detail: *mut cs_detail,
}

extern "C" {

    /// Return combined API version & major and minor version numbers.
    ///
    /// `major`: major number of API version
    /// `minor`: minor number of API version
    ///
    /// return hexical number as (major << 8 | minor), which encodes both
    /// major & minor versions.
    /// NOTE: This returned value can be compared with version number made
    /// with macro CS_MAKE_VERSION
    ///
    /// For example, second API version would return 1 in @major, and 1 in @minor
    /// The return value would be 0x0101
    ///
    /// NOTE: if you only care about returned value, but not major and minor values,
    /// set both `major` & `minor` arguments to NULL.
    ///
    pub fn cs_version(major: *mut libc::c_int, minor: *mut libc::c_int) -> libc::c_uint;

    /// This API can be used to either ask for archs supported by this library,
    /// or check to see if the library was compile with 'diet' option (or called
    /// in 'diet' mode).
    ///
    /// To check if a particular arch is supported by this library, set @query to
    /// arch mode (CS_ARCH_* value).
    /// To verify if this library supports all the archs, use CS_ARCH_ALL.
    ///
    /// To check if this library is in 'diet' mode, set @query to CS_SUPPORT_DIET.
    ///
    /// return True if this library supports the given arch, or in 'diet' mode.
    ///
    pub fn cs_support(query: libc::c_int) -> bool;

    /// Initialize CS handle: this must be done before any usage of CS.
    ///
    /// `arch`: architecture type (CS_ARCH_*)
    /// `mode`: hardware mode. This is combined of CS_MODE_*
    /// `handle`: pointer to handle, which will be updated at return time
    ///
    /// return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
    /// for detailed error).
    ///
    pub fn cs_open(arch: cs_arch, mode: cs_mode, handle: *mut csh) -> cs_err;

    /// Close CS handle: MUST do to release the handle when it is not used anymore.
    /// NOTE: this must be only called when there is no longer usage of Capstone,
    /// not even access to cs_insn array. The reason is the this API releases some
    /// cached memory, thus access to any Capstone API after cs_close() might crash
    /// your application.
    ///
    /// In fact, this API invalidate `handle` by ZERO out its value (i.e *handle = 0).
    ///
    /// `handle`: pointer to a handle returned by cs_open()
    ///
    /// return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
    /// for detailed error).
    ///
    pub fn cs_close(handle: *mut csh) -> cs_err;

    /// Set option for disassembling engine at runtime
    ///
    /// `handle`: handle returned by cs_open()
    /// `type`: type of option to be set
    /// `value`: option value corresponding with @type
    ///
    /// return: CS_ERR_OK on success, or other value on failure.
    /// Refer to cs_err enum for detailed error.
    ///
    /// NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
    /// so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
    /// even before cs_open()
    ///
    pub fn cs_option(handle: csh, typ: cs_opt_type, value: libc::size_t) -> cs_err;

    /// Report the last error number when some API function fail.
    /// Like glibc's errno, cs_errno might not retain its old value once accessed.
    ///
    /// `handle`: handle returned by cs_open()
    ///
    /// return: error code of cs_err enum type (CS_ERR_*, see above)
    ///
    pub fn cs_errno(handle: csh) -> cs_err;

    /// Return a string describing given error code.
    ///
    /// `code`: error code (see CS_ERR_* above)
    ///
    /// return: returns a pointer to a string that describes the error code
    /// passed in the argument @code
    ///
    pub fn cs_strerror(code: cs_err) -> *mut libc::c_char;

    /// Disassemble binary code, given the code buffer, size, address and number
    /// of instructions to be decoded.
    /// This API dynamically allocate memory to contain disassembled instruction.
    /// Resulted instructions will be put into *`insn`
    ///
    /// NOTE 1: this API will automatically determine memory needed to contain
    /// output disassembled instructions in `insn`.
    ///
    /// NOTE 2: caller must free the allocated memory itself to avoid memory leaking.
    ///
    /// NOTE 3: for system with scarce memory to be dynamically allocated such as
    /// OS kernel or firmware, the API cs_disasm_iter() might be a better choice than
    /// cs_disasm(). The reason is that with cs_disasm(), based on limited available
    /// memory, we have to calculate in advance how many instructions to be disassembled,
    /// which complicates things. This is especially troublesome for the case `count`=0,
    /// when cs_disasm() runs uncontrollably (until either end of input buffer, or
    /// when it encounters an invalid instruction).
    ///
    /// `handle`: handle returned by cs_open()
    ///
    /// `code`: buffer containing raw binary code to be disassembled.
    ///
    /// `code_size`: size of the above code buffer.
    ///
    /// `address`: address of the first instruction in given raw code buffer.
    ///
    /// `insn`: array of instructions filled in by this API. NOTE: `insn` will be allocated by this function, and should be freed with cs_free() API.
    ///
    /// `count`: number of instructions to be disassembled, or 0 to get all of them
    ///
    /// return: the number of successfully disassembled instructions,
    /// or 0 if this function failed to disassemble the given code
    ///
    /// On failure, call cs_errno() for error code.
    ///
    pub fn cs_disasm(handle: csh,
                     code: *const libc::uint8_t,
                     code_size: libc::size_t,
                     address: libc::uint64_t,
                     count: libc::size_t,
                     insn: *mut *mut cs_insn)
                     -> libc::size_t;

    /// Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)
    ///
    /// `insn`: pointer returned by @insn argument in cs_disasm() or cs_malloc()
    /// `count`: number of cs_insn structures returned by cs_disasm(), or 1
    /// to free memory allocated by cs_malloc().
    ///
    pub fn cs_free(insn: *mut cs_insn, count: libc::size_t);

    /// Allocate memory for 1 instruction to be used by cs_disasm_iter().
    ///
    /// `handle`: handle returned by cs_open()
    ///
    /// NOTE: when no longer in use, you can reclaim the memory allocated for
    /// this instruction with cs_free(insn, 1)
    ///
    pub fn cs_malloc(handle: csh) -> *mut cs_insn;

    /// Fast API to disassemble binary code, given the code buffer, size, address
    /// and number of instructions to be decoded.
    /// This API put the resulted instruction into a given cache in @insn.
    /// See tests/test_iter.c for sample code demonstrating this API.
    ///
    /// NOTE 1: this API will update `code`, `size` & `address` to point to the next
    /// instruction in the input buffer. Therefore, it is convenient to use
    /// cs_disasm_iter() inside a loop to quickly iterate all the instructions.
    /// While decoding one instruction at a time can also be achieved with
    /// cs_disasm(count=1), some benchmarks shown that cs_disasm_iter() can be 30%
    /// faster on random input.
    ///
    /// NOTE 2: the cache in `insn` can be created with cs_malloc() API.
    ///
    /// NOTE 3: for system with scarce memory to be dynamically allocated such as
    /// OS kernel or firmware, this API is recommended over cs_disasm(), which
    /// allocates memory based on the number of instructions to be disassembled.
    /// The reason is that with cs_disasm(), based on limited available memory,
    /// we have to calculate in advance how many instructions to be disassembled,
    /// which complicates things. This is especially troublesome for the case
    /// `count`=0, when cs_disasm() runs uncontrollably (until either end of input
    /// buffer, or when it encounters an invalid instruction).
    ///
    /// `handle`: handle returned by cs_open()
    /// `code`: buffer containing raw binary code to be disassembled
    /// `code_size`: size of above code
    /// `address`: address of the first insn in given raw code buffer
    /// `insn`: pointer to instruction to be filled in by this API.
    ///
    /// return: true if this API successfully decode 1 instruction,
    /// or false otherwise.
    ///
    /// On failure, call cs_errno() for error code.
    ///
    pub fn cs_disasm_iter(handle: csh,
                          code: *mut *const libc::uint8_t,
                          size: *mut libc::size_t,
                          address: *mut libc::uint64_t,
                          insn: *mut cs_insn)
                          -> bool;

    /// Return friendly name of register in a string.
    /// Find the instruction id from header file of corresponding architecture (arm.h for ARM,
    /// x86.h for X86, ...)
    ///
    /// WARN: when in 'diet' mode, this API is irrelevant because engine does not
    /// store register name.
    ///
    /// `handle`: handle returned by cs_open()
    /// `reg_id`: register id
    ///
    /// return: string name of the register, or NULL if `reg_id` is invalid.
    ///
    pub fn cs_reg_name(handle: csh, reg_id: libc::c_uint) -> *const libc::c_char;

    /// Return friendly name of an instruction in a string.
    /// Find the instruction id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    ///
    /// WARN: when in 'diet' mode, this API is irrelevant because the engine does not
    /// store instruction name.
    ///
    /// `handle`: handle returned by cs_open()
    /// `insn_id`: instruction id
    ///
    /// return: string name of the instruction, or NULL if `insn_id` is invalid.
    ///
    pub fn cs_insn_name(handle: csh, insn_id: libc::c_uint) -> *const libc::c_char;

    /// Return friendly name of a group id (that an instruction can belong to)
    /// Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    ///
    /// WARN: when in 'diet' mode, this API is irrelevant because the engine does not
    /// store group name.
    ///
    /// `handle`: handle returned by cs_open()
    /// `group_id`: group id
    ///
    /// return: string name of the group, or NULL if `group_id` is invalid.
    ///
    pub fn cs_group_name(handle: csh, group_id: libc::c_uint) -> *const libc::c_char;

    /// Check if a disassembled instruction belong to a particular group.
    /// Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    /// Internally, this simply verifies if `group_id` matches any member of insn->groups array.
    ///
    /// NOTE: this API is only valid when detail option is ON (which is OFF by default).
    ///
    /// WARN: when in 'diet' mode, this API is irrelevant because the engine does not
    /// update `groups` array.
    ///
    /// `handle`: handle returned by cs_open()
    /// `insn`: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
    /// `group_id`: group that you want to check if this instruction belong to.
    ///
    /// return: true if this instruction indeed belongs to aboved group, or false otherwise.
    ///
    pub fn cs_insn_group(handle: csh, insn: *const cs_insn, group_id: libc::c_uint) -> bool;

    /// Check if a disassembled instruction IMPLICITLY used a particular register.
    /// Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    /// Internally, this simply verifies if `reg_id` matches any member of insn->regs_read array.
    ///
    /// NOTE: this API is only valid when detail option is ON (which is OFF by default)
    ///
    /// WARN: when in 'diet' mode, this API is irrelevant because the engine does not
    /// update `regs_read` array.
    ///
    /// `insn`: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
    /// `reg_id`: register that you want to check if this instruction used it.
    ///
    /// return: true if this instruction indeed implicitly used aboved register, or false otherwise.
    ///
    pub fn cs_reg_read(handle: csh, insn: *const cs_insn, reg_id: libc::c_uint) -> bool;

    /// Check if a disassembled instruction IMPLICITLY modified a particular register.
    /// Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    /// Internally, this simply verifies if @reg_id matches any member of insn->regs_write array.
    ///
    /// NOTE: this API is only valid when detail option is ON (which is OFF by default)
    ///
    /// WARN: when in 'diet' mode, this API is irrelevant because the engine does not
    /// update @regs_write array.
    ///
    /// `insn`: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
    /// `reg_id`: register that you want to check if this instruction modified it.
    ///
    /// return: true if this instruction indeed implicitly modified aboved register, or false otherwise.
    ///
    pub fn cs_reg_write(handle: csh, insn: *const cs_insn, reg_id: libc::c_uint) -> bool;

    /// Count the number of operands of a given type.
    /// Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    ///
    /// NOTE: this API is only valid when detail option is ON (which is OFF by default)
    ///
    /// `handle`: handle returned by cs_open()
    /// `insn`: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
    /// `op_type`: Operand type to be found.
    ///
    /// return: number of operands of given type `op_type` in instruction `insn`,
    /// or -1 on failure.
    ///
    pub fn cs_op_count(handle: csh, insn: *const cs_insn, op_type: libc::c_uint) -> libc::c_int;

    /// Retrieve the position of operand of given type in <arch>.operands[] array.
    /// Later, the operand can be accessed using the returned position.
    /// Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
    ///
    /// NOTE: this API is only valid when detail option is ON (which is OFF by default)
    ///
    /// `handle`: handle returned by cs_open()
    /// `insn`: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
    /// `op_type`: Operand type to be found.
    /// `position`: position of the operand to be found. This must be in the range
    /// [1, cs_op_count(handle, insn, op_type)]
    ///
    /// return: index of operand of given type `op_type` in <arch>.operands[] array
    /// in instruction `insn`, or -1 on failure.
    ///
    pub fn cs_op_index(handle: csh,
                       insn: *const cs_insn,
                       op_type: libc::c_uint,
                       position: libc::c_uint)
                       -> libc::c_int;
}

#[test]
fn cs_detail_length() {
    use std::mem;
    assert!(mem::size_of::<cs_detail>() == 1528);
}
