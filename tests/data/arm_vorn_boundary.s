/* Independent LLVM assembler witnesses for the VORR encodings shared with
 * Arm's assembly-only VORN (immediate) pseudo-instruction. */
.syntax unified
.arch armv7-a
.fpu neon
.text
.arm
vorr.i32 d0, #0x12
vorr.i32 q0, #0x12
vorr.i16 d0, #0x12
vorr.i16 q0, #0x12
.thumb
vorr.i32 d0, #0x1200
vorr.i32 q0, #0x1200
vorr.i16 d0, #0x12
vorr.i16 q0, #0x12
