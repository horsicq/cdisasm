.syntax unified
.arm
.fpu neon-fp16
.text
vcvt.f32.u32 q0, q1
vcvt.u32.f32 q2, q3
vcvt.s32.f32 d0, d1, #8
vcvt.f32.s32 d2, d3, #8
.thumb
vcvt.f32.u32 q0, q1
vcvt.u32.f32 q2, q3
vcvt.s32.f32 d0, d1, #8
vcvt.f32.s32 d2, d3, #8
