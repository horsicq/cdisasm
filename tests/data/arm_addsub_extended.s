.text
add x0, x1, w2, uxtb #0
add x0, x1, w2, uxth #1
add x0, x1, w2, uxtw #2
add x0, x1, x2, uxtx #3
add x0, x1, w2, sxtb #4
add x0, x1, w2, sxth #0
add x0, x1, w2, sxtw #1
add x0, x1, x2, sxtx #2
adds x0, x1, w2, uxtw #1
sub x0, x1, x2, sxtx #4
subs xzr, x1, w2, sxtw #2
cmn x1, w2, sxtw #2
cmp x1, x2, uxtx #4
add w0, w1, w2, uxtb #0
adds w0, w1, w2, uxth #1
sub w0, w1, w2, uxtw #2
subs wzr, w1, w2, sxtb #3
cmn w1, w2, sxth #4
cmp w1, w2, sxtw #2
