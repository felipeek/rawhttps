; Arguments in the x64-86 calling convention for linux (in order):
; RDI
; RSI
; RDX
; RCX
; R8
; R9

global aes_128_cbc_encrypt
global aes_128_cbc_decrypt

section .text

; RDI = uint8_t  block[16]
; RSI = uint8_t  key[16]
; RDX = uint8_t  IV[16]
; RCX = int      count     @Important: Must be in RCX so loop knows how many times to loop
; R8  = uint8_t* result

aes_calculate_keys:
    movdqu xmm1, [rsi]
    ; push xmm1 (first key)
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x1
    ; We only keep the last double word SubByte(RotByte(xmm2[3])) Rcon
    pshufd xmm2, xmm2, 0xff
    
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4    ; W[i1] goes to W[i] place
    pxor xmm1, xmm3     ; xor all W[i] with W[i1]

    pslldq xmm3, 0x4    ; W[i2] goes to W[i] place
    pxor xmm1, xmm3     ; xor all W[i] with W[i2]

    pslldq xmm3, 0x4    ; W[i3] goes to W[i] place
    pxor xmm1, xmm3     ; xor all W[i] with W[i3]

    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x2
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x4
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x8
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x10
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x20
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x40
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x80
    pshufd xmm2, xmm2, 0xff
    
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x1b
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; push xmm1
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x36
    pshufd xmm2, xmm2, 0xff
    movdqa xmm3, xmm1
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pslldq xmm3, 0x4
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    movdqu xmm11, xmm1

    ; Pop
    movdqu xmm10, [rsp]
    add rsp, 16
    movdqu xmm9, [rsp]
    add rsp, 16
    movdqu xmm8, [rsp]
    add rsp, 16
    movdqu xmm7, [rsp]
    add rsp, 16
    movdqu xmm6, [rsp]
    add rsp, 16
    movdqu xmm5, [rsp]
    add rsp, 16
    movdqu xmm4, [rsp]
    add rsp, 16
    movdqu xmm3, [rsp]
    add rsp, 16
    movdqu xmm2, [rsp]
    add rsp, 16
    movdqu xmm1, [rsp]
    add rsp, 16

    ; keys are given in the registers xmm1-xmm11
    ret

; void aes_encrypt(uint8_t* block, uint8_t* key, uint8_t* result);
aes_128_cbc_encrypt:
    ; Encrypt

    ; Keys are returned in the registers xmm1-xmm11
    call aes_calculate_keys

    xor rax, rax

    pxor xmm12, xmm12
start_aes_cbc_enc:
    ; Move to xmm0 the block to be encrypted
    movdqu xmm0, [rdi + rax]

    pxor xmm0, xmm12

    pxor xmm0, xmm1         ; Round 0 (whitening)
    aesenc xmm0, xmm2       ; Round 1
    aesenc xmm0, xmm3       ; Round 2
    aesenc xmm0, xmm4       ; Round 3
    aesenc xmm0, xmm5       ; Round 4
    aesenc xmm0, xmm6       ; Round 5
    aesenc xmm0, xmm7       ; Round 6
    aesenc xmm0, xmm8       ; Round 7
    aesenc xmm0, xmm9       ; Round 8
    aesenc xmm0, xmm10      ; Round 9
    aesenclast xmm0, xmm11  ; Round 10

    ; End -> write the result in the r8 pointer
    movdqu [r8 + rax], xmm0
    movdqu xmm12, xmm0

    add rax, 16
    loop start_aes_cbc_enc

    ret

; void aes_decrypt(uint8_t* block, uint8_t* key, uint8_t* result);
aes_128_cbc_decrypt:
    ; Decrypt

    ; Keys are returned in the registers xmm1-xmm11
    call aes_calculate_keys

    ; Apply inverse MixColumns to all the keys
    ; scheduled for encryption, except first and last ones
    aesimc xmm2, xmm2
    aesimc xmm3, xmm3
    aesimc xmm4, xmm4
    aesimc xmm5, xmm5
    aesimc xmm6, xmm6
    aesimc xmm7, xmm7
    aesimc xmm8, xmm8
    aesimc xmm9, xmm9
    aesimc xmm10, xmm10

    xor rax, rax
    pxor xmm12, xmm12
start_aes_cbc_dec:
    ; Move to xmm0 the block to be decrypted
    movdqu xmm0, [rdi + rax]

    movdqu xmm13, xmm0 ; Save the initial block

    ; Reverse key order, since it is decryption
    pxor xmm0, xmm11        ; Round 0 (whitening)
    aesdec xmm0, xmm10      ; Round 1
    aesdec xmm0, xmm9       ; Round 2
    aesdec xmm0, xmm8       ; Round 3
    aesdec xmm0, xmm7       ; Round 4
    aesdec xmm0, xmm6       ; Round 5
    aesdec xmm0, xmm5       ; Round 6
    aesdec xmm0, xmm4       ; Round 7
    aesdec xmm0, xmm3       ; Round 8
    aesdec xmm0, xmm2       ; Round 9
    aesdeclast xmm0, xmm1   ; Round 10

    pxor xmm0, xmm12 ; xor plain text with IV
    movdqu xmm12, xmm13 ; next IV is the starting cipher text

    ; End -> write the result in the r8 pointer
    movdqu [r8 + rax], xmm0

    add rax, 16
    loop start_aes_cbc_dec

    ret