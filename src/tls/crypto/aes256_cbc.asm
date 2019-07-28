; Arguments in the x64-86 calling convention for linux (in order):
; RCX -> RDI
; RDX -> RSI
; R8  -> RDX
; R9  -> RCX
; STACK1 -> R8

global aes_calculate_keys
global rawhttps_aes_256_cbc_encrypt
global rawhttps_aes_256_cbc_decrypt

section .text

aes_calculate_keys:
	push rbp
	mov rbp, rsp

    movdqu xmm1, [rsi]
	movdqu xmm3, [rsi + 16]
	
	sub rsp, 208

    aeskeygenassist xmm2, xmm3, 0x1
	call gen_key_a
	movdqu [rsp + 16], xmm1
	
	aeskeygenassist xmm2, xmm1, 0x0
	call gen_key_b
	movdqu [rsp + 32], xmm3
	
	aeskeygenassist xmm2, xmm3, 0x2
	call gen_key_a
	movdqu [rsp + 48], xmm1
	
	aeskeygenassist xmm2, xmm1, 0x0
	call gen_key_b
	movdqu [rsp + 64], xmm3
	
	aeskeygenassist xmm2, xmm3, 0x4
	call gen_key_a
	movdqu [rsp + 80], xmm1

	aeskeygenassist xmm2, xmm1, 0x0
	call gen_key_b
	movdqu [rsp + 96], xmm3
	
	aeskeygenassist xmm2, xmm3, 0x8
	call gen_key_a
	movdqu [rsp + 112], xmm1
	
	aeskeygenassist xmm2, xmm1, 0x0
	call gen_key_b
	movdqu [rsp + 128], xmm3
	
	aeskeygenassist xmm2, xmm3, 0x10
	call gen_key_a
	movdqu [rsp + 144], xmm1
	
	aeskeygenassist xmm2, xmm1, 0x0
	call gen_key_b
	movdqu [rsp + 160], xmm3
	
	aeskeygenassist xmm2, xmm3, 0x20
	call gen_key_a
	movdqu [rsp + 176], xmm1
	
	aeskeygenassist xmm2, xmm1, 0x0
	call gen_key_b
	movdqu [rsp + 192], xmm3
	
	aeskeygenassist xmm2, xmm3, 0x40
	call gen_key_a

	movdqu xmm13, xmm1
	
	movdqu xmm12, [rsp + 192]
	movdqu xmm11, [rsp + 176]
	movdqu xmm10, [rsp + 160]
	movdqu xmm9, [rsp + 144]
	movdqu xmm8, [rsp + 128]
	movdqu xmm7, [rsp + 112]
	movdqu xmm6, [rsp + 96]
	movdqu xmm5, [rsp + 80]
	movdqu xmm4, [rsp + 64]
	movdqu xmm3, [rsp + 48]
	movdqu xmm2, [rsp + 32]
	movdqu xmm1, [rsp + 16]
	
	mov	rsp, rbp
	pop rbp
	ret
	
gen_key_a:
    pshufd xmm2, xmm2, 0xff
    
    movdqa xmm4, xmm1
    pslldq xmm4, 0x4
    pxor xmm1, xmm4
    pslldq xmm4, 0x4
    pxor xmm1, xmm4
    pslldq xmm4, 0x4
    pxor xmm1, xmm4
    pxor xmm1, xmm2
	ret

    ; save result on the stack
    sub rsp, 16
    movdqu [rsp], xmm1

gen_key_b:
    pshufd xmm2, xmm2, 0xaa
    movdqa xmm4, xmm3
    pslldq xmm4, 0x4
    pxor xmm3, xmm4
    pslldq xmm4, 0x4
    pxor xmm3, xmm4
    pslldq xmm4, 0x4
    pxor xmm3, xmm4
    pxor xmm3, xmm2
	ret


; keys are given in the registers xmm1-xmm13
rawhttps_aes_256_cbc_encrypt:
    ; Encrypt
	mov r11, rcx
	mov ecx, r8d
	
    ; Keys are returned in the registers xmm1-xmm11
    call aes_calculate_keys
	
	movdqu xmm14, [rsi] ; First 16 bytes of the key
	movdqu xmm15, [rdx]	; IV
	
	xor rax, rax
start_aes_enc:
    ; Move to xmm0 the block to be encrypted
    movdqu xmm0, [rdi + rax]
	
	pxor xmm0, xmm15
	movdqu xmm15, [rsi + 16] ; Last 16 bytes of the key

    pxor   xmm0, xmm14      ; Round 0 (whitening)
    aesenc xmm0, xmm15      ; Round 1
	
    aesenc xmm0, xmm1       ; Round 2
    aesenc xmm0, xmm2       ; Round 3
    aesenc xmm0, xmm3       ; Round 4
    aesenc xmm0, xmm4       ; Round 5
    aesenc xmm0, xmm5       ; Round 6
    aesenc xmm0, xmm6       ; Round 7
    aesenc xmm0, xmm7       ; Round 8
    aesenc xmm0, xmm8       ; Round 9
	aesenc xmm0, xmm9      ; Round 10
	aesenc xmm0, xmm10      ; Round 11
	aesenc xmm0, xmm11      ; Round 11
	aesenc xmm0, xmm12      ; Round 11
    aesenclast xmm0, xmm13  ; Round 12

    ; End -> write the result in the r8 pointer
    movdqu [r11 + rax], xmm0
	
	movdqu xmm15, xmm0

    add rax, 16
    loop start_aes_enc	
    ret

rawhttps_aes_256_cbc_decrypt:

    ; Decrypt
	mov r11, rcx
	
	; prolog
	push rbp
	mov rbp, rsp
	sub rsp, 32 ; allocate memory for iv which will be on [rsp] and block which will be on [rsp + 16]
	movdqu xmm0, [rdx]
	movdqu [rsp], xmm0 ; save iv

    ; Keys are returned in the registers xmm1-xmm13
    call aes_calculate_keys
	; xmm1 to xmm13 are allocated to the keys

    ; Apply inverse MixColumns to all the keys
    ; scheduled for encryption, except first and last ones
	movdqu xmm14, [rsi + 16]	; Last 16 bytes of the key
	aesimc xmm14, xmm14

	aesimc xmm1, xmm1
    aesimc xmm2, xmm2
    aesimc xmm3, xmm3
    aesimc xmm4, xmm4
    aesimc xmm5, xmm5
    aesimc xmm6, xmm6
    aesimc xmm7, xmm7
    aesimc xmm8, xmm8
    aesimc xmm9, xmm9
    aesimc xmm10, xmm10
	aesimc xmm11, xmm11
	aesimc xmm12, xmm12

    xor rax, rax
start_aes_dec:
    ; Move to xmm0 the block to be decrypted
    movdqu xmm0, [rdi + rax]
	
	movdqu [rsp + 16], xmm0 ; Save the initial block

	movdqu xmm15, [rsi] 		; First 16 bytes of the key
		
    ; Reverse key order, since it is decryption
    pxor xmm0, xmm13        ; Round 0 (whitening)
    
    aesdec xmm0, xmm12       ; Round 1
    aesdec xmm0, xmm11       ; Round 2
    aesdec xmm0, xmm10       ; Round 3
    aesdec xmm0, xmm9        ; Round 4
    aesdec xmm0, xmm8        ; Round 5
    aesdec xmm0, xmm7        ; Round 6
    aesdec xmm0, xmm6        ; Round 7
    aesdec xmm0, xmm5        ; Round 8
    aesdec xmm0, xmm4        ; Round 9
	aesdec xmm0, xmm3        ; Round 10
	aesdec xmm0, xmm2        ; Round 11
	aesdec xmm0, xmm1        ; Round 12
	aesdec xmm0, xmm14       ; Round 13
    aesdeclast xmm0, xmm15   ; Round 14
	
	movdqu xmm15, [rsp] 		; last iv
	pxor xmm0, xmm15   			; xor plain text with IV
    movdqu xmm15, [rsp + 16] 	; next IV is the starting cipher text
	movdqu [rsp], xmm15
	
	; End -> write the result
    movdqu [r11 + rax], xmm0
	
    add rax, 16
	dec r8d
	cmp r8d, 0
	jne start_aes_dec

	; epilog
	mov	rsp, rbp
	pop rbp
	
    ret