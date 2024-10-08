; ----------------------------------------------------------------------------------------
;     nasm -felf64 hello.asm
; ----------------------------------------------------------------------------------------

%ifdef __APPLE__
global _random_64bit_integer
global _random_integer
global _clock_counter
global _random_s64
global _is_pow2

_random_64bit_integer: jmp random_64bit_integer
_random_integer: jmp random_integer
_clock_counter: jmp clock_counter
_random_s64: jmp random_s64
_is_pow2: jmp is_pow2
%else
global random_64bit_integer
global random_integer
global clock_counter
global random_s64
global is_pow2
%endif


section .text
random_64bit_integer:
%ifdef __APPLE__
    ; rdseed is not available on M2, not even when running amd64 code.
    ; For now we will simply return 0, this obviously need to be implemented
    mov rax, 0
%else
    rdseed rax
%endif
    ret

random_s64:
random_integer:
%ifdef __APPLE__
    ; rdseed is not available on M2, not even when running amd64 code.
    ; For now we will simply consider 0, this obviously need to be implemented
    mov rax, 0
%else
    rdseed rax      ; R
%endif
    ;rdrand rax
    xor rdx, rdx
    sub rsi, rdi    ; max = max - min
    div rsi         ; R % max
    mov rax, rdx    ; modulo
    add rax, rdi    ; min + (R % max)
    ret

clock_counter:
    xor rax, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret

is_pow2:
    blsr rax, rdi
    ret