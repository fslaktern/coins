    %define PAGE_SIZE       4096
    %define MAP_LEN         0x100000

    %define PROT_RW         0x3
    %define PROT_RX         0x5

    %define MAP_PRIVATE     0x02
    %define MAP_ANONYMOUS   0x20
    %define MAP_FIXED_NOREPLACE 0x100000

    %define STDIN           0
    %define STDOUT          1

    %define SYS_READ        0
    %define SYS_WRITE       1
    %define SYS_MMAP        9
    %define SYS_MPROTECT    10
    %define SYS_EXIT        60

    %define INPUT_MAX       248     ; worst case: 31 gadgets = 248 bytes

    extern _end


    section .bss
    mmap_base resq 1
    win_addr  resq 1


    section .data

    p_base db "starting balance:", 9, "0x"
    p_base_len equ $ - p_base

    p_mid db 10, "flag price:", 9, 9, "[your_balance] + 0x"
    p_mid_len equ $ - p_mid

    p_q db 10, 10,
    p_q_len equ $ - p_q

    p_end db "> "
    p_end_len equ $ - p_end


win:
    mov     rbx, 0x0067616c662f
    push    rbx

    mov     rdi, rsp
    xor     esi, esi
    mov     eax, 2
    syscall

    mov     esi, eax
    push    1
    pop     rdi
    xor     edx, edx
    mov     r10b, 37
    mov     eax, 40
    syscall

    win_len equ $ - win

    q1 db "worth it?", 10
    q1_len equ $ - q1

    q2 db "all in?", 10
    q2_len equ $ - q2

    q3 db "double or nothing?", 10
    q3_len equ $ - q3

    q4 db "in for a penny?", 10
    q4_len equ $ - q4

    q5 db "feeling rich?", 10
    q5_len equ $ - q5

    q6 db "break the bank?", 10
    q6_len equ $ - q6

    q7 db "got any cash?", 10
    q7_len equ $ - q7

    q8 db "go big?", 10
    q8_len equ $ - q8

    q9 db "bet?", 10
    q9_len equ $ - q9

    q10 db "call?", 10
    q10_len equ $ - q10

    q11 db "worth a shot?", 10
    q11_len equ $ - q11

    q12 db "make it rain?", 10
    q12_len equ $ - q12

    q13 db "double down?", 10
    q13_len equ $ - q13

    ;; question table
qt:
    dq q1 - qt, q1_len, q2 - qt, q2_len
    dq q3 - qt, q3_len, q4 - qt, q4_len
    dq q5 - qt, q5_len, q6 - qt, q6_len
    dq q7 - qt, q7_len, q8 - qt, q8_len
    dq q9 - qt, q9_len, q10 - qt, q10_len
    dq q11 - qt, q11_len, q12 - qt, q12_len
    dq q13 - qt, q13_len


    section .text
    global _start

_start:
    ;; Start with carry flag = 0 for the ADC gadgets
    clc


    ;; Generate a random offset between the start of mmapped region and start of shellcode/win
    ;; gr = get random
gr:
    rdrand  rax
    jnc     gr

    ;; Worst case can still cause win to end up overflowing 1 MiB, but very rare
    ;; Will probably crash due to non-executable memory outside 1 MiB chunk
    and     eax, 0xfffff        ; reduce to (1 MiB - 1)

    mov     rbx, MAP_LEN - win_len
    cmp     rax, rbx
    ja      gr

    mov     r12, rax


    ;; put mapping after the end of bss

    lea     rdi, [rel _end]
    add     rdi, PAGE_SIZE - 1
    and     rdi, -PAGE_SIZE

    mov     r13, rdi


    ;; mmap 1MiB as RW

    mov     eax, SYS_MMAP
    mov     rsi, MAP_LEN
    mov     edx, PROT_RW
    mov     r10d, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE
    mov     r8, -1
    xor     r9d, r9d
    syscall

    test    rax, rax
    js      e

    cmp     rax, r13
    jne     e

    mov     [rel mmap_base], rax


    ;; Copy win payload to mmap_base + r12

    add     rax, r12
    mov     [rel win_addr], rax

    mov     rdi, rax
    lea     rsi, [rel win]
    mov     rcx, win_len
    rep     movsb


    ;; Make 1 MiB chunk executable but not writable

    mov     rdi, [rel mmap_base]
    mov     rsi, MAP_LEN
    mov     edx, PROT_RX
    mov     eax, SYS_MPROTECT
    syscall

    test    rax, rax
    js      e


    ;; Print base and win's offset from base

    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [rel p_base]
    mov     edx, p_base_len
    syscall

    lea     rdi, [rel _start]
    ;; First page (0x0000) is considered `base`. It contains ELF headers
    ;; Second page (0x1000) contains start of .text and _start. _start starts at 0x1000.
    sub     rdi, 0x1000
    call    px

    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [rel p_mid]
    mov     edx, p_mid_len
    syscall

    mov     rdi, [rel win_addr]
    lea     rbx, [rel _start]
    sub     rbx, 0x1000              ; base
    sub     rdi, rbx                 ; win_off = win_addr - base
    call    px

    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [rel p_q]
    mov     edx, p_q_len
    syscall

    ;; Variation is nice. pq = pick question
pq:
    rdrand  rax
    jnc     pq
    and     eax, 15
    cmp     eax, 13
    jae     pq

    lea     rsi, [rel qt]
    lea     rdi, [rsi + rax*8]
    lea     rdi, [rdi + rax*8]         ; entry = table + idx*16
    mov     rcx, [rdi]                 ; qN - qt (constant)
    add     rcx, rsi                   ; qN runtime address
    mov     rdx, [rdi + 8]             ; length
    mov     rsi, rcx
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    syscall

    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [rel p_end]
    mov     edx, p_end_len
    syscall

    ;; Cleanup registers before input

    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    ;; i = input
i:
    sub     rsp, INPUT_MAX

    mov     eax, SYS_READ
    xor     edi, edi
    mov     rsi, rsp
    mov     edx, INPUT_MAX
    syscall

    test    rax, rax
    jle     e

    ;; whitelist filter: every 8-byte entry must be one of the 33 gadgets
    mov     r11, rax
    cmp     r11, 8
    jb      e
    mov     rdi, rsi
    lea     rdx, [rdi + r11 - 8]

    ;; cg = check gadget
cg:
    cmp     rdi, rdx
    ja      cd
    mov     rcx, [rdi]
    lea     rax, [rel croeseid]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel daric]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel siglos]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel karshapana]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel tetradrachm]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel stater]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel obol]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel lepton]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel aureus]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel solidus]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel denarius]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel antoninianus]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel sestertius]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel florin]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel sequin]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel tremissis]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel dinar]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel dirham]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel scudo]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel thaler]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel real]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel piloncitos]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel koban]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel loonie]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel krugerrand]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel sovereign]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel drachma]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel penny]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel nickel]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel dime]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel quarter]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel cent]
    cmp     rcx, rax
    je      cn
    lea     rax, [rel shilling]
    cmp     rcx, rax
    je      cn
    jmp     e

    ;; cn = check next
cn:
    add     rdi, 8
    jmp     cg

    ;; cd = check done
cd:
    lea     rax, [rel shilling]       ; chain must terminate in jmp rax
    cmp     [rdi - 8], rax
    jne     e
    stc                             ; set carry flag

glhf:
    ;; Since carry flag is set, the first `adc` gadget will be +1, while the rest will stay the same
    ret


    ;; Convert int to hex string. px = print hex
px:
    push    rbx
    sub     rsp, 32
    mov     rbx, rdi
    lea     rsi, [rsp]
    xor     ecx, ecx

    ;; hex loop
    .xl:
    mov     rax, rbx
    shr     rax, 60
    and     eax, 0xf
    cmp     al, 10
    jb      .d
    add     al, 'a' - 10
    jmp     .s

    ;; convert int digit to str digit
    .d:
    add     al, '0'

    ;; store hex byte
    .s:
    mov     [rsi+rcx], al
    shl     rbx, 4
    inc     rcx
    cmp     rcx, 16
    jb      .xl

    ;; trim leading zeroes
    xor     ecx, ecx
    .t:
    cmp     byte [rsi+rcx], '0'
    jne     .w
    inc     ecx
    cmp     ecx, 15
    jb      .t
    .w:
    add     rsi, rcx
    mov     edx, 16
    sub     edx, ecx
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    syscall
    add     rsp, 32
    pop     rbx
    ret


    ;; e = error
e:
    mov     eax, SYS_EXIT
    mov     edi, 1
    syscall


    ;; ROP gadgets

croeseid:
    adc     r8, 1
    ret

daric:
    adc     r9, 2
    ret

siglos:
    adc     r10, 4
    ret

karshapana:
    adc     r11, 8
    ret

tetradrachm:
    adc     r12, 16
    ret

stater:
    adc     r13, 32
    ret

obol:
    adc     r14, 64
    ret

lepton:
    adc     r15, 128
    ret

aureus:
    adc     r8, 256
    ret

solidus:
    adc     r9, 512
    ret

denarius:
    adc     r10, 1024
    ret

antoninianus:
    adc     r11, 2048
    ret

sestertius:
    adc     r12, 4096
    ret

florin:
    adc     r13, 8192
    ret

sequin:
    adc     r14, 16384
    ret

tremissis:
    adc     r15, 32768
    ret

dinar:
    adc     r8, 65536
    ret
dirham:
    adc     r8, 131072
    ret

scudo:
    adc     r8, 262144
    ret

thaler:
    adc     r8, 524288
    ret

real:
    adc     r9, 131072
    ret

piloncitos:
    adc     r10, 262144
    ret

koban:
    adc     r11, 524288
    ret

loonie:
    sub     r8, r9
    ret

krugerrand:
    sub     r8, r10
    ret

sovereign:
    sub     r8, r11
    ret

drachma:
    sub     r8, r12
    ret

penny:
    sub     r8, r13
    ret

nickel:
    sub     r8, r14
    ret

dime:
    sub     r8, r15
    ret

quarter:
    lea     rax, [rel quarter + 1337]
    ret

cent:
    add     rax, r8
    ret

shilling:
    jmp     rax
