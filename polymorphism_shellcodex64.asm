;    This file implements polymorphism to run obfuscated shellcode.
;    Copyright (C) 2024  Maurice Lambert

;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.

;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.

;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <https://www.gnu.org/licenses/>.

jmp start
init_decrypt:
    pop rax
    mov rdx, rax
    add rax, 0x7
    mov rcx, 0xAA
decrypt:
    mov bl, byte [rax]
    xor bl, cl
    mov byte [rax], bl
    dec rax
    cmp rdx, rax
    jle decrypt
    inc rax
    jmp rax
start:
    call init_decrypt
shellcode:
    nop
    nop
    nop
    nop
    nop
    nop
    nop

;; eb24584889c248054f5f6f7f48c7c1aa0000008a1830cb881848ffc84839c27ef248ffc0ffe0e8d7ffffff90909090909090