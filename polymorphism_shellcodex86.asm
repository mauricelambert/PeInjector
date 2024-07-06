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
    pop eax
    mov edx, eax
    add eax, 0x7
    mov ecx, 0xAA
decrypt:
    mov bl, byte [eax]
    xor bl, cl
    mov byte [eax], bl
    dec eax
    cmp edx, eax
    jle decrypt
    inc eax
    jmp eax
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

;; eb1d5889c2054f5f6f7fc7c1aa0000008a1830cb8818ffc839c27ef440ffe0e8deffffff90909090909090