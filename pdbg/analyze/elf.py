import capstone

from io import BytesIO
from typing import Container, Optional, Union
from pathlib import Path
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, SUNWSyminfoTableSection
from elftools.common.exceptions import ELFError

# NOTE: By default, capstone is so very nice to offer you a fake generator.
#       Sure, it yields an instruction on every next(), but before it starts yielding
#       it has already disassembled the entire code block you supplied.
#       This is quite bad performance wise if you expect to stop disassembly
#       way before the actual end of the block.

def capstone_fast(code: memoryview, offset: int, count: Optional[int]=None):
    ctx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    internal_offset = 0
    while count is None or count > 0:
        insn = next(ctx.disasm_lite(code[internal_offset:], offset + internal_offset, 1))
        internal_offset += insn[1]
        yield insn

        if count:
            count -= 1

@dataclass
class ELFSymbol:
    name:   str
    offset: int
    _entry: Container

@dataclass
class TextSegment:
    text: bytearray
    offset: int
    size: int
    offset_end: int

class ELFAnalyzer:
    def __init__(self, filepath: Union[Path, str]):
        self.filepath = Path(filepath)
        if not self.filepath.is_file():
            raise AnalyzerException(f"'{self.filepath}' is not a file.")

        self.binary_data = bytearray(self.filepath.read_bytes())

        try:
            self.elf_file = ELFFile(BytesIO(self.binary_data))
        except ELFError:
            raise AnalyzerException(f"'{self.filepath}' is not a valid ELF file.")

        self.symbols: dict[str, ELFSymbol] = {}
        self.text_segments: list[TextSegment] = []

        self.base_address = 0

        self.populate_data()

    def set_base(self, base_address: int):
        self.base_address = base_address

    def populate_data(self):
        for section in self.elf_file.iter_sections():
            if type(section) == SUNWSyminfoTableSection or type(section) == SymbolTableSection:
                self.populate_symbols(section)
            elif section.name == ".text":
                self.populate_text(section.data(), section["sh_addr"], section["sh_size"])

    def populate_text(self, data: bytes, offset: int, size: int):
        # NOTE: we copy the list so we don't modify it mid-loop
        for segment in self.text_segments[:]:
            if segment.offset == offset:
                self.text_segments.remove(segment)

        segment = TextSegment(bytearray(data), offset, size, offset + size)
        self.text_segments.append(segment)

    def populate_symbols(self, section: Union[SUNWSyminfoTableSection, SymbolTableSection]):
        for symbol in section.iter_symbols():
            if symbol['st_info']['type'] == 'STT_FUNC':
                finalized_symbol = ELFSymbol(symbol.name, symbol["st_value"], symbol.entry)

                existing_symbol = self.symbols.get(symbol.name, None)
                if existing_symbol != None:
                    if existing_symbol.offset != 0:
                        continue

                self.symbols[symbol.name] = finalized_symbol

    # TODO: this approach is a bit naive, since a function could in theory return early,
    #       or jump into another segment where the RET would take place.
    def find_function_end(self, offset: int) -> int:
        for segment in self.text_segments:
            if offset >= segment.offset and offset < segment.offset_end:
                text_offset = offset - segment.offset

                # NOTE: we keep track of jump targets to end the function if a jump jumps outside of a function unconditionally.
                jmp_targets: list[tuple[int, int]] = []
                for (address, _size, mnemonic, op_str) in capstone_fast(memoryview(segment.text)[text_offset:], offset):
                    if mnemonic == "jmp":
                        # TODO: int(op_str, 16) ???
                        jmp_targets.append((address, int(op_str, 16)))

                    if mnemonic in ["ret", "hlt"]:
                        for location, target in jmp_targets:
                            if target > address or target < offset:
                                return location
                        return address
                return -1
        raise AnalyzerException(f"Offset {offset} not in any registered text segment of file '{self.filepath}'")

class AnalyzerException(Exception): ...
