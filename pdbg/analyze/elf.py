import capstone

from io import BytesIO
from typing import Container, Union
from pathlib import Path
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, SUNWSyminfoTableSection
from elftools.common.exceptions import ELFError

@dataclass
class ELFSymbol:
    name:   str
    offset: int
    _entry: Container

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
        self.text = bytearray()
        self.text_offset = 0
        self.text_size = 0

        self.populate_data()

    def populate_data(self):
        for section in self.elf_file.iter_sections():
            if type(section) == SUNWSyminfoTableSection or type(section) == SymbolTableSection:
                self.populate_symbols(section)
            elif section.name == ".text":
                self.populate_text(section.data(), section["sh_addr"], section["sh_size"])

    def populate_text(self, data: bytes, offset: int, size: int):
        self.text = bytearray(data)
        self.text_offset = offset
        self.text_size = size

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
    def find_function_end(self, offset: int):
        if offset < self.text_offset or offset >= self.text_offset + self.text_size:
            raise AnalyzerException(f"Offset {offset} not in bounds: {self.text_offset}..{self.text_offset + self.text_size}")

        binary_offset = offset - self.text_offset

        ctx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for insn in ctx.disasm(self.text[binary_offset:], offset):
            if insn.mnemonic in ["ret", "hlt"]:
                return insn.address
        return -1

class AnalyzerException(Exception): ...
