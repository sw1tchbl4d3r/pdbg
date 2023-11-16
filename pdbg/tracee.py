import signal
from mmap import PAGESIZE
from enum import Enum, IntFlag, auto

import ipdbg # type: ignore

class Permissions(IntFlag):
    N = 0
    R = 1
    W = 2
    X = 4

class StatusType(Enum):
    EXITED = auto()
    SIGNALED = auto()
    STOPPED = auto()
    CONTINUED = auto()
    INVALID = auto()

class MemoryMapping:
    def __init__(self, start: int, end: int, perms: Permissions, identifier: str):
        self.start = start
        self.end = end
        self.size = end - start
        self.perms = perms
        self.identifier = identifier

    @classmethod
    def from_line(cls, line: str):
        while " "*2 in line:
            line = line.replace(" "*2, " ")

        segments = line.split(" ")
        if len(segments) < 6:
            return None

        start = int(segments[0].split("-")[0], 16)
        end = int(segments[0].split("-")[1], 16)
        identifier = segments[5]
        perms_str = segments[1]

        perms: Permissions = Permissions.N
        if "r" in perms_str:
            perms |= Permissions.R
        if "w" in perms_str:
            perms |= Permissions.W
        if "x" in perms_str:
            perms |= Permissions.X

        return cls(start, end, perms, identifier)

class Registers:
    supported_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                      "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
                      "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
                      "gs_base", "fs_base", "orig_rax"]

    # NOTE: for autocompletion
    r15 = 0; r14 = 0; r13 = 0; r12 = 0; rbp = 0; rbx = 0; r11 = 0; r10 = 0
    r9  = 0; r8  = 0; rax = 0; rcx = 0; rdx = 0; rsi = 0; rdi = 0; rip = 0
    cs  = 0; rsp = 0; ss  = 0; ds  = 0; es  = 0; fs  = 0; gs  = 0; orig_rax = 0
    fs_base = 0; gs_base = 0; eflags = 0

    def __init__(self, reg_dict: dict[str, int]):
        assert all([i in reg_dict.keys() for i in self.supported_regs]), "dict does not contain all registers."

        for reg in self.supported_regs:
            setattr(self, reg, reg_dict[reg])

    def to_dict(self):
        ret: dict[str, int] = {}
        for reg in self.supported_regs:
            ret[reg] = getattr(self, reg)
        return ret

def parse_status(status: int):
    if status == 0xffff:
        return StatusType.CONTINUED, 0

    if status & 0xff == 0x7f:
        stop_sig = (status & 0xff00) >> 8
        return StatusType.STOPPED, stop_sig

    term_sig = status & 0x7f
    if term_sig == 0:
        exit_status = (status & 0xff00) >> 8
        return StatusType.EXITED, exit_status

    if (((status & 0x7f) + 1) >> 1) > 0:
        return StatusType.SIGNALED, term_sig

    return StatusType.INVALID, 0

class LinuxTracee:
    def __init__(self, pid: int):
        self.pid = pid
        self.attached = False
        self.seized = False

    def attach(self, seize=False):
        if seize:
            if ipdbg.seize(self.pid) == -1:
                return False
            self.attached = True
            self.seized = True
        else:
            if ipdbg.attach(self.pid) == -1:
                return False
            self.attached = True
            self.wait_for((StatusType.STOPPED, signal.SIGSTOP))

        return True

    def seize(self):
        return self.attach(seize=True)

    def detach(self):
        self.attached = False
        self.seized = False

        if ipdbg.detach(self.pid) == -1:
            return False
        return True

    def cont(self):
        self.assert_attached()

        if ipdbg.cont(self.pid) == -1:
            return False
        return True

    def interrupt(self):
        self.assert_attached(seize=True)

        if ipdbg.interrupt(self.pid) == -1:
            return False
        return self.wait_for_trap()

    def singlestep(self):
        self.assert_attached()

        if ipdbg.singlestep(self.pid) == -1:
            return False
        return self.wait_for_trap()

    def setregs(self, regs: Registers):
        self.assert_attached()

        if ipdbg.setregs(self.pid, regs.to_dict()) == -1:
            return False
        return True

    def getregs(self):
        self.assert_attached()

        regs = ipdbg.getregs(self.pid)
        if regs["err"] == -1:
            return False

        return Registers(regs)

    def peek(self, addr: int):
        self.assert_attached()

        # NOTE: We cannot know if peek succeeded.
        return ipdbg.peek(self.pid, addr)

    def poke(self, addr: int, data: int):
        self.assert_attached()

        if ipdbg.poke(self.pid, addr) == -1:
            return False
        return True

    # NOTE: The 'mind_rbound' parameter in the next two functions should only be used if the area
    #       that is accessed is within 8 bytes of the right boundary of the memory map it is contained in

    def _read_bytes(self, addr: int, length: int, mind_rbound=False):
        self.assert_attached()

        data: bytearray = ipdbg.read_bytes(self.pid, addr, length, mind_rbound)
        return data

    def _write_bytes(self, addr: int, data: bytearray, mind_rbound=False):
        self.assert_attached()

        if ipdbg.write_bytes(self.pid, addr, data, len(data), mind_rbound) == -1:
            return False
        return True

    # TODO: Maybe it's not the wisest thing to open and parse the mappings file on every single memory operation
    def read_bytes(self, addr: int, length: int):
        self.assert_attached()

        end = addr + length

        # NOTE: Don't do all the file stuffs if we aren't even close to a page border
        #       This assumes all pages are pagesize aligned, let's hope this is always the case
        close_to_page_border = PAGESIZE - (end % PAGESIZE) < 8

        if close_to_page_border:
            mmap = self.get_map_containing(addr)
            if not mmap:
                return False

            mind_rbound = mmap.end - end < 8
        else:
            mind_rbound = False

        return self._read_bytes(addr, length, mind_rbound)

    def write_bytes(self, addr: int, data: bytearray):
        self.assert_attached()

        end = addr + len(data)
        close_to_page_border = PAGESIZE - (end % PAGESIZE) < 8

        if close_to_page_border:
            mmap = self.get_map_containing(addr)
            if not mmap:
                return False

            mind_rbound = mmap.end - end < 8
        else:
            mind_rbound = False

        return self._write_bytes(addr, data, mind_rbound)

    def wait(self):
        self.assert_attached()

        ret, istatus = ipdbg.waitpid(self.pid)
        if ret == -1:
            return False

        return parse_status(istatus)

    def wait_for(self, status: tuple[StatusType, int]):
        while True:
            if not (rstatus := self.wait()):
                return False

            if rstatus[0] == status[0] and (rstatus[1] == status[1] or status[1] == -1):
                return True

    def wait_for_trap(self):
        return self.wait_for((StatusType.STOPPED, signal.SIGTRAP))

    def assert_attached(self, seize=False):
        assert self.attached, "not attached."

        if seize:
            assert self.seized, "not seized."

    def get_mmapings(self):
        mappings: list[MemoryMapping] = []

        try:
            with open(f"/proc/{self.pid}/maps", "r") as fd:
                line = fd.readline().strip("\n")
                while line:
                    mapping = MemoryMapping.from_line(line)
                    if mapping:
                        mappings.append(mapping)
                    line = fd.readline().strip("\n")
        except (PermissionError, FileNotFoundError):
            return None

        return mappings

    def get_map_containing(self, addr: int, given_mappings: list[MemoryMapping] = []):
        if len(given_mappings) == 0:
            mappings = self.get_mmapings()
            if not mappings:
                return False
        else:
            mappings = given_mappings

        for mmap in mappings:
            if mmap.start <= addr <= mmap.end:
                return mmap

        return None
