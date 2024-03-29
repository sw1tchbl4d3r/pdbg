from pdbg.ptrace.datatypes import Registers
from pdbg.ptrace.tracee import LinuxTracee as Tracee
from pdbg.commands.command import Command, CommandError
from pdbg.commands.logging import Colors, log_info

class AttachCommand(Command):
    names = ["attach", "seize"]
    requires_tracee = False
    help_string = "Attaches to a PID and makes it this debuggers tracee."

    def invoke(self, pid: int, argv0="attach"):
        if self.global_state.tracee_attached:
            raise CommandError("Please detach from the current tracee first.")

        tracee = Tracee(pid)

        if argv0 == "attach":
            try:
                tracee.attach()
            except OSError as e:
                raise CommandError(f"Could not attach to PID {pid}: {e}")
        elif argv0 == "seize":
            try:
                tracee.seize()
            except OSError as e:
                raise CommandError(f"Could not seize PID {pid}: {e}")
        self.global_state.tracee = tracee
        self.global_state.tracee_attached = True

        log_info("Attached successfully!")

        self.global_state.invoke_callbacks("on_attach")
        self.global_state.invoke_callbacks("on_step")

class BacktraceCommand(Command):
    names = ["backtrace", "bt"]
    requires_tracee = True
    help_string = "Unwinds the stack trace of the tracee and prints it."

    def invoke(self, argv0="backtrace"):
        mmaps = self.global_state.tracee.get_mmapings()
        stacktrace = self.global_state.tracee.unwind()
        for frame in stacktrace:
            offset = frame.offset
            symbol = "??" if not frame.symbol else frame.symbol

            # NOTE: If some symbols are missing from the binary, libunwind may miscategorize
            #       some symbols. Lets say `foo` goes from 0x0 - 0x10, and `bar` from 0x30 - 0x40,
            #       and everything inbetween does not have a symbol. libunwind would now say that address 0x12
            #       is foo+0x12, even though we just dont have a symbol for it. This approach here should fix that.
            if mmaps:
                mmap = self.global_state.tracee.get_map_containing(frame.rip, mmaps)
                if mmap:
                    analyzer = self.global_state.analyzers.get(mmap.identifier, None)
                    if analyzer:
                        frame_offset_to_base = frame.rip  - analyzer.base_address
                        symbol_fn_offset_to_base = frame_offset_to_base - frame.offset
                        symbol_fn_end_offset = analyzer.find_function_end(symbol_fn_offset_to_base)

                        if symbol_fn_end_offset < frame_offset_to_base:
                            symbol = "??"
                            offset = 0

            print(f"{hex(frame.rip)}: {symbol}+{hex(offset)}")

class ClearCommand(Command):
    names = ["clear", "cls"]
    requires_tracee = False
    help_string = "Clears the screen."

    def invoke(self, argv0="clear"):
        print(Colors.CLEAR)

class DetachCommand(Command):
    names = ["detach"]
    requires_tracee = True
    help_string = "Detaches the current tracee."

    def invoke(self, argv0="detach"):
        self.global_state.tracee.detach()
        self.global_state.tracee_attached = False

        log_info("Detached successfully!")

class HelpCommand(Command):
    names = ["help"]
    requires_tracee = False
    help_string = "Gets help for commands."

    def invoke(self, command: str="", argv0="help"):
        if command:
            cmd = self.global_state.get_command(command)
            if not cmd:
                raise CommandError(f"Command '{command}' not found.")
            print(cmd.help_string)
            log_info(cmd.usage(command))
            return

        for cmd in self.global_state.commands:
            print(f"{cmd.names[0]}:")
            print(f"\t{cmd.help_string}")

class PrintCommand(Command):
    names = ["print"]
    requires_tracee = False
    help_string = "Just prints."

    def invoke(self, *args: bytes, argv0="print"):
        log_info(b" ".join(args).decode())

class QuitCommand(Command):
    names = ["quit", "q"]
    requires_tracee = False
    help_string = "Quits the debugger."

    def invoke(self, argv0="quit"):
        if self.global_state.tracee_attached:
            self.global_state.tracee.detach()
        exit(0)

class RegCommand(Command):
    names = ["regs", "getregs", "reg", "getreg"]
    requires_tracee = True
    help_string = "Gets program registers."

    def invoke(self, register: str="", argv0="regs"):
        if not (registers := self.global_state.tracee.getregs()):
            raise CommandError("Could not get registers.")

        if register:
            if not hasattr(registers, register):
                raise CommandError(f"Unsupported Register: '{register}'")
            reg: int = getattr(registers, register)
            log_info(f"{register}: {reg} ({hex(reg)})")
            return

        # TODO: dont rely on __annotations__
        register_names = list(Registers.__annotations__.keys())
        for register in register_names:
            if register in ["gs_base", "fs_base", "orig_rax"]:
                continue
            reg: int = getattr(registers, register)
            print(f"{register}:\t{hex(reg)} ({reg})")

class SetRegCommand(Command):
    names = ["setreg"]
    requires_tracee = True
    help_string = "Sets program register."

    def invoke(self, register: str, value: int, argv0="setreg"):
        registers = self.global_state.tracee.getregs()
        if not hasattr(registers, register):
            raise CommandError(f"Unsupported Register: '{register}'")

        setattr(registers, register, value)
        self.global_state.tracee.setregs(registers)

        log_info(f"{register}: {value} ({hex(value)})")

class SingleStepCommand(Command):
    names = ["step", "si"]
    requires_tracee = True
    help_string = "Executes a single assembly instruction in the tracee."

    def invoke(self, argv0="step"):
        self.global_state.tracee.singlestep()

        self.global_state.invoke_callbacks("on_step")

commands = [AttachCommand(), ClearCommand(), BacktraceCommand(), DetachCommand(), HelpCommand(), PrintCommand(), QuitCommand(), RegCommand(), SetRegCommand(), SingleStepCommand()]
