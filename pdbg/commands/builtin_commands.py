from pdbg.tracee import LinuxTracee as Tracee
from pdbg.commands.command import Command, CommandError
from pdbg.commands.logging import log_info

class AttachCommand(Command):
    names = ["attach", "seize"]
    requires_tracee = False
    help_string = "Attaches to a PID and makes it this debuggers tracee."

    def invoke(self, pid: int, argv0="attach"):
        tracee = Tracee(pid)

        if argv0 == "attach":
            if not tracee.attach():
                raise CommandError(f"Could not attach to PID {pid}.")
        elif argv0 == "seize":
            if not tracee.seize():
                raise CommandError(f"Could not seize PID {pid}.")
        self.global_state.tracee = tracee
        log_info("Attached successfully!")

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

    def invoke(self, arg: bytes, argv0="print"):
        log_info(arg.decode())

class QuitCommand(Command):
    names = ["quit", "q"]
    requires_tracee = False
    help_string = "Quits the debugger."

    def invoke(self, argv0="quit"):
        exit(0)

class RegCommand(Command):
    names = ["regs", "getregs", "reg", "getreg"]
    requires_tracee = True
    help_string = "Gets program registers."

    def invoke(self, register: str="", argv0="regs"):
        assert self.global_state.tracee

        if not (registers := self.global_state.tracee.getregs()):
            raise CommandError("Could not get registers.")

        if register:
            if register not in registers.supported_regs:
                raise CommandError(f"Unsupported Register: '{register}'")
            reg: int = getattr(registers, register)
            log_info(f"{register}: {reg} ({hex(reg)})")
            return
        
        for register in registers.supported_regs:
            if register in ["gs_base", "fs_base", "orig_rax"]:
                continue
            reg: int = getattr(registers, register)
            print(f"{register}:\t{hex(reg)} ({reg})")

class SetRegCommand(Command):
    names = ["setreg"]
    requires_tracee = True
    help_string = "Sets program register."

    def invoke(self, register: str, value: int, argv0="setreg"):
        assert self.global_state.tracee

        if not (registers := self.global_state.tracee.getregs()):
            raise CommandError("Could not get registers.")

        if register not in registers.supported_regs:
            raise CommandError(f"Unsupported Register: '{register}'")
        
        setattr(registers, register, value)
        if not self.global_state.tracee.setregs(registers):
            raise CommandError("Could not set register.")
        
        log_info(f"{register}: {value} ({hex(value)})")

class SingleStepCommand(Command):
    names = ["step", "si"]
    requires_tracee = True
    help_string = "Executes a single assembly instruction in the tracee."

    def invoke(self, argv0="step"):
        assert self.global_state.tracee

        if not self.global_state.tracee.singlestep():
            raise CommandError(f"Could not singlestep.")

commands = [AttachCommand(), HelpCommand(), PrintCommand(), QuitCommand(), RegCommand(), SetRegCommand(), SingleStepCommand()]
