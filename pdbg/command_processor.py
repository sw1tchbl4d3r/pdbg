import shlex
import readline

from pdbg.commands.command import *
from pdbg.commands.callbacks import *
from pdbg.commands.logging import log_error, log_info, PROMPT
from pdbg.commands.builtin_commands import commands as builtin_commands

class CommandProcessor:
    def __init__(self):
        self.commands: list[Command] = builtin_commands
        self.global_state = GlobalState()
        self.global_state.commands = self.commands

        for command in self.commands:
            command.global_state = self.global_state

        self.global_state.add_callback("on_attach", on_attach)
        self.global_state.add_callback("on_step", on_step)

        readline.set_auto_history(True)

    def register_command(self, command: Command):
        command.global_state = self.global_state
        self.commands.append(command)

    def start(self):
        while True:
            try:
                cmd = shlex.split(input(PROMPT).strip(), posix=False)
            except KeyboardInterrupt:
                print("^C")
                continue
            except EOFError:
                print("quit")
                cmd = ["quit"]

            if len(cmd) == 0:
                continue

            command = self.global_state.get_command(cmd[0])

            if command == None:
                log_error("Command not found.")
                continue

            if command.requires_tracee and not self.global_state.tracee_attached:
                log_error("This command requires an active tracee.")
                continue

            try:
                args = command.check_signature(cmd[1:])
                command.invoke(*args, argv0=cmd[0])

            except PDBGCommandError as err:
                if isinstance(err, CommandImplementationError):
                    log_error(f"IMPL: {err.args[0]}")
                else:
                    log_error(err.args[0])

                if isinstance(err, CommandArgumentError):
                    log_info(command.usage(cmd[0]))
