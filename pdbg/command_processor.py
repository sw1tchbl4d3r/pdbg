import shlex
import readline

from pdbg.commands.command import *
from pdbg.commands.logging import log_error, log_info, PROMPT
from pdbg.commands.builtin_commands import commands as builtin_commands

class CommandProcessor:
    def __init__(self):
        self.commands: list[Command] = builtin_commands
        self.global_state = GlobalState()
        self.global_state.tracee = None
        
        self.global_state.commands = self.commands

        for command in self.commands:
            command.global_state = self.global_state

    def register_command(self, command: Command):
        command.global_state = self.global_state
        self.commands.append(command)

    def start(self):
        while True:
            cmd = shlex.split(input(PROMPT).strip(), posix=False)

            if len(cmd) == 0:
                continue

            command = self.global_state.get_command(cmd[0])
            
            if command == None:
                log_error("Command not found.")
                continue

            if command.requires_tracee and self.global_state.tracee == None:
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
