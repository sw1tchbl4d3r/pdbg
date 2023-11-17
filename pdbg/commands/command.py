from __future__ import annotations

import inspect
from typing import Any, Callable

from pdbg.ptrace.tracee import LinuxTracee as Tracee
from pdbg.commands.logging import log_error

class PDBGCommandError(Exception): ...

class CommandImplementationError(PDBGCommandError): ...
class CommandArgumentError(PDBGCommandError): ...
class CommandError(PDBGCommandError): ...

def parse_int(given: str):
    if given.isdigit():
        return int(given)

    if given.startswith("0x"):
        if all([c in set("0123456789abcdefABCDEF") for c in given[2:]]):
            return int(given, 16)

    if given.startswith("0o"):
        if all([c in set("01234567") for c in given[2:]]):
            return int(given, 8)

    if given.startswith("0b"):
        if all([c in set("01") for c in given[2:]]):
            return int(given, 2)

    raise CommandArgumentError(f"Argument '{given}' is not a valid integer.")

def parse_bytes(given: str):
    return given.encode("latin1").decode("unicode_escape").encode("latin1")

def remove_quotes(given: str):
    for quote_char in ['"', "'"]:
        if given[0] == given[-1] == quote_char:
            return given[1:-1]
    return given

class GlobalState:
    storage: dict = {}

    commands: list[Command] = []

    tracee: Tracee
    tracee_attached = False

    _callbacks: dict[str, list[Callable[[GlobalState], None]]] = {}

    def get_command(self, name: str):
        for command in self.commands:
            if name in command.names and command.init_success:
                return command
        return None

    def add_callback(self, identifier: str, callback: Callable[[GlobalState], Any]):
        callbacks_for_identifier = self._callbacks.get(identifier, [])
        callbacks_for_identifier.append(callback)
        self._callbacks[identifier] = callbacks_for_identifier

    def invoke_callbacks(self, identifier: str):
        callbacks_for_identifier = self._callbacks.get(identifier, [])
        for callback in callbacks_for_identifier:
            callback(self)

class Command:
    names: list[str] = []
    requires_tracee: bool = False
    help_string: str = "A generic command, if you are seeing this someone didn't set their help_string."

    global_state: GlobalState

    def __init__(self):
        self.init_success = False

        try:
            self.check_syntax()
            self.init_success = True
        except CommandImplementationError as e:
            log_error(f"Could not load command '{type(self).__name__}': {e}")

    def check_syntax(self):
        dict_params = dict(inspect.signature(self.invoke).parameters)

        if len(dict_params) == 0:
            raise CommandImplementationError(f"Last argument of '{type(self).__name__}' is not 'argv0'.")

        last_param = dict_params.popitem()[1]
        if last_param.name != "argv0":
            raise CommandImplementationError(f"Last argument of '{type(self).__name__}' is not 'argv0'.")

        vararg_check = [param.kind == inspect.Parameter.VAR_POSITIONAL for param in dict_params.values()]
        if any(vararg_check) and vararg_check[-1] == False:
            raise CommandImplementationError(f"The command '{type(self).__name__}' takes a vararg '*args', but should be at the last position before 'argv0'")

        annotations = [param.annotation for param in dict_params.values()]
        supported_annotations = [inspect._empty, str, int, list, list[str], list[int], bytes]

        for annotation in annotations:
            if annotation not in supported_annotations:
                raise CommandImplementationError(f"{annotation} is not a supported annotation, in '{self}'.")

    def invoke(self, argv0="cmd"):
        raise CommandImplementationError(f"The command {argv0} / '{self.__name__}' does not implement invoke().")

    def usage(self, argv0):
        params = dict(inspect.signature(self.invoke).parameters)
        params_string = ""

        params.popitem() # pop argv0

        for param in params.values():
            if param.default != inspect._empty:
                params_string += " ["
            else:
                params_string += " <"

            if param.kind == inspect.Parameter.VAR_POSITIONAL:
                params_string += "*"

            params_string += f"{param.name}"
            if param.annotation != inspect._empty:
                params_string += f": {param.annotation.__name__}"
            if param.default != inspect._empty:
                params_string += f"={param.default}"

            if param.default != inspect._empty:
                params_string += "]"
            else:
                params_string += ">"

        return f"Usage: {argv0}{params_string}"

    def check_signature(self, args: list[str]):
        params = dict(inspect.signature(self.invoke).parameters)

        params.popitem() # pop argv0

        annotations = [param.annotation for param in params.values()]
        params_needed = [param for param in params.values() if param.default == param.empty]

        if len(args) < len(params_needed):
            raise CommandArgumentError(f"Arguments given: {len(args)}, needed: {len(params_needed)}.")

        if len(params_needed) > 0:
            has_vararg = params_needed[-1].kind == inspect.Parameter.VAR_POSITIONAL
        else:
            has_vararg = False

        if len(args) > len(params) and not has_vararg:
            raise CommandArgumentError(f"Arguments given: {len(args)}, maximum: {len(params_needed)}.")

        args = [remove_quotes(i) for i in args]

        new_args = []
        for i in range(len(args)):
            given = args[i]
            needed = annotations[min(i, len(annotations) - 1)]

            if needed in [inspect._empty, str]:
                new_args.append(given)
                continue

            if needed == int:
                new_args.append(parse_int(given))
                continue

            if needed in [list, list[str], list[int]]:
                tmp_list = given.split(",")

                if needed == list[int]:
                    new_args.append([parse_int(num) for num in tmp_list])
                    continue

                new_args.append(tmp_list)
                continue

            if needed == bytes:
                new_args.append(parse_bytes(given))
                continue

            assert "unreachable"

        return new_args
