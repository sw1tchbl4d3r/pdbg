from __future__ import annotations

import inspect

from pdbg.tracee import LinuxTracee as Tracee

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
    commands: list[Command]
    tracee: Tracee | None = None

    def get_command(self, name: str):
        for command in self.commands:
            if name in command.names:
                return command
        return None

class Command:
    names: list[str] = []
    requires_tracee: bool = False
    help_string: str = "A generic command, if you are seeing this someone didn't set their help_string."

    global_state: GlobalState

    def invoke(self, argv0="cmd"):
        raise CommandImplementationError(f"The command {argv0} / '{self}' does not implement invoke().")

    def usage(self, argv0):
        params = inspect.signature(self.invoke).parameters
        params_string = ""

        if len(params) == 0 or params[list(params.keys())[-1]].name != "argv0":
            raise CommandImplementationError(f"Last argument of '{self}'.invoke is not 'argv0'.")

        for key in params.keys():
            param = params[key]
            if param.name == "argv0":
                continue
            
            if param.default != inspect._empty:
                params_string += " ["
            else:
                params_string += " <"

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
        dict_params = inspect.signature(self.invoke).parameters
        annotations = [dict_params[i].annotation for i in dict_params.keys()]
        arguments_needed = [dict_params[i] for i in dict_params.keys() if dict_params[i].default == inspect._empty]

        if len(dict_params) == 0 or dict_params[list(dict_params.keys())[-1]].name != "argv0":
            raise CommandImplementationError(f"Last argument of '{self}' is not 'argv0'.")
        
        annotations = annotations[:-1]
        
        if len(args) < len(arguments_needed):
            raise CommandArgumentError(f"Arguments given: {len(args)}, needed: {len(arguments_needed)}.")

        if len(annotations) == 1 and annotations[0] in [inspect._empty, str]:
            return [" ".join(args)]

        if len(args) > len(annotations):
            raise CommandArgumentError(f"Arguments given: {len(args)}, maximum: {len(arguments_needed)}.")

        args = [remove_quotes(i) for i in args]

        new_args = []
        for i in range(len(args)):
            given = args[i]
            needed = annotations[i]

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

            raise CommandImplementationError(f"{needed} is not a supported annotation, in '{self}'.")

        return new_args
