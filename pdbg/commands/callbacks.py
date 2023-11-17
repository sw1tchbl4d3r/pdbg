from pdbg.commands.command import CommandError, GlobalState

def execute_command(state: GlobalState, name: str, args: list):
    command = state.get_command(name)
    if command == None:
        raise CommandError(f"Command '{name}' not found.")

    if command.requires_tracee and not state.tracee_attached:
        raise CommandError(f"Command '{name}' requires an active tracee.")

    args = command.check_signature(args)
    command.invoke(*args, argv0=name)

def on_attach(state: GlobalState):
    ...

def on_step(state: GlobalState):
    ...
