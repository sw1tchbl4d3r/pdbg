from pathlib import Path
from pdbg.analyze.elf import AnalyzerException, ELFAnalyzer

from pdbg.commands.command import CommandError, GlobalState
from pdbg.ptrace.tracee import Permissions

def execute_command(state: GlobalState, name: str, args: list):
    command = state.get_command(name)
    if command == None:
        raise CommandError(f"Command '{name}' not found.")

    if command.requires_tracee and not state.tracee_attached:
        raise CommandError(f"Command '{name}' requires an active tracee.")

    args = command.check_signature(args)
    command.invoke(*args, argv0=name)

def on_attach(state: GlobalState):
    tracee = state.tracee

    mmaps = tracee.get_mmapings()
    if not mmaps:
        return

    for mmap in mmaps:
        ident = mmap.identifier
        if not ident or ident.startswith("["):
            continue

        backing_file = Path(ident)
        if backing_file.is_file():
            analyzer = state.analyzers.get(ident, None)
            if not analyzer:
                try:
                    analyzer = ELFAnalyzer(backing_file)
                    analyzer.set_base(mmap.start)
                except AnalyzerException:
                    continue

            if mmap.perms & Permissions.X:
                if not (data := tracee.read_bytes(mmap.start, mmap.size)):
                    continue

                analyzer.populate_text(data, mmap.start, mmap.size)

            state.analyzers[ident] = analyzer

def on_step(state: GlobalState):
    ...
