# pdbg

WIP process debugger for linux, written in Python and C.

## Usage
```sh
$ pip install -r requirements.txt
$ make
$ ./main.py
dbg> help
```

Currently it can attach to/seize processes, get and set registers, and singlestep.
Backend functions for memory read/write are implemented and are a WIP.

The main focus lies on extendability. Adding a new command is as easy as leaving a py file with a command that inherits from the `Command` class.

Let's take the simple `print` command.

```python
class PrintCommand(Command):
    names = ["print"]
    requires_tracee = False
    help_string = "Just prints."

    def invoke(self, *args: bytes, argv0="print"):
        log_info(b" ".join(args).decode())
```

This class already tells the debugger that this is a command with the name `print`, which does not require to be attached to a tracee.

The function signature is taken from python, here a function which takes a variable amount of bytes to print.

The help string is printed when `help print` or `help` is invoked, and usage information is automatically generated.

## //TODO:

- [x] Debugger interface
- [x] Process attaching 
- [x] Register manipulation
- [x] Backtrace unwinding
- [ ] Memory manipulation
- [ ] Floating point registers
- [ ] `capstone` disassembler integration
