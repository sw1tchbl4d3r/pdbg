#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "methods/ptrace.c"
#include "methods/util.c"

static PyMethodDef ModuleMethods[] = {
    { "attach",      method_attach,      METH_VARARGS, "attach to pid"                  },
    { "seize",       method_seize,       METH_VARARGS, "attach to pid without trapping" },
    { "detach",      method_detach,      METH_VARARGS, "detach from pid"                },
    { "cont",        method_cont,        METH_VARARGS, "continue pid"                   },
    { "interrupt",   method_interrupt,   METH_VARARGS, "stop pid"                       },
    { "singlestep",  method_singlestep,  METH_VARARGS, "single instruction step"        },
    { "getregs",     method_getregs,     METH_VARARGS, "get registers"                  },
    { "setregs",     method_setregs,     METH_VARARGS, "set registers"                  },
    { "peek",        method_peek,        METH_VARARGS, "read memory"                    },
    { "poke",        method_poke,        METH_VARARGS, "write memory"                   },

    { "read_bytes",  method_read_bytes,  METH_VARARGS, "helper to read bytes"           },
    { "write_bytes", method_write_bytes, METH_VARARGS, "helper to write bytes"          },

    { "waitpid",     method_waitpid,     METH_VARARGS, "wait for child"                 },

    { NULL,          NULL,               0,            NULL                             },
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "ipdbg",
    "pdbg internal c functions",
    -1,
    ModuleMethods
};

PyMODINIT_FUNC PyInit_ipdbg(void) {
    return PyModule_Create(&module);
}
