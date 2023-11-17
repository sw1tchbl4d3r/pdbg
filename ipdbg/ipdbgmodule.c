#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "methods/globals.h"
#include "methods/ptrace.h"
#include "methods/util.h"

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
    { "unwind",      method_unwind,      METH_VARARGS, "unwind stack frames"            },

    { "waitpid",     method_waitpid,     METH_VARARGS, "wait for child"                 },

    { NULL,          NULL,               0,            NULL                             },
};

void ipdbg_dealloc(void*) {
    Py_XDECREF(IPDBG_Registers);
    Py_XDECREF(IPDBG_UnwoundStackFrame);
}

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "ipdbg",
    "pdbg internal c functions",
    -1,
    ModuleMethods,
    NULL,
    NULL,
    NULL,
    ipdbg_dealloc
};

PyMODINIT_FUNC PyInit_ipdbg(void) {
    PyObject* module = PyModule_Create(&module_def);

    PyObject* datatypes_module_name = PyUnicode_FromString("pdbg.datatypes");
    PyObject* datatypes_module = PyImport_Import(datatypes_module_name);
    Py_DECREF(datatypes_module_name);

    if (!datatypes_module)
        return NULL;

    PyObject* module_dict = PyModule_GetDict(datatypes_module);

    IPDBG_Registers = PyDict_GetItemString(module_dict, "Registers");
    if (!IPDBG_Registers) {
        Py_DECREF(datatypes_module);
        return PyErr_Format(PyExc_NameError, "Could not import pdbg.datatypes.Registers");
    }

    IPDBG_UnwoundStackFrame = PyDict_GetItemString(module_dict, "UnwoundStackFrame");
    if (!IPDBG_UnwoundStackFrame) {
        Py_DECREF(datatypes_module);
        return PyErr_Format(PyExc_NameError, "Could not import pdbg.datatypes.UnwoundStackFrame");
    }

    Py_INCREF(IPDBG_Registers);
    Py_INCREF(IPDBG_UnwoundStackFrame);

    return module;
}
