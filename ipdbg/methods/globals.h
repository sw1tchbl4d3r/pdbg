#pragma once

#define PY_SSIZE_T_CLEAN
#include <Python.h>

PyObject* IPDBG_Registers = NULL;
PyObject* IPDBG_UnwoundStackFrame = NULL;
