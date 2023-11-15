#include <sys/types.h>
#include <sys/wait.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject* method_waitpid(PyObject* self, PyObject* args) {
    pid_t pid, ret;
    int status;

    if(!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    ret = waitpid(pid, &status, 0);
    PyObject* py_ret = PyTuple_New(2);
    PyTuple_SetItem(py_ret, 0, PyLong_FromLong(ret));
    PyTuple_SetItem(py_ret, 1, PyLong_FromLong(status));

    return py_ret;
}
