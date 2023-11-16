#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#define ENMUMERATE_REGISTERS(O)          \
    O(r15); O(r14); O(r13); O(r12);      \
    O(rbp); O(rbx); O(r11); O(r10);      \
    O(r9);  O(r8);  O(rax); O(rcx);      \
    O(rdx); O(rsi); O(rdi); O(rip);      \
    O(cs);  O(rsp); O(ss);  O(ds);       \
    O(es);  O(fs);  O(gs);  O(orig_rax); \
    O(fs_base); O(gs_base); O(eflags);   \

// https://docs.python.org/3/c-api/arg.html

PyObject* ptrace_command(PyObject* self, PyObject* args, enum __ptrace_request command) {
    pid_t pid;

    if(!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    if (ptrace(command, pid, NULL, NULL) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    Py_RETURN_NONE;
}

PyObject* method_attach(PyObject* self, PyObject* args) { return ptrace_command(self, args, PTRACE_ATTACH); }
PyObject* method_seize(PyObject* self, PyObject* args) { return ptrace_command(self, args, PTRACE_SEIZE); }
PyObject* method_detach(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_DETACH); }
PyObject* method_cont(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_CONT); }
PyObject* method_interrupt(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_INTERRUPT); }
PyObject* method_singlestep(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_SINGLESTEP); }

#define GET_REGISTER(reg) PyDict_SetItem(dict, PyUnicode_FromString(#reg), PyLong_FromUnsignedLong(regs.reg))
PyObject* method_getregs(PyObject* self, PyObject* args) {
    pid_t pid;
    struct user_regs_struct regs;

    if(!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    PyObject* dict = PyDict_New();
    ENMUMERATE_REGISTERS(GET_REGISTER);

    return dict;
}

#define SET_REGISTER(reg) regs.reg = PyLong_AsUnsignedLong(PyDict_GetItem(dict, PyUnicode_FromString(#reg)))
PyObject* method_setregs(PyObject* self, PyObject* args) {
    pid_t pid;
    PyObject* dict;
    struct user_regs_struct regs;

    if(!PyArg_ParseTuple(args, "iO!", &pid, &PyDict_Type, &dict))
        return NULL;

    ENMUMERATE_REGISTERS(SET_REGISTER);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    Py_RETURN_NONE;
}

PyObject* method_peek(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;

    if(!PyArg_ParseTuple(args, "ik", &pid, &addr))
        return NULL;

    // NOTE: set errno to 0 to check it later, as PEEKTEXT cannot return error values.
    errno = 0;
    uint64_t result = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

    if (errno != 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    return PyLong_FromUnsignedLong(result);
}

PyObject* method_poke(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;
    uint64_t data;

    if(!PyArg_ParseTuple(args, "ikk", &pid, &addr, &data))
        return NULL;

    if (ptrace(PTRACE_POKETEXT, pid, addr, data) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    Py_RETURN_NONE;
}

// NOTE: These methods have to be a bit finnicky because PTRACE_POKE and PTRACE_PEEK 
//       only support reading/writing full uint64_t values.

PyObject* method_read_bytes(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;
    size_t length;
    uint32_t mind_rbound;

    if (!PyArg_ParseTuple(args, "ikkp", &pid, &addr, &length, &mind_rbound))
        return NULL;

    uint64_t data;

    char* final = malloc(length+1);
    if (!final)
        return PyErr_NoMemory();

    char* final_ptr = final;
    for (size_t i = 0; i < length / sizeof(uint64_t); i++) {
        errno = 0;
        data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

        if (errno != 0)
            return PyErr_SetFromErrno(PyExc_OSError);

        memcpy(final_ptr, (char*)(&data), sizeof(uint64_t));
        addr += sizeof(uint64_t);
        final_ptr += sizeof(uint64_t);
    }

    int partial_len = length % sizeof(uint64_t);
    if (mind_rbound)
        addr = addr - (sizeof(uint64_t) - partial_len);

    errno = 0;
    data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

    if (errno != 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    char* ptr;
    if (mind_rbound)
        ptr = (char*)(&data) + (sizeof(uint64_t) - partial_len);
    else
        ptr = (char*)(&data);

    memcpy(final_ptr, ptr, partial_len);

    PyObject* final_bytes = PyByteArray_FromStringAndSize(final, length);
    free(final);

    return final_bytes;
}

PyObject* method_write_bytes(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;
    size_t length;
    PyObject* data;
    uint32_t mind_rbound;

    if (!PyArg_ParseTuple(args, "ikO!kp", &pid, &addr, &PyByteArray_Type, &data, &length, &mind_rbound))
        return NULL;

    char* c_data = PyByteArray_AsString(data);

    for (size_t i = 0; i < length / sizeof(uint64_t); i++) {
        if (ptrace(PTRACE_POKETEXT, pid, addr, *((uint64_t*)c_data)) < 0)
            return PyErr_SetFromErrno(PyExc_OSError);

        c_data += sizeof(uint64_t);
        addr += sizeof(uint64_t);
    }

    int partial_len = length % sizeof(uint64_t);
    if (mind_rbound)
        addr = addr - (sizeof(uint64_t) - partial_len);

    errno = 0;
    uint64_t read_data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

    if (errno != 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    char* ptr;
    if (mind_rbound)
        ptr = (char*)(&read_data) + (sizeof(uint64_t) - partial_len);
    else
        ptr = (char*)(&read_data);

    memcpy(ptr, c_data, partial_len);
    if (ptrace(PTRACE_POKETEXT, pid, addr, *((uint64_t*)ptr)) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    Py_RETURN_NONE;
}
