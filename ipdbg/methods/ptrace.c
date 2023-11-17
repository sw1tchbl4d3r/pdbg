#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <libunwind-ptrace.h>

#include "globals.h"

#define ENUMERATE_REGISTERS(O)           \
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

#define GET_REGISTER(reg) PyObject_SetAttrString(registers_instance, #reg, PyLong_FromUnsignedLong(regs.reg))
PyObject* method_getregs(PyObject* self, PyObject* args) {
    pid_t pid;
    struct user_regs_struct regs;

    if(!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);

    PyObject* registers_instance = PyObject_CallObject(IPDBG_Registers, NULL);
    if (!registers_instance)
        return NULL;

    ENUMERATE_REGISTERS(GET_REGISTER);

    return registers_instance;
}

#define SET_REGISTER(reg) regs.reg = PyLong_AsLong(PyObject_GetAttrString(registers_instance, #reg))
PyObject* method_setregs(PyObject* self, PyObject* args) {
    pid_t pid;
    PyObject* registers_instance;
    struct user_regs_struct regs;

    if(!PyArg_ParseTuple(args, "iO!", &pid, IPDBG_Registers, &registers_instance))
        return NULL;

    ENUMERATE_REGISTERS(SET_REGISTER);

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

void decref_list(PyObject* list) {
    if (!list)
        return;

    Py_ssize_t size = PyList_Size(list);
    for (Py_ssize_t i = 0; i < size; ++i)
        Py_XDECREF(PyList_GetItem(list, i));

    Py_DECREF(list);
}

PyObject* method_unwind(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t step_limit;

    if(!PyArg_ParseTuple(args, "ik", &pid, &step_limit))
        return NULL;

    unw_cursor_t cursor;
    unw_addr_space_t addr_space = unw_create_addr_space(&_UPT_accessors, 0);
    unw_init_remote(&cursor, addr_space, _UPT_create(pid));

    PyObject* list = PyList_New(0);

    unw_word_t offset, rip;
    do {
        char sym[4096];
        unw_get_reg(&cursor, UNW_REG_IP, &rip);

        PyObject* frame = PyObject_CallObject(IPDBG_UnwoundStackFrame, NULL);
        if (!frame) {
            decref_list(list);
            return NULL;
        }

        PyObject_SetAttrString(frame, "rip", PyLong_FromUnsignedLong(rip));

        if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
            PyObject_SetAttrString(frame, "symbol", PyUnicode_FromString(sym));
            PyObject_SetAttrString(frame, "offset", PyLong_FromUnsignedLong(offset));
        } else {
            PyObject_SetAttrString(frame, "symbol", PyUnicode_FromString(""));
            PyObject_SetAttrString(frame, "offset", PyLong_FromUnsignedLong(0));
        }

        PyList_Append(list, frame);
        step_limit--;
    } while (unw_step(&cursor) > 0 && step_limit > 0);

    return list;
}
