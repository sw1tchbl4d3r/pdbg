#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>

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

static PyObject* ptrace_command(PyObject* self, PyObject* args, enum __ptrace_request command) {
    pid_t pid;

    if(!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    return PyLong_FromLong(ptrace(command, pid, NULL, NULL));
}

static PyObject* method_attach(PyObject* self, PyObject* args) { return ptrace_command(self, args, PTRACE_ATTACH); }
static PyObject* method_seize(PyObject* self, PyObject* args) { return ptrace_command(self, args, PTRACE_SEIZE); }
static PyObject* method_detach(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_DETACH); }
static PyObject* method_cont(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_CONT); }
static PyObject* method_interrupt(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_INTERRUPT); }
static PyObject* method_singlestep(PyObject *self, PyObject *args) { return ptrace_command(self, args, PTRACE_SINGLESTEP); }

#define GET_REGISTER(reg) PyDict_SetItem(dict, PyUnicode_FromString(#reg), PyLong_FromUnsignedLong(regs.reg))
static PyObject* method_getregs(PyObject* self, PyObject* args) {
    pid_t pid;
    struct user_regs_struct regs;

    if(!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    long call_ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    PyObject* dict = PyDict_New();

    ENMUMERATE_REGISTERS(GET_REGISTER);

    PyDict_SetItem(dict, PyUnicode_FromString("call_ret"), PyLong_FromLong(call_ret));

    return dict;
}

#define SET_REGISTER(reg) regs.reg = PyLong_AsUnsignedLong(PyDict_GetItem(dict, PyUnicode_FromString(#reg)))
static PyObject* method_setregs(PyObject* self, PyObject* args) {
    pid_t pid;
    PyObject* dict;
    struct user_regs_struct regs;

    if(!PyArg_ParseTuple(args, "iO!", &pid, &PyDict_Type, &dict))
        return NULL;

    ENMUMERATE_REGISTERS(SET_REGISTER);

    return PyLong_FromLong(ptrace(PTRACE_SETREGS, pid, NULL, &regs));
}

static PyObject* method_peek(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;

    if(!PyArg_ParseTuple(args, "ik", &pid, &addr))
        return NULL;

    // NOTE: As we extract a full long of data, the signing bit has to be interpreted as a data bit.
    return PyLong_FromUnsignedLong(ptrace(PTRACE_PEEKTEXT, pid, addr, NULL));
}

static PyObject* method_poke(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;
    uint64_t data;

    if(!PyArg_ParseTuple(args, "ikk", &pid, &addr, &data))
        return NULL;

    return PyLong_FromLong(ptrace(PTRACE_POKETEXT, pid, addr, data));
}

// NOTE: These methods have to be a bit finnicky because PTRACE_POKE and PTRACE_PEEK 
//       only support reading/writing full uint64_t values.

static PyObject* method_read_bytes(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;
    size_t length;
    uint32_t mind_rbound;

    if (!PyArg_ParseTuple(args, "ikkp", &pid, &addr, &length, &mind_rbound))
        return NULL;

    uint64_t data;

    char* final = malloc(length+1);
    char* final_ptr = final;

    for (size_t i = 0; i < length / sizeof(uint64_t); i++) {
        data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
        memcpy(final_ptr, (char*)(&data), sizeof(uint64_t));
        addr += sizeof(uint64_t);
        final_ptr += sizeof(uint64_t);
    }

    int partial_len = length % sizeof(uint64_t);
    if (mind_rbound)
        addr = addr - (sizeof(uint64_t) - partial_len);

    data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

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

static PyObject* method_write_bytes(PyObject* self, PyObject* args) {
    pid_t pid;
    uint64_t addr;
    size_t length;
    PyObject* data;
    uint32_t mind_rbound;

    if (!PyArg_ParseTuple(args, "ikO!kp", &pid, &addr, &PyByteArray_Type, &data, &length, &mind_rbound))
        return NULL;

    char* c_data = PyByteArray_AsString(data);

    for (size_t i = 0; i < length / sizeof(uint64_t); i++) {
        ptrace(PTRACE_POKETEXT, pid, addr, *((uint64_t*)c_data));
        c_data += sizeof(uint64_t);
        addr += sizeof(uint64_t);
    }

    int partial_len = length % sizeof(uint64_t);
    if (mind_rbound)
        addr = addr - (sizeof(uint64_t) - partial_len);

    uint64_t read_data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

    char* ptr;
    if (mind_rbound)
        ptr = (char*)(&read_data) + (sizeof(uint64_t) - partial_len);
    else
        ptr = (char*)(&read_data);

    memcpy(ptr, c_data, partial_len);
    ptrace(PTRACE_POKETEXT, pid, addr, *((uint64_t*)ptr));

    Py_RETURN_NONE;
}
