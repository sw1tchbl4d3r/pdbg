#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

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

    GET_REGISTER(r15); GET_REGISTER(r14); GET_REGISTER(r13); GET_REGISTER(r12);
    GET_REGISTER(rbp); GET_REGISTER(rbx); GET_REGISTER(r11); GET_REGISTER(r10);
    GET_REGISTER(r9);  GET_REGISTER(r8);  GET_REGISTER(rax); GET_REGISTER(rcx);
    GET_REGISTER(rdx); GET_REGISTER(rsi); GET_REGISTER(rdi); GET_REGISTER(rip);
    GET_REGISTER(cs);  GET_REGISTER(rsp); GET_REGISTER(ss);  GET_REGISTER(ds);
    GET_REGISTER(es);  GET_REGISTER(fs);  GET_REGISTER(gs);  GET_REGISTER(orig_rax);
    GET_REGISTER(fs_base); GET_REGISTER(gs_base); GET_REGISTER(eflags);

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

    SET_REGISTER(r15); SET_REGISTER(r14); SET_REGISTER(r13); SET_REGISTER(r12);
    SET_REGISTER(rbp); SET_REGISTER(rbx); SET_REGISTER(r11); SET_REGISTER(r10);
    SET_REGISTER(r9);  SET_REGISTER(r8);  SET_REGISTER(rax); SET_REGISTER(rcx);
    SET_REGISTER(rdx); SET_REGISTER(rsi); SET_REGISTER(rdi); SET_REGISTER(rip);
    SET_REGISTER(cs);  SET_REGISTER(rsp); SET_REGISTER(ss);  SET_REGISTER(ds);
    SET_REGISTER(es);  SET_REGISTER(fs);  SET_REGISTER(gs);  SET_REGISTER(orig_rax);
    SET_REGISTER(fs_base); SET_REGISTER(gs_base); SET_REGISTER(eflags);

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
