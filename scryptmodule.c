#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "scrypt.h"

static PyObject *scrypt_getpowhash(PyObject *self, PyObject *args) {
    char *outbuf;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    outbuf = PyMem_Malloc(32);
    Py_BEGIN_ALLOW_THREADS;
#if PY_MAJOR_VERSION >= 3
    scrypt_1024_1_1_256((char *)PyBytes_AsString((PyObject*) input), outbuf);
#else
    scrypt_1024_1_1_256((char *)PyString_AsString((PyObject*) input), outbuf);
#endif
    Py_END_ALLOW_THREADS;
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", outbuf, 32);
#else
    value = Py_BuildValue("s#", outbuf, 32);
#endif
    PyMem_Free(outbuf);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "getPoWHash", scrypt_getpowhash, METH_VARARGS, "Returns the proof of work hash using scrypt" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef scryptmodule = {
    PyModuleDef_HEAD_INIT,
    "ltc_scrypt",
    "...",
    -1,
    ScryptMethods
};

PyMODINIT_FUNC PyInit_ltc_scrypt(void) {
    return PyModule_Create(&scryptmodule);
}
#else

PyMODINIT_FUNC initltc_scrypt(void) {
    (void) Py_InitModule("ltc_scrypt", ScryptMethods);
}
#endif
