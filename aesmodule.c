/*
---------------------------------------------------------------------------
Copyright (c) 2019, Michael Mohr, San Jose, CA, USA. All rights reserved.
Copyright (c) 2019, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 12/12/2019
*/

#define CAPSULE_NAME "__AES_CONTEXT__"
#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <structmember.h>

#include "aes_compat.h"

/*
 * Internal support subroutine which functions as a destructor
 * for the AES context capsules.
 */
static void destroy_aes_context(PyObject *capsule)
{
    del_aes_context((aes_crypt_ctx *)PyCapsule_GetPointer(capsule, CAPSULE_NAME));
}

PyDoc_STRVAR(build_context__doc__,
"build_context(key, use_case) -> PyCapsule\n\n\
Allocate and initialize an AES context on the heap.");
static PyObject *build_context(PyObject *self, PyObject *args, PyObject *kwds)
{
    Py_buffer key, use_case;
    char *kwlist[] = {"key", "use_case", NULL};
    aes_crypt_ctx *ctx;
    unsigned int success = 0;
    PyObject *capsule;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*s*", kwlist, &key, &use_case))
    {
        PyErr_SetString(PyExc_ValueError, "Failed to parse arguments");
        return NULL;
    }

    ctx = new_aes_context();
    if(!ctx)
        return PyErr_NoMemory();

    if(strncasecmp(use_case.buf, "encryption", use_case.len))
        if(aes_encrypt_key(key.buf, key.len, ctx) == EXIT_SUCCESS)
            success = 1;
        else
            PyErr_SetString(PyExc_ValueError, "Invalid encryption key size");
    else if(strncasecmp(use_case.buf, "decryption", use_case.len))
        if(aes_decrypt_key(key.buf, key.len, ctx) == EXIT_SUCCESS)
            success = 1;
        else
            PyErr_SetString(PyExc_ValueError, "Invalid decryption key size");
    else
        PyErr_SetString(PyExc_ValueError, "Invalid use case");

    PyBuffer_Release(&key);
    PyBuffer_Release(&use_case);
    if(!success)
    {
        del_aes_context(ctx);
        return NULL;
    }
    capsule = PyCapsule_New((void*)ctx, CAPSULE_NAME, destroy_aes_context);
    if(!capsule)
        del_aes_context(ctx);
    return capsule;
}

/*
 * Internal support subroutine which unwraps a PyCapsule and returns NULL
 * (on error) or a valid pointer to an aes_crypt_ctx.  On error sets the
 * exception before return.
 */
aes_crypt_ctx *unwrap_aes_context(PyObject *capsule)
{
    if(!PyCapsule_IsValid(capsule, CAPSULE_NAME))
    {
        PyErr_SetString(PyExc_ValueError, "Invalid AES context");
        return NULL;
    }
    return (aes_crypt_ctx *)PyCapsule_GetPointer(capsule, CAPSULE_NAME);
}

PyDoc_STRVAR(ecb_encrypt__doc__,
"ecb_encrypt(data, ctx) -> None\n\n\
Encrypt one or more blocks of data in ECB mode in-place.");
static PyObject *ecb_encrypt(PyObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *capsule;
    Py_buffer data;
    char *kwlist[] = {"data", "ctx", NULL};
    aes_encrypt_ctx *ctx;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*O", kwlist, &data, &capsule))
    {
        PyErr_SetString(PyExc_ValueError, "Failed to parse arguments");
        return NULL;
    }
    ctx = (aes_encrypt_ctx *)unwrap_aes_context(capsule);
    if(!ctx) return NULL;

    if(aes_ecb_encrypt(data.buf, data.buf, data.len, ctx) != EXIT_SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError, "ECB encryption failure");
        return NULL;
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(ecb_decrypt__doc__,
"ecb_decrypt(data, ctx) -> None\n\n\
Decrypt one or more blocks of data in ECB mode in-place.");
static PyObject *ecb_decrypt(PyObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *capsule;
    Py_buffer data;
    char *kwlist[] = {"data", "ctx", NULL};
    aes_decrypt_ctx *ctx;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*O", kwlist, &data, &capsule))
    {
        PyErr_SetString(PyExc_ValueError, "Failed to parse arguments");
        return NULL;
    }
    ctx = (aes_decrypt_ctx *)unwrap_aes_context(capsule);
    if(!ctx) return NULL;

    if(aes_ecb_decrypt(data.buf, data.buf, data.len, ctx) != EXIT_SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError, "ECB decryption failure");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMethodDef aes_methods[] = {
    {"build_context", build_context, METH_VARARGS | METH_KEYWORDS,
     build_context__doc__},
    {"ecb_encrypt", ecb_encrypt, METH_VARARGS | METH_KEYWORDS,
     ecb_encrypt__doc__},
    {"ecb_decrypt", ecb_decrypt, METH_VARARGS | METH_KEYWORDS,
     ecb_decrypt__doc__},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

static struct PyModuleDef aes_module =
{
    PyModuleDef_HEAD_INIT,
    "aes",              /* m_name     */
    "Python Bindings",  /* m_doc      */
    -1,                 /* m_size     */
    aes_methods,        /* m_methods  */
    NULL,               /* m_reload   */
    NULL,               /* m_traverse */
    NULL,               /* m_clear    */
    NULL,               /* m_free     */
};

PyMODINIT_FUNC PyInit_aes(void)
{
    return PyModule_Create(&aes_module);
}
