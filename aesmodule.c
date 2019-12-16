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

typedef enum {
    UC_ENCRYPTION = 0,
    UC_DECRYPTION = 1,
} use_case;

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

/*
 * Internal subroutine used by exported methods build_{en,de}cryption_context
 */
static PyObject *build_aes_context(use_case uc, PyObject *args, PyObject *kwds)
{
    Py_buffer key;
    char *kwlist[] = {"key", NULL};
    aes_crypt_ctx *ctx;
    unsigned int success = 0;
    PyObject *capsule;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*", kwlist, &key))
    {
        PyErr_SetString(PyExc_ValueError, "Failed to parse arguments");
        return NULL;
    }

    ctx = new_aes_context();
    if(!ctx)
        return PyErr_NoMemory();

    if(uc == UC_ENCRYPTION)
        if(aes_encrypt_key(key.buf, key.len, ctx) == EXIT_SUCCESS)
            success = 1;
        else
            PyErr_SetString(PyExc_ValueError, "Invalid encryption key size");
    else if(uc == UC_DECRYPTION)
        if(aes_decrypt_key(key.buf, key.len, ctx) == EXIT_SUCCESS)
            success = 1;
        else
            PyErr_SetString(PyExc_ValueError, "Invalid decryption key size");
    else
        PyErr_SetString(PyExc_ValueError, "Invalid use case");

    PyBuffer_Release(&key);
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

PyDoc_STRVAR(build_encryption_context__doc__,
"build_encryption_context(key) -> PyCapsule\n\n\
Allocate and initialize an AES encryption context on the heap.");
static PyObject *build_encryption_context(PyObject *self, PyObject *args, PyObject *kwds)
{
    return build_aes_context(UC_ENCRYPTION, args, kwds);
}

PyDoc_STRVAR(build_decryption_context__doc__,
"build_decryption_context(key) -> PyCapsule\n\n\
Allocate and initialize an AES encryption context on the heap.");
static PyObject *build_decryption_context(PyObject *self, PyObject *args, PyObject *kwds)
{
    return build_aes_context(UC_DECRYPTION, args, kwds);
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

/*
 * Internal subroutine used by exported methods ecb_{en,de}crypt
 */
static PyObject *ecb_crypt(use_case uc, PyObject *args, PyObject *kwds)
{
    PyObject *capsule, *retval;
    Py_buffer idata;
    unsigned char *odata;
    char *kwlist[] = {"data", "ctx", NULL};
    aes_crypt_ctx *ctx;
    AES_RETURN ecb_status;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "y*O", kwlist, &idata, &capsule))
    {
        PyErr_SetString(PyExc_ValueError, "Failed to parse arguments");
        return NULL;
    }
    ctx = unwrap_aes_context(capsule);
    if(!ctx)
    {
        PyBuffer_Release(&idata);
        return NULL;
    }

    retval = PyBytes_FromStringAndSize(NULL, idata.len);
    if(!retval)
    {
        PyBuffer_Release(&idata);
        return NULL;
    }
    odata = (unsigned char *)PyBytes_AsString(retval);
    if(!odata)
    {
        Py_DECREF(retval);
        PyBuffer_Release(&idata);
        return NULL;
    }

    switch(uc)
    {
    case UC_ENCRYPTION:
        ecb_status = aes_ecb_encrypt((unsigned char *)idata.buf, odata, (int)idata.len, (aes_encrypt_ctx *)ctx);
        break;
    case UC_DECRYPTION:
        ecb_status = aes_ecb_decrypt((unsigned char *)idata.buf, odata, (int)idata.len, (aes_decrypt_ctx *)ctx);
        break;
    }

    PyBuffer_Release(&idata);
    if(ecb_status != EXIT_SUCCESS)
    {
        Py_DECREF(retval);
        PyErr_SetString(PyExc_RuntimeError, "ECB crypto failure");
        return NULL;
    }

    return retval;
}

PyDoc_STRVAR(ecb_encrypt__doc__,
"ecb_encrypt(data, ctx) -> bytes\n\n\
Encrypt one or more blocks of data in ECB mode.");
static PyObject *ecb_encrypt(PyObject *self, PyObject *args, PyObject *kwds)
{
    return ecb_crypt(UC_ENCRYPTION, args, kwds);
}

PyDoc_STRVAR(ecb_decrypt__doc__,
"ecb_decrypt(data, ctx) -> bytes\n\n\
Decrypt one or more blocks of data in ECB mode.");
static PyObject *ecb_decrypt(PyObject *self, PyObject *args, PyObject *kwds)
{
    return ecb_crypt(UC_DECRYPTION, args, kwds);
}

static PyMethodDef aes_methods[] = {
    {"build_encryption_context", (PyCFunction)build_encryption_context,
     METH_VARARGS | METH_KEYWORDS, build_encryption_context__doc__},
    {"build_decryption_context", (PyCFunction)build_decryption_context,
     METH_VARARGS | METH_KEYWORDS, build_decryption_context__doc__},
    {"ecb_encrypt", (PyCFunction)ecb_encrypt, METH_VARARGS | METH_KEYWORDS,
     ecb_encrypt__doc__},
    {"ecb_decrypt", (PyCFunction)ecb_decrypt, METH_VARARGS | METH_KEYWORDS,
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
