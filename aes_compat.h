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

#ifndef _AES_COMPAT_H
#define _AES_COMPAT_H

#include <aes.h>

void del_aes_context(aes_crypt_ctx *ctx);
aes_crypt_ctx *new_aes_context(void);
void ctr_inc(unsigned char *cbuf);

#endif  /* _AES_COMPAT_H */
