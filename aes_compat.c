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

#if defined(_MSC_VER)
#  include <Windows.h>
#  include <malloc.h>
#  define strncasecmp _strnicmp
#else
#  include <stdlib.h>
#  include <string.h>
#  include <sys/mman.h>
#endif

#include "aes_compat.h"

/*
 * Zero the supplied context's memory, unlock it, and then free it.
 */
void del_aes_context(aes_crypt_ctx *ctx)
{
    if(!ctx)
        return;
    memset(ctx, 0, sizeof(aes_crypt_ctx));
#if defined(_MSC_VER)
    VirtualUnlock(ctx, sizeof(aes_crypt_ctx));
    _aligned_free(ctx);
#else
    munlock(ctx, sizeof(aes_crypt_ctx));
    free(ctx);
#endif
}

/*
 * Allocate sufficient memory on the heap for an AES context (aligned to a
 * 16-byte boundary), lock it, and then zero it.
 */
aes_crypt_ctx *new_aes_context(void)
{
    aes_crypt_ctx *ctx = NULL;

#if defined(_MSC_VER)
    if((ctx = _aligned_malloc(sizeof(aes_crypt_ctx), 16)) == NULL)
        return NULL;
    if(VirtualLock(ctx, sizeof(aes_crypt_ctx)) == 0)
    {
        _aligned_free(ctx);
        return NULL;
    }
#else
    if(posix_memalign((void **)&ctx, 16, sizeof(aes_crypt_ctx)) != 0)
        return NULL;
    if(mlock(ctx, sizeof(aes_crypt_ctx)) != 0)
    {
        free(ctx);
        return NULL;
    }
#endif
    memset(ctx, 0, sizeof(aes_crypt_ctx));
    return ctx;
}

/*
This subroutine implements the CTR mode standard incrementing function.
See NIST Special Publication 800-38A, Appendix B for details:
http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
*/
#define CTR_POS 8

void ctr_inc(unsigned char *cbuf)
{
    unsigned char *p = cbuf + AES_BLOCK_SIZE, *e = cbuf + CTR_POS;
    while(p-- > e && !++(*p))
        ;
}
