/*
 * https://xakep.ru/2016/07/20/hash-gost-34-11-2012/
 *
 */



#ifdef __cplusplus
extern "C" {
#endif

#include "gost_3411_2012_calc.h"

void GOSTHashInit(TGOSTHashContext *ctx, uint16_t hash_size)
{
    memset(ctx, 0x00, sizeof(TGOSTHashContext));
    if (hash_size == 256)
        memset(ctx->h, 0x01, BLOCK_SIZE);
    else
        memset(ctx->h, 0x00, BLOCK_SIZE);

    ctx->hash_size = hash_size;
    ctx->v_512[1] = 0x02;
}

static void GOSTHashX(const uint8_t *a, const uint8_t *b, uint8_t *c)
{
    int i;
    for (i=0; i<64; i++)
        c[i] = a[i] ^ b[i];
}

static void GOSTHashAdd512(const uint8_t *a, const uint8_t *b, uint8_t *c)
{
    int i;
    int internal = 0;
    for (i=0; i<64; i++)
    {
        internal = a[i] + b[i] + (internal >> 8);
        c[i] = internal & 0xFF;
    }
}

static void GOSTHashP(uint8_t *state)
{
    int i;
    vect internal;
    for (i=63; i>=0; i--)
        internal[i] = state[Tau[i]];
    memcpy(state, internal, BLOCK_SIZE);
}

static void GOSTHashS(uint8_t *state)
{
    int i;
    vect internal;
    for (i=63; i>=0; i--)
        internal[i] = Pi[state[i]];
    memcpy(state, internal, BLOCK_SIZE);
}

static void GOSTHashL(uint8_t *state)
{
    uint64_t *internal_in = (uint64_t *)state;
    uint64_t internal_out[8];
    memset(internal_out, 0x00, BLOCK_SIZE);
    int i, j;
    for (i=7; i>=0; i--)
    {
        for (j=63; j>=0; j--)
            if ((internal_in[i] >> j) & 0x1)
                internal_out[i] ^= A[63 - j];
    }
    memcpy(state, internal_out, 64);
}

static void GOSTHashGetKey(uint8_t *K, int i)
{
    GOSTHashX(K, C[i], K);
    GOSTHashS(K);
    GOSTHashP(K);
    GOSTHashL(K);
}

static void GOSTHashE(uint8_t *K, const uint8_t *m, uint8_t *state)
{
    int i;
    memcpy(K, K, BLOCK_SIZE);
    GOSTHashX(m, K, state);
    for (i=0; i<12; i++)
    {
        GOSTHashS(state);
        GOSTHashP(state);
        GOSTHashL(state);
        GOSTHashGetKey(K, i);
        GOSTHashX(state, K, state);
    }
}

static void GOSTHashG(uint8_t *h, uint8_t *N, const uint8_t *m)
{
    vect K, internal;
    GOSTHashX(N, h, K);

    GOSTHashS(K);
    GOSTHashP(K);
    GOSTHashL(K);

    GOSTHashE(K, m, internal);

    GOSTHashX(internal, h, internal);
    GOSTHashX(internal, m, h);
}

static void GOSTHashPadding(TGOSTHashContext *ctx)
{
    vect internal;

    if (ctx->buf_size < BLOCK_SIZE)
    {
        memset(internal, 0x00, BLOCK_SIZE);
        memcpy(internal, ctx->buffer, ctx->buf_size);
        internal[ctx->buf_size] = 0x01;
        memcpy(ctx->buffer, internal, BLOCK_SIZE);
    }
}

static void GOSTHashStage_2(TGOSTHashContext *ctx, const uint8_t *data)
{
    GOSTHashG(ctx->h, ctx->N, data);
    GOSTHashAdd512(ctx->N, ctx->v_512, ctx->N);
    GOSTHashAdd512(ctx->Sigma, data, ctx->Sigma);
}

static void GOSTHashStage_3(TGOSTHashContext *ctx)
{
    vect internal;
    memset(internal, 0x00, BLOCK_SIZE);
    internal[1] = ((ctx->buf_size * 8) >> 8) & 0xFF;
    internal[0] = (ctx->buf_size * 8) & 0xFF;

    GOSTHashPadding(ctx);

    GOSTHashG(ctx->h, ctx->N, (const uint8_t *)&(ctx->buffer));
    GOSTHashAdd512(ctx->N, internal, ctx->N);
    GOSTHashAdd512(ctx->Sigma, ctx->buffer, ctx->Sigma);

    GOSTHashG(ctx->h, ctx->v_0, (const uint8_t *)&(ctx->N));
    GOSTHashG(ctx->h, ctx->v_0, (const uint8_t *)&(ctx->Sigma));

    memcpy(ctx->hash, ctx->h, BLOCK_SIZE);
}

void GOSTHashUpdate(TGOSTHashContext *ctx, const uint8_t *data, size_t len)
{
    size_t chk_size;

    while ((len > 63) && (ctx->buf_size) == 0)
    {
        GOSTHashStage_2(ctx, data);
        data += 64;
        len -= 64;
    }

    while (len)
    {
        chk_size = 64 - ctx->buf_size;
        if (chk_size > len)
            chk_size = len;
        memcpy(&ctx->buffer[ctx->buf_size], data, chk_size);
        ctx->buf_size += chk_size;
        len -= chk_size;
        data += chk_size;
        if (ctx->buf_size == 64) {
            GOSTHashStage_2(ctx, ctx->buffer);
            ctx->buf_size = 0;
        }
    }
}

void GOSTHashFinal(TGOSTHashContext *ctx)
{
    GOSTHashStage_3(ctx);
    ctx->buf_size = 0;
}

#ifdef __cplusplus
}
#endif
