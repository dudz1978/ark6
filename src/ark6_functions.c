/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/

/*
Versão de RC6(w=32,r=20,b=32) alterada para aumento de segurança (mais rounds, chave maior),
constantes alteradas (verão customizada), e
melhoria contra ataque de distinção chi^2 (baseada em
    _ Uma versão mais forte do algoritmo RC6 contra criptanálise chi ^2 _
    Eduardo Takeo Ueda, 2007
    Routo Terada 
).
O algoritmo Rcom esses parâmetros, C6T(w=32,r=40,b=64), será denominado Ark6.

Formato do arquivo .ark6:
128 bits de salt aleatório
128 bits do xor das duas metades de
pbkdf2(prf=hash_128_bytes(), qtd_blocos=2, pass=senha, salt=salt(este anterior), c=16k), para
conferência de senha. Isso faz com que tenha 2^128 senhas distintas que levem ao mesmo hash,
de forma que não saberá qual o correto.
O salt da geração da chave será os 128+256 bits dos passos anteriores, ou seja,
o próprio salt é secreto com 384 bits.
Chave de criptografia é pbkdf2(prf=hash_128_bytes(), qtd_blocos=4, pass=senha, salt=salt_384, c=16k).
Demais bytes são a criptografia em si no modo counter, com número inicial (nonce) formado
pelo hash do salt_384 descrito acima, ou seja, o nonce do modo counter também é secreto.

Crescimento do arquivo é fixo de 256 bits = 32 bytes.

*/


#include <string.h>
#include <stdint.h>
#include "include/ark6_constants.h"



uint32_t
rot_e(uint32_t v, uint32_t n)
{
    n &= 0x1f;
    return (uint32_t)(((v << n) | (v >> (32 - n))) & 0xffffffffU);
}

void
calcula_subkeys(const uint32_t L_[KEY_SIZE_WORDS], uint32_t S[DOIS_R_MAIS_4])
{
    int i, j, s;
    uint32_t a, b;
    uint32_t L[C];

    for (i = 0; i < C; i++) L[i] = L_[i];
    S[0] = P;
    for (i = 1; i < DOIS_R_MAIS_4; i++) {
        S[i] = S[i - 1] + Q;
    }
    a = b = 0;
    i = j = 0;
    for (s = 1; s <= V; s++) {
        a = S[i] = rot_e(S[i] + a + b, 3);
        b = L[j] = rot_e(L[j] + a + b, a + b);
        i = (i + 1) % DOIS_R_MAIS_4;
        j = (j + 1) % C;
    }
    for (i = 0; i < C; i++) L[i] = 0;
}

#ifndef RC6_MODE
uint32_t
T(uint32_t n)
{
    uint32_t n2 = n;
    int p = 0;
    while (n != 0) {
        p ^= (n & 1);
        n >>= 1;
    }
    if (p != 0) {
        return (0xffffU & (n2 >> NIBBLE_SIZE)) | (0xffff0000U & (n2 << NIBBLE_SIZE));
    }
    return n2;
}
#endif

void
ark6(uint32_t *pa, uint32_t *pb, uint32_t *pc, uint32_t *pd, const uint32_t S[DOIS_R_MAIS_4])
{
    int i;
    uint32_t a, b, c, d;
    uint32_t t, u;
    int dois_r_mais_2 = (R << 1) + 2;
    a = *pa;
    b = *pb + S[0];
    c = *pc;
    d = *pd + S[1];
    i = 2;
    while (i < dois_r_mais_2) {
#ifndef RC6_MODE
        b = T(b);
        d = T(d);
#endif
        t = rot_e(b * ((b << 1) + 1), 5);
        u = rot_e(d * ((d << 1) + 1), 5);
        a = rot_e(a ^ t, u) + S[i++];
        c = rot_e(c ^ u, t) + S[i++];
        t = a;
        a = b;
        b = c;
        c = d;
        d = t;
    }
    *pa = a + S[i++];
    *pb = b;
    *pc = c + S[i++];
    *pd = d;
}

/* Criptografa block usando chave key */
uint8_t *
ark6_block_key(uint8_t *block, const uint8_t *key)
{
    int i;
    uint32_t S[DOIS_R_MAIS_4];
    uint32_t *block_vars;
    calcula_subkeys((uint32_t *) key, S);
    block_vars = (uint32_t *) block;
    ark6(&block_vars[0],&block_vars[1],&block_vars[2],&block_vars[3], S);
    for (i = 0; i < DOIS_R_MAIS_4; i++) S[i] = 0;
    return block;
}

/* Criptografa block com saida em output, usando chave key. */
uint8_t *
ark6_output_block_key(uint8_t *output, const uint8_t *block, const uint8_t *key)
{
    memcpy(output, block, BLOCK_SIZE_BYTES);
    return ark6_block_key(output, key);
}

/* Criptografa block usando subchaves S */
uint8_t *
ark6_block_subkeys(uint8_t *block, const uint32_t S[DOIS_R_MAIS_4])
{
    uint32_t *block_vars;
    block_vars = (uint32_t *) block;
    ark6(&block_vars[0],&block_vars[1],&block_vars[2],&block_vars[3], S);
    return block;
}

/* Criptografa block usando subchaves S, com saída em output. */
uint8_t *
ark6_output_block_subkeys(uint8_t output[BLOCK_SIZE_BYTES],
    const uint8_t *block, const uint32_t S[DOIS_R_MAIS_4])
{
    memcpy(output, block, BLOCK_SIZE_BYTES);
    return ark6_block_subkeys(output, S);
}
