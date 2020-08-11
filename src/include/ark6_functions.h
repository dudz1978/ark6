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

#ifndef __ark6_functions_h_
#define __ark6_functions_h_

#include "ark6_types.h"

uintw_t
rot_e(uintw_t v, uintw_t n);

void
calcula_subkeys(const uintw_t L_[KEY_SIZE_WORDS], uintw_t S[DOIS_R_MAIS_4]);

void
ark6(uintw_t *pa, uintw_t *pb, uintw_t *pc, uintw_t *pd, const uintw_t S[DOIS_R_MAIS_4]);

/* Criptografa block usando chave key */
uint8_t *
ark6_block_key(uint8_t *block, const uint8_t *key);

/* Criptografa block com saida em output, usando chave key. */
uint8_t *
ark6_output_block_key(uint8_t *output, const uint8_t *block, const uint8_t *key);

/* Criptografa block usando subchaves S */
uint8_t *
ark6_block_subkeys(uint8_t *block, const uintw_t S[DOIS_R_MAIS_4]);

/* Criptografa block usando subchaves S, com saída em output. */
uint8_t *
ark6_output_block_subkeys(uint8_t output[BLOCK_SIZE_BYTES],
    const uint8_t *block, const uintw_t S[DOIS_R_MAIS_4]);

#endif
