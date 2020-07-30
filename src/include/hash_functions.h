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

#ifndef __hash_functions_h_
#define __hash_functions_h_

/* Gera hash de 128 bits.
Algoritmo: começar com tamanho em bits (big-endian, até 64 bits)
depois os bits, com o último com append 1000...000, com pelo
menos o bit 1 obrigatório (mesmo que abra mais um bloco inteiro).
Cada KEY_SIZE_BITS bits do texto é chave usada na criptografia do bloco
hash anterior, e o
hash inicial é formado por 128 (BLOCK_SIZE_BITS) bits zero.
*/
uint8_t *
hash_128_bits(uint8_t hash[BLOCK_SIZE_BYTES], const uint8_t *v, uint64_t qtd_bits);

uint8_t *
hash_128_bytes(uint8_t hash[BLOCK_SIZE_BYTES], const uint8_t *v, uint64_t qtd_bytes);

uint8_t *
hash_128_str(uint8_t hash[BLOCK_SIZE_BYTES], const char *str);

/*
Gera chave de 128*qtd_blocos_senha bits com c iterações.
Usa senha de tam_senha bytes.
O valor de U0 será o hash de (salt + uint32_be(i)).
O valor de U_j é hash de (senha + U_(j-1)), para j=1..c.
O xor de todos o Uj (incluindo o 0) é Ti, e as concatenações de Ti
(para i=1..2) é a chave derivada (key).
*/
uint8_t *
pbkdf2(uint8_t key[KEY_SIZE_BYTES], const int qtd_blocos_senha, const uint8_t *senha,
    int tam_senha, const uint8_t *salt, int tam_salt, int c
);

#endif
