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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "include/ark6_constants.h"
#include "include/ark6_functions.h"

/* OBS: as funções deste arquivo funcionam exclusivamente com o Ark6, já que para
conseguirem hash de 256 bits precisam de bloco do mesmo tamanho.
Um hash de 256 bits com RC6 pode ser feito usando um PBKDF2 interno com apenas
um passo, mas não será implementado aqui, já que o modo RC6 serve
apenas para confirmar que a implementação da criptografia está correta.
 */

/* Gera hash de 256 bits.
Algoritmo: começar com tamanho em bits (big-endian, até 64 bits)
depois os bits, com o último com append 1000...000, com pelo
menos o bit 1 obrigatório (mesmo que abra mais um bloco inteiro).
Cada KEY_SIZE_BITS bits do texto é chave usada na criptografia do bloco
hash anterior, e o
hash inicial é formado por 256 (BLOCK_SIZE_BITS) bits zero.
*/
uint8_t *
hash_256_bits(uint8_t hash[BLOCK_SIZE_BYTES], const uint8_t *v, uint64_t qtd_bits)
{
    int i;
    int pos, pos_key;
    uint64_t ui64;
    uint8_t key[KEY_SIZE_BYTES];
    uint8_t ultimo_byte_nao_zero;
    int ultima_posicao;
    uint8_t ui8;

#ifdef RC6_MODE
    fprintf(stderr, "\nFuncoes hash_256 nao devem ser usadas com RC6_MODE.\n");
    exit(1);
#endif

    for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
        hash[i] = 0;
    }
    ui64 = qtd_bits;
    for (i = 7; i >= 0; i--) {
        key[i] = (uint8_t)(ui64 & 0xffU);
        ui64 >>= 8;
    }
    ultima_posicao = (int)(qtd_bits >> 3) - 1;
    if ((qtd_bits & 0x7) != 0) {
        ultima_posicao++;
    }
    pos = 0;
    pos_key = 8;
    while (pos < ultima_posicao) {
        key[pos_key++] = v[pos++];
        if (pos_key == KEY_SIZE_BYTES) {
            pos_key = 0;
            ark6_block_key(hash, key);
        }
    }
    i = (qtd_bits & 0x7);
    if (i == 0) { /* se 0, a quantidade de bits é multipla de 8 */
        if (ultima_posicao >= 0) { /* impede pegar byte [-1] se qtd_bits==0 */
            key[pos_key++] = v[ultima_posicao];
            if (pos_key == KEY_SIZE_BYTES) {
                pos_key = 0;
                ark6_block_key(hash, key);
            }
        }
        ultimo_byte_nao_zero = (uint8_t) 0x80U;
    }
    else {
        ultimo_byte_nao_zero = 0;
        ui8 = v[ultima_posicao];
        while (i > 0) {
            ultimo_byte_nao_zero <<= 1;
            ultimo_byte_nao_zero |= (uint8_t)(((ui8 & 0x80) >> 7) & 1);
            ui8 = (uint8_t)((ui8 << 1) & 0xfe);
            i--;
        }
        ultimo_byte_nao_zero <<= 1;
        ultimo_byte_nao_zero |= (uint8_t) 1;
        i = (int)(qtd_bits & 0x7) + 1;
        while (i < 8) {
            ultimo_byte_nao_zero <<= 1;
            i++;
        }
    }
    key[pos_key++] = ultimo_byte_nao_zero;
    while (pos_key < KEY_SIZE_BYTES) {
        key[pos_key++] = 0;
    }
    pos_key = 0;
    ark6_block_key(hash, key);
    qtd_bits = 0;
    pos = 0;
    pos_key = 0;
    ui64 = 0;
    for (i = 0; i < KEY_SIZE_BYTES; i++) key[i] = 0;
    ultimo_byte_nao_zero = 0;
    ultima_posicao = 0;
    ui8 = 0;
    return hash;
}

uint8_t *
hash_256_bytes(uint8_t hash[BLOCK_SIZE_BYTES], const uint8_t *v, uint64_t qtd_bytes)
{
    uint8_t *r = hash_256_bits(hash, v, qtd_bytes << 3);
    qtd_bytes = 0;
    return r;
}

uint8_t *
hash_256_str(uint8_t hash[BLOCK_SIZE_BYTES], const char *str)
{
    return hash_256_bytes(hash, (uint8_t *) str, strlen(str));
}

/* Função auxiliar para pbkdf2 */
static uint8_t *
pbkdf2_t(uint8_t *key_parc /* com BLOCK_SIZE_BYTES */,
    const uint8_t *senha,
    int tam_senha,
    const uint8_t *salt,
    int tam_salt,
    int qtd_ciclos,
    int num_iteracao,
    uint8_t *area_aux
)
{
    int i;
    int tam_hash_ui;
    uint32_t ui32;
    uint8_t ui[2][BLOCK_SIZE_BYTES];
    int pos = 0;

#ifdef RC6_MODE
    fprintf(stderr, "\nFuncao pbkdf2_t nao deve ser usadas com RC6_MODE.\n");
    exit(1);
#endif

    for (i = 0; i < BLOCK_SIZE_BYTES; i++) key_parc[i] = 0;
    if (tam_salt > 0) {
        memcpy(area_aux, salt, tam_salt);
    }
    ui32 = num_iteracao;
    for (i = tam_salt + 3; i >= tam_salt; i--) { /* número da iteração em UINT32_BIG_ENDIAN */
        area_aux[i] = (uint8_t)(ui32 & 0xffU);
        ui32 >>= 8;
    }
    hash_256_bytes(ui[pos], area_aux, tam_salt + 4); /* Valor U0 extra */
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) key_parc[i] ^= ui[pos][i];
    pos ^= 1;
    memcpy(area_aux, senha, tam_senha);
    tam_hash_ui = tam_senha + BLOCK_SIZE_BYTES; /* tamanho das iterações U_i para i=1..qtd_ciclos */
    while (qtd_ciclos > 0) {
        memcpy(&area_aux[tam_senha], ui[pos ^ 1], BLOCK_SIZE_BYTES);
        hash_256_bytes(ui[pos], area_aux, tam_hash_ui);
        for (i = 0; i < BLOCK_SIZE_BYTES; i++) key_parc[i] ^= ui[pos][i];
        pos ^= 1;
        qtd_ciclos--;
    }
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) ui[0][i] = ui[1][i] = 0;
    pos = 0;
    tam_senha = 0;
    tam_salt = 0;
    tam_hash_ui = 0;
    ui32 = 0;
    qtd_ciclos = 0;
    return key_parc;
}

/*
Gera chave de qtd_bytes_chave com c iterações.
Usa senha de tam_senha_bytes bytes.
O valor de U0 será o hash de (salt + uint32_be(i)).
O valor de U_j é hash de (senha + U_(j-1)), para j=1..c.
O xor de todos o Uj (incluindo o 0) é Ti, e as concatenações de Ti
(para i=1..2) é a chave derivada (key).
*/
uint8_t *
pbkdf2(uint8_t *key, int qtd_bytes_chave,
    const uint8_t *senha, int tam_senha_bytes,
    const uint8_t *salt, int tam_salt,
    int c /* quantidade iterações */
)
{
    int i, j;
    uint8_t *area_aux;
    uint8_t bloco[BLOCK_SIZE_BYTES];
    int tam_aux;
    int qtd_blocos_senha;

#ifdef RC6_MODE
    fprintf(stderr, "\nFuncao pbkdf2 nao deve ser usadas com RC6_MODE.\n");
    exit(1);
#endif

    tam_aux = tam_salt + 4;
    if (tam_senha_bytes + BLOCK_SIZE_BYTES > tam_aux) {
        tam_aux = tam_senha_bytes + BLOCK_SIZE_BYTES;
    }
    area_aux = (uint8_t *) malloc(tam_aux);
    if (area_aux == NULL) {
        fprintf(stderr, "Sem memoria.\n");
        exit(1);
    }
    qtd_blocos_senha = qtd_bytes_chave / BLOCK_SIZE_BYTES;
    if (qtd_blocos_senha * BLOCK_SIZE_BYTES < qtd_bytes_chave) {
        qtd_blocos_senha++;
    }
    i = 0;
    while (i < qtd_blocos_senha) {
        pbkdf2_t(bloco, senha, tam_senha_bytes, salt, tam_salt, c, i + 1, area_aux);
        if (i != qtd_blocos_senha - 1) { /* último bloco não é copiado inteiro*/
            memcpy(&key[i * BLOCK_SIZE_BYTES], bloco, BLOCK_SIZE_BYTES);
        }
        i++;
    }
    /* ultimo bloco pode nao ser multiplo de BLOCK_SIZE_BYTES */
    i = (qtd_blocos_senha - 1) * BLOCK_SIZE_BYTES;
    j = 0;
    while (i < qtd_bytes_chave) {
        key[i] = bloco[j];
        i++;
        j++;
    }
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) bloco[i] = 0;
    for (i = 0; i < tam_aux; i++) area_aux[i] = 0;
    free (area_aux);
    j = 0;
    tam_senha_bytes = 0;
    tam_salt = 0;
    tam_aux = 0;
    qtd_bytes_chave = 0;
    c = 0;
    return key;
}

