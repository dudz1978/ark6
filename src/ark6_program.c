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
#include "include/io.h"
#include "include/ark6_constants.h"
#include "include/ark6_functions.h"
#include "include/hash_functions.h"

void
incrementa_contador(uint8_t bloco_count[BLOCK_SIZE_BYTES])
{
    int i;
    i = BLOCK_SIZE_BYTES - 1;
    while (i >= 0) {
        if (bloco_count[i] < 0xffU) {
            bloco_count[i]++;
            return;
        }
        bloco_count[i] = 0;
        i--;
    }
}

void
criptografa_arquivo(const char *nome_arq, const char *nome_saida)
{
    int i;
    FILE *fi;
    FILE *fo;
    int ch;
    int pos_bloco;
    uint32_t subkeys[DOIS_R_MAIS_4];
    uint8_t salt_384[3 * BLOCK_SIZE_BYTES];
    uint8_t senha[1024], senha2[1024];
    uint8_t key[KEY_SIZE_BYTES];
    uint8_t bloco_out[BLOCK_SIZE_BYTES], bloco_count[BLOCK_SIZE_BYTES];
    uint32_t tam_entrada;
    uint32_t qtd_tratados;
    uint32_t cont_impressao;
    fi = fopen(nome_arq, "rb");
    if (fi == NULL) {
        fprintf (stderr, "Erro ao abrir arquivo de entrada.\n");
        exit (1);
    }
    fo = fopen(nome_saida, "wb");
    if (fo == NULL) {
        fclose(fi);
        fprintf (stderr, "Erro ao criar arquivo de saida.\n");
        exit (1);
    }
    
    senha[0] = '\0';
    senha2[0] = '\0';
    do {
        if (senha[0] != '\0' || senha2[0] != '\0') {
            printf ("\nAs senhas nao coincidem. Digite novamente.\n\n");
            senha[0] = '\0';
            senha2[0] = '\0';
        }
        printf("Digite a senha, com menos que 1024 caracteres (nao sera' exibida):\n");
        le_senha(senha, 1024 - 1);
        printf("Digite a senha novamente (nao sera' exibida):\n");
        le_senha(senha2, 1024 - 1);
    } while (strcmp((char *)senha, (char *)senha2) != 0);
    for (i = 1024-1; i >= 0; i--) senha2[i] = 0;

    salt_aleatorio(salt_384, BLOCK_SIZE_BYTES);
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
        Fputc(salt_384[i], fo);
    }
    pbkdf2(&salt_384[BLOCK_SIZE_BYTES], 2, senha, strlen((char *)senha), salt_384, BLOCK_SIZE_BYTES, QTD_PBKDF2);
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
        Fputc(salt_384[BLOCK_SIZE_BYTES + i] ^ salt_384[2 * BLOCK_SIZE_BYTES + i], fo);
    }
    pbkdf2(key, KEY_SIZE_BYTES / BLOCK_SIZE_BYTES, senha, strlen((char *)senha), salt_384, 384 / 8, QTD_PBKDF2);
    for (i = 1024-1; i >= 0; i--) senha[i] = 0;
    calcula_subkeys((uint32_t *) key, subkeys);
    for (i = 0; i < KEY_SIZE_BYTES; i++) key[i] = 0;
    hash_128_bytes(bloco_count, salt_384, 384 / 8);
    for (i = 3 * BLOCK_SIZE_BYTES; i > 0; i--) salt_384[i - 1] = 0;
    pos_bloco = BLOCK_SIZE_BYTES;
    fseek(fi, 0, SEEK_END);
    tam_entrada = ftell(fi);
    fseek(fi, 0, SEEK_SET);
    qtd_tratados = 0;
    cont_impressao = tam_entrada / 100 - 1;
    for (;;) {
        ch = Fgetc(fi);
        if (ch == EOF) break;
        if (pos_bloco == BLOCK_SIZE_BYTES) {
            pos_bloco = 0;
            ark6_output_block_subkeys(bloco_out, bloco_count, subkeys);
            incrementa_contador(bloco_count);
        }
        Fputc((ch ^ bloco_out[pos_bloco]) & 0xffU, fo);
        pos_bloco++;
        qtd_tratados++;
        if (cont_impressao-- == 0) {
            printf("\r%d%%", (int)(100.0 * qtd_tratados / tam_entrada));
            fflush(stdout);
            cont_impressao = tam_entrada / 100 - 1;
        }
    }
    printf("\r100%%\n");
    Fputc(0, NULL); /* flush do que está no buffer */
    fflush(fo);
    fclose (fo);
    fclose(fi);
    fi = fo = NULL;
    ch = 0;
    pos_bloco = 0;
    for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
    for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
}

void
descriptografa_arquivo(const char *nome_arq, const char *nome_saida)
{
    int i;
    FILE *fi;
    FILE *fo;
    int ch;
    int pos_bloco;
    uint32_t tam_entrada;
    uint32_t qtd_tratados;
    uint32_t cont_impressao;
    uint8_t salt_inicial[BLOCK_SIZE_BYTES];
    uint8_t bytes_conferencia[BLOCK_SIZE_BYTES];
    uint8_t bytes_conferencia_calculados[2 * BLOCK_SIZE_BYTES];
    uint32_t subkeys[DOIS_R_MAIS_4];
    uint8_t salt_384[3 * BLOCK_SIZE_BYTES];
    uint8_t senha[1024];
    uint8_t key[KEY_SIZE_BYTES];
    uint8_t bloco_out[BLOCK_SIZE_BYTES], bloco_count[BLOCK_SIZE_BYTES];
    fi = fopen(nome_arq, "rb");
    if (fi == NULL) {
        fprintf (stderr, "Erro ao abrir arquivo de entrada.\n");
        exit (1);
    }
    fo = fopen(nome_saida, "wb");
    if (fo == NULL) {
        fclose(fi);
        fprintf (stderr, "Erro ao criar arquivo de saida.\n");
        exit (1);
    }
    
    fseek(fi, 0, SEEK_END);
    tam_entrada = ftell(fi);
    fseek(fi, 0, SEEK_SET);
    if (tam_entrada <= 2 * BLOCK_SIZE_BYTES) {
        tam_entrada = 0;
    }

    for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
        salt_inicial[i] = (uint8_t) (Fgetc(fi) & 0xffU);
    }
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
        bytes_conferencia[i] = (uint8_t) (Fgetc(fi) & 0xffU);
    }

    for(;;) {
        senha[0] = '\0';
        printf("Digite a senha (menos que 1024 caracteres). A senha nao sera' exibida:\n");
        le_senha(senha, 1024 - 1);
        pbkdf2(bytes_conferencia_calculados, 2, senha, strlen((char *) senha),
            salt_inicial, BLOCK_SIZE_BYTES,QTD_PBKDF2
        );
        i = 0;
        while (i < BLOCK_SIZE_BYTES) {
            if (bytes_conferencia[i] !=
                (bytes_conferencia_calculados[i] ^ bytes_conferencia_calculados[i + BLOCK_SIZE_BYTES])
            ) break;
            i++;
        }
        if (i == BLOCK_SIZE_BYTES) break;
        printf ("SENHA INCORRETA.\n");
    }

    memcpy (salt_384, salt_inicial, BLOCK_SIZE_BYTES);
    memcpy (&salt_384[BLOCK_SIZE_BYTES], bytes_conferencia_calculados, 2 * BLOCK_SIZE_BYTES);
    for (i = 0; i < 2 * BLOCK_SIZE_BYTES; i++) bytes_conferencia_calculados[i] = 0;
    pbkdf2(key, KEY_SIZE_BYTES / BLOCK_SIZE_BYTES, senha, strlen((char *)senha),
        salt_384, 384 / 8, QTD_PBKDF2
    );
    for (i = 1024-1; i >= 0; i--) senha[i] = 0;
    calcula_subkeys((uint32_t *) key, subkeys);
    for (i = 0; i < KEY_SIZE_BYTES; i++) key[i] = 0;
    hash_128_bytes(bloco_count, salt_384, 384 / 8);
    for (i = 3 * BLOCK_SIZE_BYTES; i > 0; i--) salt_384[i - 1] = 0;
    pos_bloco = BLOCK_SIZE_BYTES;
    qtd_tratados = 0;
    cont_impressao = tam_entrada / 100 - 1;
    for (;;) {
        ch = Fgetc(fi);
        if (ch == EOF) break;
        if (pos_bloco == BLOCK_SIZE_BYTES) {
            pos_bloco = 0;
            ark6_output_block_subkeys(bloco_out, bloco_count, subkeys);
            incrementa_contador(bloco_count);
        }
        Fputc((ch ^ bloco_out[pos_bloco]) & 0xffU, fo);
        pos_bloco++;
        qtd_tratados++;
        if (cont_impressao-- == 0) {
            printf("\r%d%%", (int)(100.0 * qtd_tratados / tam_entrada));
            fflush(stdout);
            cont_impressao = tam_entrada / 100 - 1;
        }
    }
    printf("\r100%%\n");
    Fputc(0, NULL); /* flush do que está no buffer */
    fflush(fo);
    fclose(fo);
    fclose(fi);
    fi = fo = NULL;
    ch = 0;
    pos_bloco = 0;
    for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
    for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
}



int
main(int argc, char *argv[])
{
    /* Teste padrão se RC6(w=32,r=20,b=32) está ok
    int i;
    uint8_t text[BLOCK_SIZE_BYTES];
    uint8_t key[KEY_SIZE_BYTES];
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) text[i] = 0;
    for (i = 0; i < KEY_SIZE_BYTES; i++) key[i] = 0;
    ark6_block_key(text, key);
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) printf("%02x ", text[i]);
    putchar('\n');
    for (i = 0; i < BLOCK_SIZE_BYTES; i++) printf("%02x", text[i]);
    putchar('\n');
    //*/

    if (argc != 4 || argv[1][0] != '-' || (argv[1][1] != 'c' && argv[1][1] != 'd')
        || strcmp(argv[2], argv[3]) == 0
    ) {
        printf (
                "Sintaxe:\n"
                "       cifrar: ark6 -c arq_entrada_legivel.ext arq_saida_cifrado.ext\n"
                "     decifrar: ark6 -d arq_entrada_cifrado.ext arq_saida_decifrado_legivel.ext\n"
        );
        printf("\nPressione Enter...");
        fflush (stdout);
        (void) getchar();
        exit(0);
    }
    verifica_existencia_saida(argv[3]);
    if (argv[1][1] == 'c') {
        criptografa_arquivo(argv[2], argv[3]);
    }
    else if (argv[1][1] == 'd') {
        descriptografa_arquivo(argv[2], argv[3]);
    }

    printf("Fim normal.\n");

    return 0;
}
