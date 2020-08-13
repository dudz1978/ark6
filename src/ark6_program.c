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
#include <stdbool.h>
#include <time.h>
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
criptografa_arquivo(FILE *fi, FILE *fo, char *senha_comando,
    int argc, char *argv[], char *envp[]
)
{
    int i;
    int ch;
    int pos_bloco;
    uintw_t subkeys[DOIS_R_MAIS_4];
    uint8_t salt_384[48];
    uint8_t senha[TAM_BUF_SENHA];
    uint8_t hash_senha1[BLOCK_SIZE_BYTES];
    uint8_t hash_senha2[BLOCK_SIZE_BYTES];
    uint8_t key[KEY_SIZE_BYTES];
    uint8_t bloco_out[BLOCK_SIZE_BYTES], bloco_count[BLOCK_SIZE_BYTES];
    uint64_t tam_entrada = 0;
    uint64_t qtd_tratados = 0;
    uint64_t cont_impressao = 0;
#ifdef RC6_MODE
fprintf(stderr, "Funcao criptografa_arquivo() nao deve ser usada no modo RC6.\n");
exit(1);
#endif
    
    if (senha_comando == NULL) {
        senha[0] = '\0';
        i = 0; /* marcar que nao digitou nenhuma ainda */
        do {
            if (i != 0) {
                fprintf (fprint, "\nAs senhas nao coincidem. Digite novamente.\n\n");
            }
            fprintf(fprint, "Digite a senha, com menos que %d caracteres (nao sera' exibida):\n", TAM_BUF_SENHA);
            le_senha(senha, TAM_BUF_SENHA);
            hash_256_str(hash_senha1, (char *)senha);
            fprintf(fprint, "Digite a senha novamente (nao sera' exibida):\n");
            le_senha(senha, TAM_BUF_SENHA);
            hash_256_str(hash_senha2, (char *)senha);
            for (i = 0; i < BLOCK_SIZE_BYTES; i++) {
                if (hash_senha1[i] != hash_senha2[i]) break;
            }
            if (i == BLOCK_SIZE_BYTES) i = 0;
            else i = 1; /* marcar que senhas não coincide */
        } while (i != 0); /* enquanto senhas não coincidem */
        for (i = 0; i < BLOCK_SIZE_BYTES; i++) hash_senha1[i] = hash_senha2[i] = 0;
    }
    else {
        if ((i = strlen(senha_comando) >= TAM_BUF_SENHA)) {
            fprintf(stderr, "Erro: Senha muito grande.\n");
            for (; i >= 0; i--) senha_comando[i] = 0;
            exit(1);
        }
        strcpy((char *) senha, senha_comando); /* limpar senha_comando apos coletar entropia */
    }

    /* limpar a senha do comando só depois de coletar a entropia, porque toda a linha de comando também
        é usada, junto com variáveis de ambiente.
     */
    salt_aleatorio(salt_384, 16, argc, argv, envp); /* salt aleatório inicial do arquivo, com 128 bits */
    if (senha_comando != NULL) {
        for (i = strlen(senha_comando); i >= 0; i--) senha_comando[i] = 0;
    }
    for (i = 0; i < 16; i++) {
        Fputc(salt_384[i], fo);
    }
    pbkdf2(&salt_384[16], 32, senha, strlen((char *)senha), salt_384, 16, QTD_PBKDF2);
    for (i = 0; i < 16; i++) { /* gravação 128 bits da conferência de senha */
        Fputc(salt_384[16 + i] ^ salt_384[32 + i], fo);
    }
    pbkdf2(key, KEY_SIZE_BYTES, senha, strlen((char *)senha), salt_384, 384 / 8, QTD_PBKDF2);
    for (i = TAM_BUF_SENHA-1; i >= 0; i--) senha[i] = 0;
    calcula_subkeys((uintw_t *) key, subkeys);
    for (i = 0; i < KEY_SIZE_BYTES; i++) key[i] = 0;
    hash_256_bytes(bloco_count, salt_384, 384 / 8);
    for (i = 384 / 8; i > 0; i--) salt_384[i - 1] = 0;
    pos_bloco = BLOCK_SIZE_BYTES;
    if (! entrada_padrao) {
        fseek(fi, 0, SEEK_END);
        tam_entrada = ftell(fi);
        fseek(fi, 0, SEEK_SET);
    }
    qtd_tratados = 0;
    if (! entrada_padrao) cont_impressao = tam_entrada / 100 - 1;
    else {
        fprintf(fprint, "Aguarde...");
        fflush (fprint);
    }
    for (;;) {
        ch = Fgetc(fi);
        if (ch == EOF) break;
        if (ch == ERRO_IO || (++qtd_tratados >= 0x80000000UL && !entrada_padrao)) {
            if (! entrada_padrao) fclose (fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            fi = fo = NULL;
            ch = 0;
            pos_bloco = 0;
            for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
            for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
            fprintf(stderr, "\nErro de leitura de entrada.\n");
            exit(1);
        }
        if (pos_bloco == BLOCK_SIZE_BYTES) {
            pos_bloco = 0;
            ark6_output_block_subkeys(bloco_out, bloco_count, subkeys);
            incrementa_contador(bloco_count);
        }
        if (Fputc((ch ^ bloco_out[pos_bloco]) & 0xffU, fo) == ERRO_IO) {
            if (! entrada_padrao) fclose (fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            fi = fo = NULL;
            ch = 0;
            pos_bloco = 0;
            for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
            for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
            fprintf(stderr, "\nErro de gravacao da saida.\n");
            exit(1);
        }
        pos_bloco++;
        if (! entrada_padrao) {
            if (cont_impressao-- == 0) {
                fprintf(fprint, "\r%d%%", (int)(100.0 * qtd_tratados / tam_entrada));
                fflush(fprint);
                cont_impressao = tam_entrada / 100 - 1;
            }
        }
    }
    if (! entrada_padrao) fprintf(fprint, "\r100%%\n");
    else fprintf (fprint, " feito!\n");
    (void) Fputc(0, NULL); /* flush do que está no buffer */
    fflush(fo);
    fi = fo = NULL;
    ch = 0;
    pos_bloco = 0;
    for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
    for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
}

void
descriptografa_arquivo(FILE *fi, FILE *fo, char *senha_comando, bool modo_teste)
{
    int i;
    int ch;
    int pos_bloco;
    uint64_t tam_entrada = 0;
    uint64_t qtd_tratados;
    uint64_t cont_impressao = 0;
    uint8_t salt_inicial[BLOCK_SIZE_BYTES];
    uint8_t bytes_conferencia[BLOCK_SIZE_BYTES];
    uint8_t bytes_conferencia_calculados[2 * BLOCK_SIZE_BYTES];
    uintw_t subkeys[DOIS_R_MAIS_4];
    uint8_t salt_384[3 * BLOCK_SIZE_BYTES];
    uint8_t senha[TAM_BUF_SENHA];
    uint8_t key[KEY_SIZE_BYTES];
    uint8_t bloco_out[BLOCK_SIZE_BYTES], bloco_count[BLOCK_SIZE_BYTES];

#ifdef RC6_MODE
    fprintf(stderr, "Funcao descriptografa_arquivo() nao deve ser usada no modo RC6.\n");
    exit(1);
#endif
    if (! entrada_padrao) {
        fseek(fi, 0, SEEK_END);
        tam_entrada = ftell(fi);
        fseek(fi, 0, SEEK_SET);
        if (tam_entrada <= 32) { /* salt (128) e conferencia (128) */
            tam_entrada = 0;
        }
    }

    for (i = 0; i < 16; i++) {
        salt_inicial[i] = (uint8_t) (Fgetc(fi) & 0xffU);
    }
    for (i = 0; i < 16; i++) {
        bytes_conferencia[i] = (uint8_t) (Fgetc(fi) & 0xffU);
    }

    if (senha_comando == NULL) {
        for(;;) {
            senha[0] = '\0';
            fprintf(fprint, "Digite a senha (menos que %d caracteres). A senha nao sera' exibida:\n", TAM_BUF_SENHA);
            le_senha(senha, TAM_BUF_SENHA);
            pbkdf2(bytes_conferencia_calculados, 32, senha, strlen((char *) senha),
                salt_inicial, 16, QTD_PBKDF2
            );
            i = 0;
            while (i < 16) {
                if (bytes_conferencia[i] !=
                    (bytes_conferencia_calculados[i] ^ bytes_conferencia_calculados[i + 16])
                ) break;
                i++;
            }
            if (i == 16) break;
            fprintf (fprint, "SENHA INCORRETA.\n");
        }
        if (modo_teste) {
            for (i = TAM_BUF_SENHA-1; i >= 0; i--) senha[i] = 0;
            for (i = 0; i < 32; i++) bytes_conferencia_calculados[i] = 0;
            if (! entrada_padrao) fclose(fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            fprintf(fprint, "Senha correta!\n");
            exit(0);
        }
    }
    else {
        if ((i = strlen(senha_comando) >= TAM_BUF_SENHA)) {
            fprintf(stderr, "Erro: Senha muito grande.\n");
            for (; i >= 0; i--) senha_comando[i] = 0;
            if (! entrada_padrao) fclose(fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            exit(1);
        }
        strcpy((char *) senha, senha_comando);
        for (; i >= 0; i--) senha_comando[i] = 0;
        pbkdf2(bytes_conferencia_calculados,32,senha,strlen((char *)senha),salt_inicial,16,QTD_PBKDF2);
        i = 0;
        while (i < 16) {
            if (bytes_conferencia[i] !=
                (bytes_conferencia_calculados[i] ^ bytes_conferencia_calculados[i + 16])
            ) break;
            i++;
        }
        if (i != 16) {
            fprintf (fprint, "SENHA INCORRETA.\n");
            if (! entrada_padrao) fclose(fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            exit(1);
        }
        else if (modo_teste) {
            for (i = TAM_BUF_SENHA-1; i >= 0; i--) senha[i] = 0;
            for (i = 0; i < 32; i++) bytes_conferencia_calculados[i] = 0;
            if (! entrada_padrao) fclose(fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            fprintf(fprint, "Senha correta!\n");
            exit(0);
        }
    }

    memcpy (salt_384, salt_inicial, 16);
    memcpy (&salt_384[16], bytes_conferencia_calculados, 2 * 16);
    for (i = 0; i < 2 * BLOCK_SIZE_BYTES; i++) bytes_conferencia_calculados[i] = 0;
    pbkdf2(key, KEY_SIZE_BYTES, senha, strlen((char *)senha),
        salt_384, 384 / 8, QTD_PBKDF2
    );
    for (i = TAM_BUF_SENHA-1; i >= 0; i--) senha[i] = 0;
    calcula_subkeys((uintw_t *) key, subkeys);
    for (i = 0; i < KEY_SIZE_BYTES; i++) key[i] = 0;
    hash_256_bytes(bloco_count, salt_384, 384 / 8);
    for (i = 384 / 8; i > 0; i--) salt_384[i - 1] = 0;
    pos_bloco = BLOCK_SIZE_BYTES;
    qtd_tratados = 0;
    if (! entrada_padrao) cont_impressao = tam_entrada / 100 - 1;
    else {
        fprintf(fprint, "Aguarde...");
        fflush(fprint);
    }
    for (;;) {
        ch = Fgetc(fi);
        if (ch == EOF) break;
        if (ch == ERRO_IO || (++qtd_tratados >= 0x80000000UL && !entrada_padrao)) {
            if (! entrada_padrao) fclose (fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            fi = fo = NULL;
            ch = 0;
            pos_bloco = 0;
            for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
            for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
            fprintf(stderr, "\nErro de leitura de entrada.\n");
            exit(1);
        }
        if (pos_bloco == BLOCK_SIZE_BYTES) {
            pos_bloco = 0;
            ark6_output_block_subkeys(bloco_out, bloco_count, subkeys);
            incrementa_contador(bloco_count);
        }
        if (Fputc((ch ^ bloco_out[pos_bloco]) & 0xffU, fo) == ERRO_IO) {
            if (! entrada_padrao) fclose (fi);
            if (! saida_padrao && fo != NULL) fclose(fo);
            fi = fo = NULL;
            ch = 0;
            pos_bloco = 0;
            for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
            for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
            fprintf(stderr, "\nErro de gravacao da saida.\n");
            exit(1);
        }
        pos_bloco++;
        if (! entrada_padrao) {
            if (cont_impressao-- == 0) {
                fprintf(fprint, "\r%d%%", (int)(100.0 * qtd_tratados / tam_entrada));
                fflush(fprint);
                cont_impressao = tam_entrada / 100 - 1;
            }
        }
    }
    if (! entrada_padrao) fprintf(fprint, "\r100%%\n");
    else fprintf(fprint, " feito!\n");
    (void) Fputc(0, NULL); /* flush do que está no buffer */
    fflush(fo);
    fi = fo = NULL;
    ch = 0;
    pos_bloco = 0;
    for (i = 0; i < DOIS_R_MAIS_4; i++) subkeys[i] = 0;
    for (i = BLOCK_SIZE_BYTES; i > 0; i--) bloco_out[i-1] = bloco_count[i-1] = 0;
}



int
main(int argc, char *argv[], char *envp[])
{
    FILE *fi;
    FILE *fo;
    bool modo_teste = false;

    (void) clock(); /* para iniciar contador e coletar entropia */

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
    exit(0);
    //*/

    if (
        argc < 2
        || argv[1][0] != '-'
        || (argv[1][1] != 'c' && argv[1][1] != 'd' && argv[1][1] != 't')
        || (argv[1][1] != 't' && (argc != 4 && argc != 5))
        || (argv[1][1] == 't' && (argc != 3 && argc != 4))
        || (argv[1][1] != 't' && strcmp(argv[2], argv[3]) == 0)
    ) {
        printf (
                "Sintaxe:\n"
                "       cifrar: ark6 -c arq_entrada_legivel.ext arq_saida_cifrado.ext [senha]\n"
                "     decifrar: ark6 -d arq_entrada_cifrado.ext arq_saida_decifrado_legivel.ext [senha]\n"
                " testar senha: ark6 -t arq_entrada_cifrado.ext [senha]\n"
                "Para usar entrada/saida padroes, usar --stdin e/ou\n"
                "--stdout no lugar dos nomes dos arquivos.\n"
                "Se a entrada for stdin, e' obrigatorio informar a senha no comando.\n"
        );
        printf("\nPressione Enter...");
        fflush (stdout);
        (void) getchar();
        exit(0);
    }

    if (strcmp(argv[2], "--stdin") != 0) {
        entrada_padrao = false;
        fi = fopen(argv[2], "rb");
        if (fi == NULL) {
            fprintf (stderr, "Erro ao abrir arquivo de entrada.\n");
            exit (1);
        }
    }
    else {
        entrada_padrao = true;
        if (
            (argv[1][1] != 't' && argc < 5)
            || (argv[1][1] == 't' && argc < 4)
        ) {
            fprintf(stderr, "Entrada stdin precisa da senha na linha de comando.\n");
            exit(1);
        }
        binary_stdin();
        fi = stdin;
    }

    if (argv[1][1] != 't') {
        modo_teste = false;
        if (strcmp(argv[3], "--stdout") != 0) {
            saida_padrao = false;
            fprint = stdout;
            verifica_existencia_saida(argv[3]);
            fo = fopen(argv[3], "wb");
            if (fo == NULL) {
                if (! entrada_padrao) fclose(fi);
                fprintf (stderr, "Erro ao criar arquivo de saida.\n");
                exit (1);
            }
        }
        else {
            saida_padrao = true;
            fprint = stderr;
            binary_stdout();
            fo = stdout;
            if (fo == NULL) {
                if (! entrada_padrao) fclose(fi);
                fprintf (stderr, "Erro ao configurar saida padrao.\n");
                exit (1);
            }
        }
    }
    else {
        saida_padrao = false;
        fprint = stdout;
        modo_teste = true;
        fo = NULL;
    }

    if (argv[1][1] == 'c') {
        criptografa_arquivo(fi, fo, argc < 5 ? NULL : argv[4], argc, argv, envp);
    }
    else if (argv[1][1] == 'd') {
        descriptografa_arquivo(fi, fo, argc < 5 ? NULL : argv[4], modo_teste);
    }
    else if (argv[1][1] == 't') {
        descriptografa_arquivo(fi, fo, argc < 4 ? NULL : argv[3], modo_teste);
    }

    fprintf(fprint, "Fim normal.\n");
    if (! saida_padrao && fo != NULL) fclose (fo);
    if (! entrada_padrao) fclose(fi);

    return 0;
}
