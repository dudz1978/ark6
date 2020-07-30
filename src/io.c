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
#include <time.h>
#include <stdint.h>
#include "include/io.h"
#include "include/ark6_constants.h"
#include "include/hash_functions.h"

#ifndef OS_LINUX
#include <conio.h>
#else
#include <termios.h>
/* Le caracter sem exibir e sem bufferização do conteúdo. */
int getch(void) 
{
    static struct termios old, current;
    int ch;
    tcgetattr(0, &old); /* grab old terminal i/o settings */
    current = old; /* make new settings same as old settings */
    current.c_lflag &= ~ICANON; /* disable buffered i/o */
    /* current.c_lflag |= ECHO; / * set echo mode */
    current.c_lflag &= ~ECHO; /* set no echo mode */
    tcsetattr(0, TCSANOW, &current); /* use these new terminal i/o settings now */
    ch = getchar();
    tcsetattr(0, TCSANOW, &old);
    return ch;
}
#endif


/* Versão bufferizada de fgetc.
Para iniciar, chamar com o fd do arquivo.
Para resetar, chamar com NULL, ou o fd diferente do anterior.
*/
int
Fgetc(FILE *fd)
{
    static FILE *fd_ = NULL;
    static uint32_t tam_arq = 0;
    static uint32_t pos_atu = 0;
    static uint8_t buf[4096];
    static int pos_buf = 4096;
    static int limite = 4096;
    int i;

    if (fd == NULL) {
        if (fd_ != NULL && pos_buf != limite) {
            fseek(fd, pos_atu - (limite - pos_buf), SEEK_SET);
        }
        fd_ = NULL;
        tam_arq = 0;
        pos_atu = 0;
        pos_buf = 4096;
        limite = 4096;
        for (i = 0; i < 4096; i++) buf[i] = 0;  
        return EOF;
    }
    if (fd != fd_) (void) Fgetc(NULL);
    if (fd_ == NULL) {
        fd_ = fd;
        pos_atu = ftell(fd);
        fseek(fd, 0, SEEK_END);
        tam_arq = ftell(fd);
        fseek(fd, pos_atu, SEEK_SET);
    }
    if (pos_buf == limite) {
        if (pos_atu >= tam_arq) {
            return EOF;
        }
        pos_buf = 0;
        if (pos_atu + 4096 <= tam_arq) {
            (void) fread(buf, 4096, 1, fd);
            pos_atu += 4096;
            limite = 4096;
        }
        else {
            limite = tam_arq - pos_atu;
            (void) fread(buf, limite, 1, fd);
            pos_atu += limite;
        }
    }
    pos_buf++;
    return (int) buf[pos_buf - 1];
}

/* Versão bufferizada de fputc.
Para iniciar, chamar com o fd do arquivo.
Para resetar, chamar com NULL, ou o fd diferente do anterior.
*/
void
Fputc(int ch, FILE *fd)
{
    static FILE *fd_ = NULL;
    static uint8_t buf[4096];
    static int pos_buf = 0;
    int i;

    if (fd == NULL) {
        if (fd_ != NULL && pos_buf > 0) {
            fwrite(buf, pos_buf, 1, fd_);
            fflush(fd_);
        }
        fd_ = NULL;
        pos_buf = 0;
        for (i = 0; i < 4096; i++) buf[i] = 0;  
        return;
    }
    if (fd != fd_) (void) Fputc(0, NULL);
    if (fd_ == NULL) {
        fd_ = fd;
        pos_buf = 0;
    }
    buf[pos_buf] = (uint8_t)(ch & 0xffU);
    pos_buf++;
    if (pos_buf == 4096) {
        fwrite(buf, pos_buf, 1, fd);
        pos_buf = 0;
    }
}

uint8_t *
salt_aleatorio(uint8_t *salt, const int qtd_bytes)
{
    int i;
    int ch;
    uint8_t *salt_ant;
    if (qtd_bytes < 1 || qtd_bytes % BLOCK_SIZE_BYTES != 0) {
        fprintf(stderr, "Erro: salt deve ter tamanho multiplo de %d\n", BLOCK_SIZE_BYTES);
        exit (1);
    }
    salt_ant = (uint8_t *) malloc(qtd_bytes);
    if (salt_ant == NULL) {
        fprintf (stderr, "Sem memoria em salt_aleatorio().\n");
        exit (1);
    }
    for (i = 0; i < qtd_bytes; i++) salt[i] = 0;
    printf("Digite aleatoriamente para coletar entropia do salt, e ESC para terminar...\n");

    i = 0;
    for (;;) {
        ch = getch();
        if (ch == CHR_ESC) break;
        salt[i] ^= (uint8_t) (ch & 0xffU);
        i++;
        if (i == qtd_bytes) {
            i = 0;
            memcpy(salt_ant, salt, qtd_bytes);
            pbkdf2(salt, qtd_bytes / BLOCK_SIZE_BYTES, salt_ant, qtd_bytes, NULL, 0, 1);
        }
    }
    memcpy(salt_ant, salt, qtd_bytes);
    pbkdf2(salt, qtd_bytes / BLOCK_SIZE_BYTES, salt_ant, qtd_bytes, NULL, 0, 1);
    for (i = 0; i < qtd_bytes; i++) salt_ant[i] = 0;
    free(salt_ant);
    ch = 0;
    i = 0;
    return salt;
}

uint8_t *
le_senha(uint8_t *senha, int tam_buf)
{
    int ch;
    int i;
    i = 0;
    for(;;) {
        ch = getch();
        if (ch < 0 || ch == CHR_ESC) {
            while (i >= 0) senha[i--] = 0;
            ch = 0;
            printf("Execucao cancelada.\n");
            exit(0);
        }
        if (ch == CHR_CR || ch == CHR_LF) break;
        if (ch == CHR_BACKSPACE && i > 0) {
            i--;
            senha[i] = '\0';
            continue;
        }
        if (ch < ' ') continue;
        if (i >= tam_buf - 1) {
            printf("%c", CHR_BEEP);
            fflush(stdout);
            continue;
        }
        senha[i] = (uint8_t) (ch & 0xffU);
        i++;
    }
    senha[i] = '\0';
    ch = i = 0;
    tam_buf = 0;
    return senha;
}

void
verifica_existencia_saida(char *nome_arq_saida)
{
    FILE *fd;
    int a, b, soma;
    char resposta[128];

    fd = fopen(nome_arq_saida, "rb");
    if (fd == NULL) return;
    fclose (fd);
    printf(
        "Arquivo de saida\n'%s'\n"
        "ja' existe. Digite o resultado se quiser\n"
        "sobrescreve-lo, ou Enter para cancelar.\n",
        nome_arq_saida
    );
    srand((unsigned int) time(NULL));
    do {
        a = (rand() % 79) + 21;
    } while (a % 10 == 0);
    do {
        b = (rand() % 79) + 21;
    } while (b == a || b % 10 == 0);
    printf ("%d + %d = ", a, b);
    fflush(stdout);
    soma = a + b;
    fgets(resposta, 127, stdin);
    if (atoi(resposta) != soma) {
        printf("Execucao interrompida.\n");
        exit(0);
    }
}

/*
https://stackoverflow.com/questions/7469139/what-is-the-equivalent-to-getch-getche-in-linux

#include <termios.h>
#include <stdio.h>

static struct termios old, current;

\* Initialize new terminal i/o settings *\
void initTermios(int echo) 
{
  tcgetattr(0, &old); \* grab old terminal i/o settings *\
  current = old; \* make new settings same as old settings *\
  current.c_lflag &= ~ICANON; \* disable buffered i/o *\
  if (echo) {
      current.c_lflag |= ECHO; \* set echo mode *\
  } else {
      current.c_lflag &= ~ECHO; \* set no echo mode *\
  }
  tcsetattr(0, TCSANOW, &current); \* use these new terminal i/o settings now *\
}

\* Restore old terminal i/o settings *\
void resetTermios(void) 
{
  tcsetattr(0, TCSANOW, &old);
}

\* Read 1 character - echo defines echo mode *\
char getch_(int echo) 
{
  char ch;
  initTermios(echo);
  ch = getchar();
  resetTermios();
  return ch;
}

\* Read 1 character without echo *\
char getch(void) 
{
  return getch_(0);
}

\* Read 1 character with echo *\
char getche(void) 
{
  return getch_(1);
}


*/

