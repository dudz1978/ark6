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

#ifndef __io_mode_h_
#define __io_mode_h_

/* #define OS_LINUX */

#include <stdbool.h>

#ifndef OS_LINUX
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#endif

#ifndef __EM_IO_C_
extern bool entrada_padrao;
extern bool saida_padrao;
extern FILE *fprint;
#endif

void binary_stdout(void);
void binary_stdin(void);

#define CHR_BEEP (7)
#define CHR_BACKSPACE (8)
#define CHR_BACKSPACE_LINUX (127) /* Linux tem um bug (ninguém me convence que */
                                  /* não é bug) que troca por 127 em vez de 8 */
#define CHR_LF (10)
#define CHR_CR (13)
#define CHR_ESC (27)

#define TAM_BUF_SENHA (65536)

#define ERRO_IO (-314159265)


/* Versão bufferizada de fgetc.
Para iniciar, chamar com o fd do arquivo.
Para resetar, chamar com NULL, ou o fd diferente do anterior.
*/
int
Fgetc(FILE *fd);

/* Versão bufferizada de fputc.
Para iniciar, chamar com o fd do arquivo.
Para resetar, chamar com NULL, ou o fd diferente do anterior.
*/
int
Fputc(int ch, FILE *fd);

uint8_t *
salt_aleatorio(uint8_t *salt, const int qtd_bytes, int argc, char *argv[], char *envp[]);

uint8_t *
le_senha(uint8_t *senha, int tam_max);

void
verifica_existencia_saida(char *nome_arq_saida);

#endif
