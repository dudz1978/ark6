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

#ifndef __ark6_constants_h_
#define __ark6_constants_h_

/* #define RC6_MODE / * modo compatível com RC6(32,20,32), proposto para AES-256 */



#define QTD_PBKDF2 (16384)

#define W (32)
#define NIBBLE_SIZE (W >> 1)
#define B (32)

#define BLOCK_SIZE_BITS (128)
#define BLOCK_SIZE_BYTES (BLOCK_SIZE_BITS >> 3)
#define BLOCK_SIZE_WORDS (BLOCK_SIZE_BITS / W)


#ifndef RC6_MODE
#define KEY_SIZE_BITS (512)
#define P ((uint32_t) 0x90fdaa23) /* bits de pi (deslocado para usar 32 bits) */
#define Q ((uint32_t) 0xd413cccf) /* bits de sqrt(2) (deslocado para usar 32 bits) */
#define R (40)
#else
#define KEY_SIZE_BITS (256)
#define P ((uint32_t) 0xb7e15163) /* bits de e (número de Euler) */
#define Q ((uint32_t) 0x9e3779b9) /* bits da razão áurea */
#define R (20)
#endif

#define KEY_SIZE_BYTES (KEY_SIZE_BITS >> 3)
#define KEY_SIZE_WORDS (KEY_SIZE_BITS / W)
#define C KEY_SIZE_WORDS

#define DOIS_R_MAIS_4 (2 * R + 4)
#define V (3 * DOIS_R_MAIS_4) /* V = 3 * max(C, DOIS_R_MAIS_4) */

#endif
