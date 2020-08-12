
# Ark6

Ark6 é um algoritmo de criptografia simétrica baseado numa variação do algoritmo
[RC6](https://en.wikipedia.org/wiki/RC6), e foi desenhado com a intenção de
ser mais seguro, apesar de mais lento.

Como o algoritmo RC6 já tem mais de vinte anos, a perda de performance
acaba sendo compensada por máquinas mais rápidas que
as da época da criação do RC6.


## Licença de uso

Tanto o algoritmo Ark6 quanto sua implementação no programa ark6 estão
sendo disponibilizados em domínio público, sem **nenhuma** garantia por
parte do autor ou possibilidade de qualquer responsabiliação
do mesmo, conforme [unlicense.org](https://unlicense.org/),
ainda que haja aviso prévio sobre erros de implementação,
incorreções, falhas de segurança ou qualquer outro problema
com o conteúdo:

```
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
```

Para os casos em que forem necessários uma licença real para uso
do código ou algoritmo, está sendo disponibilizada adicionalmente a licença
MIT, também sem quaisquer garantias:


```
Copyright (c) 2020 José Eduardo Gaboardi de Carvalho <edu.a1978@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```


## Características do Ark6 comparadas com as do RC6

Este comparação é da versão do RC6 proposta na
[competição para AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard_process)


| Característica    |  Ark6           | RC6              |
|------------------:|:---------------:|:----------------:|
| Tamanho da chave  | 512 bits        | 128/192/256 bits |
| Tamanho do bloco  | 256 bits        | 128 bits         |
| Número de rounds  | 40              | 20               |
| Tamanho variáveis | 64 bits         | 32 bits          |
| Constante P       | bits de π       | bits de *e*      |
| Constante Q       | bits de sqrt(2) | bits de φ        |

As constantes são obtidas da mesma forma do RC6, pegando os bits após o ponto
decimal e arredondando para o número inteiro ímpar mais próximo, porém com a
diferença de começar a partir do primeiro bit 1 após o ponto decimal, já que
as constantes do Ark6 são menores que 0,5. A proposta do algoritmo
RC6 já mencionava a possibilidade de se usar constantes diferentes
em implementações customizadas.


## Passo de segurança adicional

O algoritmo Ark6 contém uma transformação adicional T, descrita em

*Uma versão mais forte do algoritmo RC6 contra criptanálise χ²* (Ueda, E. T., Terada, R., 2007)

A transformação T consiste na troca da primeira com a segunda metade
das variáveis
B e D no início de cada iteração, caso o número de bits 1 da
variável seja ímpar.

## Derivação das sub-chaves

A derivação das 84 sub-chaves é feita a partir dos 512 bits da chave,
da mesma forma que no RC6, porém com constantes P e Q diferentes.

## Pseudo-código

### Operações

Todas as operações são em variáveis inteiras não-sinalizadas de 64 bits.

- x + y: soma de duas variáveis, mod 2^64do bits
- rotE(x, n): rotação de n bits para esquerda dos bits da variável x
- x * y: multiplicação de duas variáveis, mod 2^64
- x ^ y: ou-exclusivo ([xor](https://en.wikipedia.org/wiki/Exclusive_or)) de duas variávels
- x % y: resto de divisão ([mod](https://en.wikipedia.org/wiki/Modulo_operation)) de x por y
- x / y: divisão inteira de x por y, desprezando a parte após ponto decimal
- x ** y: exponenciação de x elevado a y

### Derivação das sub-chaves

```
Entrada: Chave de 64 bytes
c[0 ... 63]

Saída: Sub-chaves S[0 ... 83]

Procedimento:

const P := 0x90fdaa22168c234d
const Q := 0xd413cccfe7799211
Para i = 0 ... 7, faça:
    L[i] := 0
    Para j = 7 ... 0, passo -1, faça:
        L[i] := L[i] * 256 + c[i * 8 + j]
    Fim-Para
Fim-Para
S[0] := P
Para i = 1 ... 83, faça:
    S[i] := S[i - 1] + Q
Fim-Para
A := 0
B := 0
i := 0
j := 0
Para s = 1 ... 252, faça:
    S[i] := rotE(S[i] + A + B, 3)
    A := S[i]
    L[j] := rotE(L[j] + A + B, (A + B) % 64)
    B := L[j]
    i := (i + 1) % 84
    j := (j + 1) % 8
Fim-Para
```

### Função de transformação T

```
Entrada: n

Saída: m

Função:

p := 0
n2 := n
Enquanto n2 > 0, faça:
    p := p ^ (n2 % 2)
    n2 := n2 / 2
Fim-Enquanto
Se p = 1, então:
    m = rotE(n, 32)
Senão:
    m = n
Fim-Se
Devolva m
```

### Rotina do algoritmo Ark6

```
Entrada: 32 bytes de texto legível
a0 a1 a2 a3 a4 a5 a6 a7 b0 b1 b2 b3 b4 b5 b6 b7 c0 c1 c2 c3 c4 c5 c6 c7 d0 d1 d2 d3 d4 d5 d6 d7
84 variáveis de 64 bits, das sub-chaves derivada em um array S[0 ... 83]

Saída: 32 bytes de texto cifrado
A0 A1 A2 A3 A4 A5 A6 A7 B0 B1 B2 B3 B4 B5 B6 B7 C0 C1 C2 C3 C4 C5 C6 C7 D0 D1 D2 D3 D4 D5 D6 D7

Procedimento:

A := a0 * (256 ** 0) + a1 * (256 ** 1) + ... + a7 * (256 ** 7)
B := b0 * (256 ** 0) + b1 * (256 ** 1) + ... + b7 * (256 ** 7)
C := c0 * (256 ** 0) + c1 * (256 ** 1) + ... + c7 * (256 ** 7)
D := d0 * (256 ** 0) + d1 * (256 ** 1) + ... + d7 * (256 ** 7)

B := B + S[0]
D := D + S[1]
Para i = 1 ... 40, faça:
    B := T(B)
    D := T(D)
    x := rotE(B * (2 * B + 1), 6)
    y := rotE(D * (2 * D + 1), 6)
    A := rotE(A ^ x, y % 64) + S[2 * i]
    C := rotE(C ^ y, x % 64) + S[2 * i + 1]
    x := A
    A := B
    B := C
    C := D
    D := x
Fim-para
A := A + S[82]
C := C + S[83]
Para cada uma das variáveis de saída Wi (onde W é uma das variáveis entre
{A,B,C,D} e i = 0 .. 7), atribuir o valor
Wi := W / (256 ** i) % 256
```

## Programa ark6

O programa ark6 é uma implementação do algoritmo Ark6 mencionado acima.

Trata-se de um programa simples que pode ser usado como referência de
implementação. É funcional e segue a especificação do Ark6,
mas não contém funcionalidades
que poderiam estar presentes em um programa mais completo.


### Parâmetros

**Cifrar:** `ark6 -c arquivo_entrada_legivel.extensao arquivo_saida_cifrado.ark6 [senha]`  
**Decifrar:** `ark6 -d arquivo_entrada_cifrado.ark6 arquivo_saida_decifrado_legivel.extensao [senha]`
**Testar senha:** `ark6 -t arquivo_entrada_cifrado.ark6 [senha]`

- Para usar entrada padrão, colocar *--stdin* no nome do arquivo.
- Para usar saída padrão, colocar *--stdout* no nome do arquivo. Neste caso, não se deve
redirecionar stderr, pois as impressões serão feitas neste local.
- O parâmetro da senha é opcional. Se a entrada for --stdin, a senha na linha de comando é obrigatória.
- O teste da senha apenas verifica se as senhas tentadas (ou a da linha de comando) estão corretas,
sem gerar nenhuma saída com o arquivo decifrado.

### Algoritmos adicionais do programa

#### Hash com Ark6

O tamanho da saída do hash é o tamanho do bloco.

O algoritmo de hash utliza o algoritmo Ark6 para obter um hash de 256 bits de cadeias de bytes de tamanho
arbitrário em bits (nesta implementação, limitado a 2^64-1 bits). O bloco do hash tem 256 bits,
iniciados com zeros. Os bits do texto a passar pelo hash
comporão a chave, acrescentando antes o tamanho do texto em bits em formato big-endian, limitado a 64 bits
(na hipótese de mais de 2^64-1 bits na entrada, usar *n mod 2^64*).
Ao final dos bits do conteúdo, acrescenta-se um bit 1, e tantos bits 0 quantos forem necessários
para completar um múltiplo de 512 bits, que é o tamanho da chave do Ark6.

#### PBKDF2

O algoritmo [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) é implementado com
2<sup>14</sup> iterações fixas,
[salt](https://en.wikipedia.org/wiki/Salt_(cryptography))
de tamanho arbitrário, e a função usada
é o hash descrito acima. Em cada iteração de cálculo de T<sub>i</sub>,
é utilizado um bloco inicial adicional U<sub>0</sub> que é o hash de
(salt + uint32_be(número_iteração)), onde o sinal + significa a concatenação
dos bytes.
Cada bloco U<sub>j</sub> seguinte é hash de (senha + U<sub>j-1</sub>),
para j de 1 a c.


#### Outras funções

Outras funções incluem hash com medição em bytes, hash de strings, que são
simples atalhos para o hash já descrito acima.


### Entrada da senha

A senha, com tamanho de até 65535 caracteres na atual implementação,
é coletada sem exibição (quando não informada na linha de comando),
e coletada uma segunda vez para conferência,
também sem exibição.


### Derivação da chave de criptografia

A chave de 512 bits é derivada usando PBKDF2
a partir da senha, usando um salt de 384
bits, em que os primeiros 128 são aleatórios
e os demais são o
[xor](https://en.wikipedia.org/wiki/Exclusive_or)
das duas metades de um bloco de 256 bits gerados
com o PBKDF2 da própria senha, usando como
salt os 128 primeiros bits aleatórios do salt de 384 bits.


### Modo de cifragem

Para cifragem é utilizado
[counter mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)),
com número inicial
calculado a partir do hash dos 384 bits utilizados de salt
na derivação da chave de criptografia.


### Formato do arquivo cifrado do programa ark6

1. 128 bits de *salt* aleatório.

O
[salt](https://en.wikipedia.org/wiki/Salt_(cryptography))
é obtido usando o hash de entrada aleatória de tamanho arbitrário
obtida pelo teclado, horário e variáveis do sistema, mas pode
ser obtido de outras formas que sejam seguras,
coletando entropia de onde estiver disponível no sistema.

2. 128 bits de conferência da senha

Usando PBKDF2 com o salt do item 1 acima e a senha fornecida pelo usuário,
são calculados 256 bits, e o *xor* das duas metades é colocado como
bits de conferência da senha no arquivo.

Esses 256 bits, após serem anexados aos 128 bits do item 1, formam
um novo salt de 384 bits a ser utilizado para derivar a chave do Ark6.

3. bits com o conteúdo cifrado

Usando a chave derivada da senha e dos 384 bits de salt calculados
conforme descrito, o conteúdo é criptografado usando counter mode.

### Descriptografia

O processo de descriptografar é o mesmo, usando antes o segundo bloco
de 128 bits do arquivo para conferência se a senha é a correta. Como
o modo utilizado foi counter, não é necessária a implementação do
algoritmo de descriptografia Ark6, que consiste na execução dos mesmos
passos em ordem contrária da utilizada na cifragem.


### Entrada e saída de dados

As operações de leitura e escrita em arquivos são feitas usando
buffers (versão atual com 4096 bytes) para melhorar a performance.

### Ausência de metadados

O programa ark6 faz apenas a cifragem dos dados, isto é,
o arquivo cifrado no formato ark6 não guarda metadados referentes ao
tamanho do arquivo, de forma que não há proteção contra alterações
no arquivo de saída.

Por exemplo, se forem anexados bytes ao final do arquivo cifrado, eles
serão decifrados como se fossem parte do arquivo cifrado. Da mesma forma,
se forem retirados bytes, o arquivo decifrado será o texto legível
truncado.

Outro dado não guardado é o nome do arquivo de saída.

Para essas necessidades, recomenda-se programas específicos
de autenticação e redundâncias que protejam contra alterações.

### Proteção de dados na memória

O programa ark6 limpa da memória todos os dados sensíveis que não
serão mais utilizados. No entanto, não há garantia de que o sistema
operacional não vá armazená-los em algum cache, memória virtual, etc.

### Recuperação de conteúdo cifrado com senha esquecida

**NÃO** é possível recuperar os dados cifrados caso se esqueça
a senha, ou seja, não há nenhum tipo de backdoor implementado,
e nem mesmo o autor do programa tem como recuperar os dados.

Caso esqueça a senha, o máximo que se poderá fazer é tentar
alguma implementação de programa que faça tentativa da senha
por força bruta,
mas mesmo isso será inútil caso a senha seja grande, e/ou não se
saiba qual o conjunto de caracteres utilizado na senha.

Se esqueceu, o melhor a fazer é tentar senhas que costuma usar
ou combinações delas, para ver se foi a senha usada.

Tampouco adianta tentar quebrar, por força bruta, a chave
de criptografia, pois tem 512 bits, tornando inviável a
tarefa.



### Arquivo corrompido

Se o arquivo cifrado for corrompido, mas ainda souber a senha,
há chances do conceúdo ser recuperado. As seguintes situações
podem ocorrer:

- Arquivo corrompido a partir do deslocamento inicial de 32 bytes

O arquivo decifrado terá como resultado corrompido apenas os
bytes que foram corrompidos no arquivo cifrado. Isso é possível
pela utilização do modo counter. Caso fossem usados outros modos,
como por exemplo
[CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)),
o erro se propagaria, perdendo todo o conteúdo a partir do ponto em
que ocorreu o problema.

- Arquivo corrompido nos bytes de deslocamento 16 a 31

Esses bytes são utilizados para conferência de senha. Neste caso,
o programa sempre informará que a senha está incorreta, mesmo não
estando. É possível recuperar o arquivo, sendo necessário conhecimentos
de programação, para fazer o programa de descriptografia ignorar a conferência
da senha, e forçar a descriptografia com a senha fornecida. Vale ressaltar,
no entanto, que se o problema não for arquivo corrompido no trecho citado,
mas sim esquecimento de senha, o texto decifrado gerado será inútil,
com aparência de bytes aleatórios.

- Arquivo corrompido nos 16 bytes iniciais

Esses bytes são usados para geração da chave de descriptografia. Neste
caso pode-se tentar, via programação, pequenas variações de bits
nesses 16 bytes. Há alguma chance de sucesso se forem poucos os bits
corrompidos nesse trecho. Esse problema pode estar associado ao item
anterior (de bytes de conferência de senha corrompidos), então é recomendado
(caso tenha certeza da senha) ignorar a conferência de senha também. Se forem
muitos os bytes alterados no arquivo corrompido neste trecho inicial, o conteúdo
estará perdido.

### Variações na implementação de ark6

Futuras implementações poderão incluir variações que
*não modifiquem os algoritmos internos nem o formato do arquivo cifrado*,
como os exemplos abaixo:

- Coletar entropia de outros locais
- Mudança no tamanho do buffer
- Melhoria no tratamento dos parâmetros da linha de comando
- Implementação de uma interface gráfica mais amigável
- Implementação de aplicativo para celulares
- Refatorações diversas

### Versões em outras linguagens

Implementações em outras linguagens são disponibilizadas para os
casos em que não há compilador C disponível. É importante saber
que tratam-se de implementações para casos extremamente necessários,
já que apresentam características inferiores das versões em C:

- Menor velocidade
- Não ocultam as senhas durante a digitação
- Não limpam a memória dos dados utilizados
- Não usam cache para leitura e escrita de arquivos


### Versões pré-compiladas

- Versão em [ark6_windows.zip](https://github.com/dudz1978/ark6/blob/master/compilado/ark6_windows.zip) foi compilada com Windows 10, gcc (MinGW.org GCC-8.2.0-3) 8.2.0

- Versão em [ark6_ubuntu.tar.gz](https://github.com/dudz1978/ark6/blob/master/compilado/ark6_ubuntu.tar.gz) foi compilada com 5.4.0-42-generic #46~18.04.1-Ubuntu SMP, gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0, ldd (Ubuntu GLIBC 2.27-3ubuntu1.2) 2.27

- Versão em [ark6_java.zip](https://github.com/dudz1978/ark6/blob/master/compilado/ark6_java.zip)
foi compilada com Java 1.8.0_221


## Variações de uso do algoritmo Ark6

Além da implentação ark6 descrita acima, novas implementações de
variações do programa para outros propósitos
podem, em princípio, serem feitas com alternativas que ainda usem o algoritmo Ark6,
como por exemplo:

- outros [modos de operação](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- derivação diferente da chave de 512 bits, com outros algoritmos ou mais/menos iterações
- outros algoritmos de hash
- programas que armazenem metadados
- proteção contra trechos com bits corrompidos
- proteção contra alterações do arquivo cifrado

## Referências

[Ronald L. Rivest: Publications and Talks](http://people.csail.mit.edu/rivest/pubs.html)

[\[RRSY98\] The RC6 Block Cipher. Ronald L. Rivest, M. J. B. Robshaw, R. Sidney, and Y. L. Yin. Posted on the RC6 site of RSA Laboratories. (1998-08-20) Slides from NIST AES1 (1998-08-21) and AES3 (2000-04-14) conferences.](http://people.csail.mit.edu/rivest/pubs.html#RRSY98)  
PDF: [http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf](http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf)

Uma versão mais forte do algoritmo RC6 contra criptanálise χ² (Ueda, E. T., Terada, R., 2007)

Icons made by
[Freepik](https://www.flaticon.com/authors/freepik)
from [www.flaticon.com](https://www.flaticon.com/)

## Test Vectors

```
Entrada:
00000000000000000000000000000000
00000000000000000000000000000000

Chave:
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000

Saída:
e0a14f773c759154531c5c28ee82c374
ce84bfd0f35080fb657732d12fe3c17e
```

