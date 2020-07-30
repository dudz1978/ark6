
# Ark6

Ark6 é um algoritmo de criptografia simética baseado numa variação do algoritmo
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


## Características comparadas com RC6 proposto na [competição para AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard_process)

| Característica    | RC6              |  Ark6     |
|------------------:|:----------------:|:---------:|
| Tamanho da chave  | 128/192/256 bits | 512 bits  |
| Tamanho do bloco  | 128 bits         | 128 bits  |
| Número de rounds  | 20               | 40        |
| Tamanho variáveis | 32 bits          | 32 bits   |
| Constante P       | bits de *e*      | bits de π |
| Constante Q       | bits de φ        | bits de sqrt(2) |

As constantes são obtidas da mesma forma do RC6, pegando os 32 bits após o ponto
decimal e arredondando para o número inteiro ímpar mais próximo, porém com a
diferença de começar a partir do primeiro bit 1 após o ponto decimal, já que
as constantes do Ark6 são menores que 0,5. A proposta do algoritmo
RC6 já mencionava a possibilidade de se usar constantes diferentes
em implementações customizadas.


## Passo de segurança adicional

O algoritmo Ark6 contém uma transformação adicional T, descrita em

*Uma versão mais forte do algoritmo RC6 contra criptanálise χ²* (Ueda, E. T., Terada, R., 2007)

A transformação T consiste na rotação de 16 bits nas variáveis
B e D no início de cada iteração, caso o número de bits 1 da
variável seja ímpar.


## Programa ark6

O programa ark6 é uma implementação do algoritmo Ark6 mencionado acima.


### Parâmetros

**Cifrar:** `ark6 -c arquivo_entrada_legivel.extensao arquivo_saida_cifrado.ark6`  
**Decifrar:** `ark6 -d arquivo_entrada_cifrado.ark6 arquivo_saida_decifrado_legivel.extensao`


### Algoritmos adicionais do programa

#### Hash 128 bits com RC6

O algoritmo de hash utliza o algoritmo Ark6 para obter um hash de 128 bits de cadeias de bytes de tamanho
arbitrário em bits. O bloco do hash tem 128 bits, iniciados com zeros. Os bits do texto a passar pelo hash
comporão a chave, acrescentando antes o tamanho do texto em bits em formato big-endian, limitado a 64 bits.
Ao final dos bits do conteúdo, acrescenta-se um bit 1, e tantos bits 0 quantos forem necessários
para completar um múltiplo de 512 bits, que é o tamanho da chave do Ark6.

#### PBKDF2

O algoritmo [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) é implementado com
2<sup>14</sup> iterações, salt de tamanho arbitrário, e a função usada
é o hash descrito acima. Em cada iteração de cálculo de T<sub>i</sub>,
é utilizado um bloco inicial adicional U<sub>0</sub> que é o hash de
(salt + uint32_be(número_iteração)).
Cada bloco U<sub>j</sub> seguinte é hash de (senha + U<sub>j-1</sub>),
para j de 1 a c.


#### Outras funções

Outras funções incluem hash com medição em bytes, hash de strings, que são
simples atalhos para o hash já descrito acima.


### Entrada da senha

A senha, com tamanho de até 1023 bits (futuramente poderá ser arbitrário),
é coletada sem exibição, e coletada uma segunda vez para conferência,
também sem exibição.


### Derivação da chave de criptografia

A chave de 512 bits é derivada usando PBKDF2
a partir da senha, usando um salt de 384
bits, em que os primeiros 128 são aleatórios
e os demais são PBKDF2 da própria senha usando como
salt os 128 primeiros.


### Modo de cifragem

Para cifragem é utilizado
[counter mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)),
com número inicial
calculado a partir do hash dos 384 bits utilizados de salt
na derivação da chave de criptografia.


### Formato do arquivo cifrado do programa ark6

1. 128 bits de *salt* aleatório.

O salt é obtido usando o hash de entrada aleatória de tamanho arbitrário
obtida pelo teclado, mas pode ser obtido de outras formas que sejam seguras,
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

### Decriptografia

O processo de descriptografar é o mesmo, usando antes o segundo bloco
de 128 bits do arquivo para conferência se a senha é a correta. Como
o modo utilizado foi counter, não é necessária a implementação do
algoritmo de decriptografia Ark6, que consiste na execução dos mesmos
passos em ordem contrária da utilizada na cifragem.


### Entrada e saída de dados

As operações de leitura e escrita em arquivos são feitas usando
buffer de 4096 bytes para melhorar a performance.

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
o erro se propagaria, perdendo todo o conteúdo.

- Arquivo corrompido nos bytes de deslocamento 16 a 31

Esses bytes são utilizados para conferência de senha. Neste caso,
o programa sempre informará que a senha está incorreta, mesmo não
estando. É possível recuperar o arquivo, sendo necessário conhecimentos
de programação, para fazer o programa de decriptografia ignorar a conferência
da senha, e forçar a decriptografia com a senha fornecida. Vale ressaltar,
no entanto, que o problema não for arquivo corrompido no trecho citado,
mas sim esquecimento de senha, o texto decifrado gerado será inútil,
com aparência de bytes aleatórios.

- Arquivo corrompido nos 16 bytes iniciais

Esses bytes são usados para geração da chave de decriptografia. Neste
caso pode-se tentar, via programação, pequenas variações de bits
nesses 16 bytes. Há alguma chance de sucesso se forem poucos os bits
corrompidos nesse trecho. Esse problema pode estar associado ao item
anterior, de bytes de conferência de senha corrompidos, então é recomendado
(caso tenha certeza da senha) ignorar a conferência de senha também. Se forem
muitos os bytes alterados no arquivo corrompido neste trecho inicial, o conteúdo
estará perdido.


### Variações na implementação de ark6

Futuras implementações poderão incluir variações que
*não modifiquem os algoritmos internos nem o formato do arquivo cifrado*,
como os exemplos abaixo:

- Informar a senha na linha de comando
- Coletar entropia de outros locais
- Mudança no tamanho do buffer
- Leitura e escrita na entrada e saída padrão (possível por usar counter mode)


## Variações de uso do algoritmo Ark6

Além da implentação ark6 descrita acima, novas implementações de
variações do programa para outros propósitos
podem, a princípio, serem utilizadas com outros modos e derivação
diferente da chave, podendo usar, por exemplo, mais passos
no PBKDF2.

## Referências

[Ronald L. Rivest: Publications and Talks](http://people.csail.mit.edu/rivest/pubs.html)

[\[RRSY98\] The RC6 Block Cipher. Ronald L. Rivest, M. J. B. Robshaw, R. Sidney, and Y. L. Yin. Posted on the RC6 site of RSA Laboratories. (1998-08-20) Slides from NIST AES1 (1998-08-21) and AES3 (2000-04-14) conferences.](http://people.csail.mit.edu/rivest/pubs.html#RRSY98)  
PDF: [http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf](http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf)

Uma versão mais forte do algoritmo RC6 contra criptanálise χ² (Ueda, E. T., Terada, R., 2007)

Icons made by
[Freepik](https://www.flaticon.com/authors/freepik)
from [www.flaticon.com](https://www.flaticon.com/)
