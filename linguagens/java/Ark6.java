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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.LongBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Ark6 {

    public static void main(String[] args) {
        if (args.length != 3 || (! "-c".equals(args[0]) && !"-d".equals(args[0]))) {
            System.err.println(
                    "Sintaxe:\n" +
                            "    criptografar: java Ark6 -c entrada.txt saida.ark6\n"+
                            "    descriptografar: java Ark6 -d entrada.ark6 saida.txt\n"
            );
            System.exit(1);;
        }
        String nomeIn = args[1];
        String nomeOut = args[2];
        File fout = new File(nomeOut);
        if (nomeIn == null || nomeOut == null || nomeIn.isEmpty() || nomeOut.isEmpty()) {
            throw new IllegalArgumentException("Entrada e/ou saida invalidos.");
        }
        if(fout.exists()) { 
            throw new RuntimeException("Arquivo de saida ja existe.");
        }
        File fin = new File(nomeIn);
        if (! fin.exists() || fin.isDirectory() || fin.isHidden() || ! fin.isFile()) {
            throw new RuntimeException("Arquivo entrada nao encontrado.");
        }
        if ("-c".equals(args[0])) criptografar(fin, fout);
        else if ("-d".equals(args[0])) descriptografar(fin, fout);
        System.exit(0);
    }
    
    private static void criptografar(File fin, File fout) {
        int i;
        long qtdTratados;
        long tamArq = fin.length();
        byte[] saltAleat = new byte[16];
        Random rnd = new SecureRandom();
        rnd.nextBytes(saltAleat);
        BufferedOutputStream out = null;
        BufferedInputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream(fin));
        } catch (FileNotFoundException e) {
            System.err.println("Erro ler entrada.");
            e.printStackTrace();
            System.exit(1);
            
        }
        try {
            out = new BufferedOutputStream(new FileOutputStream(fout));
        } catch (FileNotFoundException e) {
            System.err.println("Erro ao criar saida.");
            e.printStackTrace();
            System.exit(1);
        }
        try {
            out.write(saltAleat);
        } catch (IOException e) {
            System.err.println("Erro ao gravar saida.");
            e.printStackTrace();
            System.exit(1);
        }
        Scanner scanner = new Scanner(System.in);
        String senha;
        do {
            System.out.println("Digite a senha (ATENCAO! SERA' EXIBIDA NA TELA!)");
            senha = scanner.nextLine();
        } while(senha == null);
        scanner.close();
        byte[] bytesSenha;
        byte[] bitsConferencia;
        bytesSenha = senha.getBytes(Charset.availableCharsets().get("ISO-8859-1"));
        bitsConferencia = pbkdf2(bytesSenha, saltAleat, 32, 16384);        
        for (i = 0; i < 16; i++) {
            try {
                out.write((bitsConferencia[i] ^ bitsConferencia[i + 16]) & 0xff);
            } catch (IOException e) {
                System.err.println("Erro ao gravar saida.");
                e.printStackTrace();
                System.exit(1);
            }
        }
        byte[] key;
        byte[] bits384 = concat(saltAleat, bitsConferencia);
        key = pbkdf2(bytesSenha, bits384, 64, 16384);
        long[] subChaves = derivaSubChaves(key);
        int ch = 0;
        try {
            ch = in.read();
        } catch (IOException e) {
            System.err.println("Erro ao ler entrada.");
            e.printStackTrace();
            System.exit(1);
        }
        int pos = 32;
        byte[] counter = hash_bytes(bits384);
        byte[] bitsCrip = null;
        long exibirPercentual;
        qtdTratados = 0;
        exibirPercentual = tamArq / 100 - 1;
        System.out.print("0%");
        System.out.flush();
        while (ch >= 0) {
            if (pos >= 32) {
                pos = 0;
                bitsCrip = ark6(counter, subChaves);
                incrementaCounter(counter);
            }
            try {
                out.write((ch ^ (bitsCrip[pos] + 256)) & 0xff);
            } catch (IOException e) {
                System.err.println("Erro ao gravar saida.");
                e.printStackTrace();
                System.exit(1);
            }
            pos++;
            qtdTratados++;
            if (--exibirPercentual <= 0) {
                exibirPercentual = tamArq / 100 - 1;
                System.out.printf("\r%d%%", (int)(qtdTratados * 100.0 / tamArq));
                System.out.flush();
            }
            try {
                ch = in.read();
            } catch (IOException e) {
                System.err.println("Erro ao ler entrada.");
                e.printStackTrace();
                System.exit(1);
            }
        }
        System.out.printf("\r100%%\n");
        try {
            in.close();
            out.close();
        } catch (IOException e) {
            System.err.println("Erro ao fechar arquivos.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void incrementaCounter(byte[] counter) {
        int i;
        i = counter.length - 1;
        while (i >= 0) {
            counter[i] = (byte)(0xff & (counter[i] + 1));
            if (counter[i] != 0) return;
            i--;
        }
    }

    private static void descriptografar(File fin, File fout) {
        int i;
        long qtdTratados;
        long tamArq = fin.length();
        byte[] saltAleat = new byte[16];
        BufferedOutputStream out = null;
        BufferedInputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream(fin));
        } catch (FileNotFoundException e) {
            System.err.println("Erro ler entrada.");
            e.printStackTrace();
            System.exit(1);
        }
        try {
            out = new BufferedOutputStream(new FileOutputStream(fout));
        } catch (FileNotFoundException e) {
            System.err.println("Erro ao criar saida.");
            e.printStackTrace();
            System.exit(1);
        }
        byte[] bitsConferenciaLidos = new byte[16];
        try {
            in.read(saltAleat);
            in.read(bitsConferenciaLidos);
        } catch (IOException e) {
            System.err.println("Erro ler entrada.");
            e.printStackTrace();
            System.exit(1);
        }
        Scanner scanner = new Scanner(System.in);
        String senha;
        byte[] bytesSenha;
        boolean senhaCorreta;
        byte[] bitsConferencia;
        do {
            senhaCorreta = true;
            do {
                System.out.println("Digite a senha (ATENCAO! SERA' EXIBIDA NA TELA!)");
                senha = scanner.nextLine();
            } while(senha == null);
            bytesSenha = senha.getBytes(Charset.availableCharsets().get("ISO-8859-1"));
            bitsConferencia = pbkdf2(bytesSenha, saltAleat, 32, 16384);        
            for (i = 0; i < 16; i++) {
                if (bitsConferenciaLidos[i] != 
                        (byte)((bitsConferencia[i] ^ bitsConferencia[i + 16]) & 0xff)
                ) {
                    System.out.println("Senha incorreta!");
                    senhaCorreta = false;
                    break;
                }
            }
        } while (! senhaCorreta);
        scanner.close();
        byte[] key;
        byte[] bits384 = concat(saltAleat, bitsConferencia);
        key = pbkdf2(bytesSenha, bits384, 64, 16384);
        long[] subChaves = derivaSubChaves(key);
        int ch = 0;
        try {
            ch = in.read();
        } catch (IOException e) {
            System.err.println("Erro ao ler entrada.");
            e.printStackTrace();
            System.exit(1);
        }
        int pos = 32;
        byte[] counter = hash_bytes(bits384);
        byte[] bitsCrip = null;
        long exibirPercentual;
        qtdTratados = 0;
        exibirPercentual = tamArq / 100 - 1;
        System.out.print("0%");
        System.out.flush();
        while (ch >= 0) {
            if (pos >= 32) {
                pos = 0;
                bitsCrip = ark6(counter, subChaves);
                incrementaCounter(counter);
            }
            try {
                out.write((ch ^ (bitsCrip[pos] + 256)) & 0xff);
            } catch (IOException e) {
                System.err.println("Erro ao gravar saida.");
                e.printStackTrace();
                System.exit(1);
            }
            pos++;
            qtdTratados++;
            if (--exibirPercentual <= 0) {
                exibirPercentual = tamArq / 100 - 1;
                System.out.printf("\r%d%%", (int)(qtdTratados * 100.0 / tamArq));
                System.out.flush();
            }
            try {
                ch = in.read();
            } catch (IOException e) {
                System.err.println("Erro ao ler entrada.");
                e.printStackTrace();
                System.exit(1);
            }
        }
        System.out.printf("\r100%%\n");
        try {
            in.close();
            out.close();
        } catch (IOException e) {
            System.err.println("Erro ao fechar arquivos.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static long[] derivaSubChaves(byte[] chave) { 
        final long P = 0x90fdaa22168c234dL;
        final long Q = 0xd413cccfe7799211L;
        long[] subChaves = new long[84];
        int i, j;
        long[] L = new long[8];
        long A, B;
        LongBuffer lb = ByteBuffer.wrap(chave).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();

        for (i = 0; i < 8; i++) {
            L[i] = lb.get();
        }
        
        subChaves[0] = P;
        for (i = 1; i < 84; i++) {
            subChaves[i] = subChaves[i - 1] + Q;
        }
        A = B = 0;
        i = j = 0;
        for (int s = 0; s < 252; s++) {
            A = subChaves[i] = Long.rotateLeft(subChaves[i] + A + B, 3);
            B = L[j] = Long.rotateLeft(L[j] + A + B, (int)((A + B) & 63));
            i = (i + 1) % 84;
            j = (j + 1) & 7;
        }
        return subChaves;
    }
    
    public static long T(long n) {
        if ((Long.bitCount(n) & 1) == 1) return Long.rotateLeft(n, 32);
        return n;
    }

    public static byte[] ark6(byte[] plain, long[] subChaves) {
        int i, j;
        long[] v = new long[4];
        long tmp;
        long x, y;
        LongBuffer lb = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();
        for (i = 0; i < 4; i++) {
            v[i] = lb.get();
        }
        v[1] += subChaves[0];
        v[3] += subChaves[1];
        j = 2;
        for (i = 1; i <= 40; i++) {
            v[1] = T(v[1]);
            v[3] = T(v[3]);
            x = Long.rotateLeft(v[1] * ((v[1] << 1) + 1), 6);
            y = Long.rotateLeft(v[3] * ((v[3] << 1) + 1), 6);
            v[0] = Long.rotateLeft(v[0] ^ x, (int) (y & 63)) + subChaves[j++];
            v[2] = Long.rotateLeft(v[2] ^ y, (int) (x & 63)) + subChaves[j++];
            tmp = v[0];
            v[0] = v[1];
            v[1] = v[2];
            v[2] = v[3];
            v[3] = tmp;
        }
        v[0] += subChaves[82];
        v[2] += subChaves[83];
        LongBuffer.wrap(v);
        ByteBuffer bb = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
        for (i = 0; i < 4; i++) {
            bb.putLong(v[i]);
        }
        return bb.array();
    }
    
    public static byte[] hash_bytes(byte[] v) {
        byte[] hash = new byte[32];
        ByteBuffer key;
        int pos_v, pos_k;
        int tam_bytes = v.length;
        
        key = ByteBuffer.allocate(64);
        key.order(ByteOrder.BIG_ENDIAN);
        key.putLong(tam_bytes << 3);
        pos_v = 0;
        pos_k = 8;
        while (pos_v < tam_bytes) {
            key.put(v[pos_v++]);
            if (++pos_k == 64) {
                pos_k = 0;
                hash = ark6(hash, derivaSubChaves(key.array()));
                key.rewind();
            }
        }
        key.put((byte) 0x80);
        pos_k++;
        while (pos_k < 64) {
            key.put((byte)0);
            pos_k++;
        }
        hash = ark6(hash, derivaSubChaves(key.array()));
        
        return hash;
    }
    
    public static byte[] concat(byte[] a, byte[] b, byte[] destino) {
        byte[] result;
        if (destino == null) {
            result = Arrays.copyOf(a, a.length + b.length);
        }
        else {
            result = destino;
            System.arraycopy(a, 0, result, 0, a.length);
        }
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    public static byte[] concat(byte[] a, byte[] b) {
        return concat(a, b, null);
    }
    
    private static byte[] pbkdf2(int nrIteracao, byte[] senha, byte[] salt, int qtdCiclos) {
        int pos = 0; // posição do valor u atual
        byte[] ui32 = new byte[4];
        byte[][] u = new byte[2][32];
        byte[] senhaUant;
        int i, j;
        byte[] key = new byte[32];
        
        ByteBuffer.wrap(ui32).order(ByteOrder.BIG_ENDIAN).putInt(nrIteracao);
        u[pos] = hash_bytes(concat(salt, ui32)); // valor extra U0
        for (j = 0; j < 32; j++) key[j] ^= u[pos][j];
        senhaUant = concat(senha, new byte[32]); // alocação para usar sempre o mesmo espaço
        for (i = 0; i < qtdCiclos; i++) {
            pos ^= 1;
            u[pos] = hash_bytes(concat(senha, u[pos ^ 1], senhaUant));
            for (j = 0; j < 32; j++) key[j] ^= u[pos][j];
        }
        return key;
    }
    
    public static byte[] pbkdf2(byte[] senha, byte[] salt, int tam_key, int qtdCiclos) {
        byte[] key = new byte[tam_key];
        int pos = 0;
        int iteracao = 0;
        byte[] key_parc;
        
        while (pos + 32 < tam_key) {
            iteracao++;
            key_parc = pbkdf2(iteracao, senha, salt, qtdCiclos);
            System.arraycopy(key_parc, 0, key, pos, 32);
            pos += 32;
        }
        iteracao++;
        key_parc = pbkdf2(iteracao, senha, salt, qtdCiclos);
        System.arraycopy(key_parc, 0, key, pos, tam_key - pos);

        return key;
    }
}
