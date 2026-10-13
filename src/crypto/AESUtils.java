package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESUtils {

    private static final String ALGORITMO = "AES/CBC/PKCS5Padding";

    public static SecretKey gerarChave() throws Exception {
        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256); 
        return gerador.generateKey();
    }

    public static byte[] cifrar(byte[] dadosAbertos, SecretKey chave) throws Exception {
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv); 

        Cipher cifrador = Cipher.getInstance(ALGORITMO); 
        cifrador.init(Cipher.ENCRYPT_MODE, chave, new IvParameterSpec(iv)); 

        byte[] dadosCifrados = cifrador.doFinal(dadosAbertos);

        byte[] resultado = new byte[iv.length + dadosCifrados.length];
        System.arraycopy(iv, 0, resultado, 0, iv.length);
        System.arraycopy(dadosCifrados, 0, resultado, iv.length, dadosCifrados.length); 

        return resultado;
    }

    public static byte[] decifrar(byte[] dadosComIv, SecretKey chave) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(dadosComIv, 0, iv, 0, iv.length); 

        byte[] dadosCifrados = new byte[dadosComIv.length - iv.length]; 
        System.arraycopy(dadosComIv, iv.length, dadosCifrados, 0, dadosCifrados.length); 

        Cipher decriptador = Cipher.getInstance(ALGORITMO); 
        decriptador.init(Cipher.DECRYPT_MODE, chave, new IvParameterSpec(iv)); 

        return decriptador.doFinal(dadosCifrados);
    }
}