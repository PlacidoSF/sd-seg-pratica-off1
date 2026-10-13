package crypto;

import java.security.MessageDigest;

public class HashUtils {

    public static byte[] gerarHash(byte[] dados) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); 
        return md.digest(dados);
    }

    public static boolean compararHashSeguro(byte[] hashCalculado, byte[] hashRecebido) {
        return MessageDigest.isEqual(hashCalculado, hashRecebido);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}