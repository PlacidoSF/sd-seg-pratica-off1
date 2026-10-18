package crypto;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HashUtils {

    public static byte[] calcularHmacSha256(byte[] chave, byte[] bytesMensagem) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(chave, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(bytesMensagem);
    }

    public static boolean checarHmac(byte[] chave, byte[] bytesMensagem, byte[] hmacRecebido) throws Exception {
        byte[] hmacCalculado = calcularHmacSha256(chave, bytesMensagem);
        return MessageDigest.isEqual(hmacCalculado, hmacRecebido);
    }
}
