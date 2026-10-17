package crypto;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAUtils {

    private static final String PADDING = "RSA/ECB/PKCS1Padding";

    public static KeyPair gerarParDeChaves() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); 
        return kpg.generateKeyPair(); 
    }

    public static byte[] cifrarHandshake(byte[] dados, PublicKey chavePublicaDestinatario) throws Exception {
        Cipher cifrador = Cipher.getInstance(PADDING);
        cifrador.init(Cipher.ENCRYPT_MODE, chavePublicaDestinatario);
        return cifrador.doFinal(dados);
    }

    public static byte[] decifrarHandshake(byte[] dadosCifrados, PrivateKey propriaChavePrivada) throws Exception {
        Cipher decifrador = Cipher.getInstance(PADDING);
        decifrador.init(Cipher.DECRYPT_MODE, propriaChavePrivada);
        return decifrador.doFinal(dadosCifrados);
    }

    public static byte[] assinar(byte[] hash, PrivateKey propriaChavePrivada) throws Exception {
        Cipher cifrador = Cipher.getInstance(PADDING);
        cifrador.init(Cipher.ENCRYPT_MODE, propriaChavePrivada);
        return cifrador.doFinal(hash);
    }

    public static byte[] decifrarAssinatura(byte[] assinatura, PublicKey chavePublicaRemetente) throws Exception {
        Cipher decifrador = Cipher.getInstance(PADDING);
        decifrador.init(Cipher.DECRYPT_MODE, chavePublicaRemetente);
        return decifrador.doFinal(assinatura);
    }
}