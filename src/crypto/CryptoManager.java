package crypto;

import shared.Pacote;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;


public class CryptoManager {

    /**
      fluxo do remetente:
      1 cifra a mensagem com AES (S -> C)
      2 gera o HMAC do texto cifrado (H -> R)
      3 assina o HMAC com a Chave Privada RSA (A^-1 -> As)
      4 retorna o Pacote contendo [C, As]
     */
    public static Pacote gerarPacote(byte[] mensagemPura, SecretKey chaveAES, PrivateKey chavePrivadaRemetente) throws Exception {
        
        // 1 cifra simétrica 
        byte[] textoCifrado = AESUtils.cifrar(mensagemPura, chaveAES);
        
        // 2 geração do HMAC
        byte[] hmacDoTextoCifrado = HashUtils.calcularHmacSha256(chaveAES.getEncoded(), textoCifrado);
        
        // 3 assinatura assimétrica 
        byte[] assinatura = RSAUtils.assinar(hmacDoTextoCifrado, chavePrivadaRemetente);
        
        // 4 retorna o envelope de rede
        return new Pacote(textoCifrado, assinatura);
    }

    /**
      fluxo do destinatário:
      1 recebe o Pacote [C, As]
      2 decifra a Assinatura com a Chave Pública RSA (A -> R_original)
      3 calcula o HMAC local do texto cifrado e compara R_local ?= R_original. Se falhar, bloqueia a execução
      4 se for válido, decifra o texto com AES (S^-1 -> M) e devolve a mensagem
     */
    public static byte[] abrirPacote(Pacote pacote, SecretKey chaveAES, PublicKey chavePublicaRemetente) throws Exception {
        
        byte[] textoCifrado = pacote.getTextoCifrado();
        byte[] assinaturaRecebida = pacote.getAssinatura();

        // 1 decifra a assinatura 
        byte[] hmacOriginalDaAssinatura = RSAUtils.decifrarAssinatura(assinaturaRecebida, chavePublicaRemetente);

        // 2 validação segura 
        if (!HashUtils.checarHmac(chaveAES.getEncoded(), textoCifrado, hmacOriginalDaAssinatura)) {
    
            throw new SecurityException("ALERTA CRÍTICO: Falha de integridade ou autenticidade! HMAC ou assinatura RSA inválidos.");
        }

        // 3 decifra a mensagem
        return AESUtils.decifrar(textoCifrado, chaveAES);
    }
}