package crypto;

import shared.Pacote;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;


public class CryptoManager {

    /**
      fluxo do remetente:
      1 cifra a mensagem com AES (S -> C)
      2 gera o Hash do texto cifrado (H -> R)
      3 assina o Hash com a Chave Privada RSA (A^-1 -> As)
      4 retorna o Pacote contendo [C, As]
     */
    public static Pacote gerarPacote(byte[] mensagemPura, SecretKey chaveAES, PrivateKey chavePrivadaRemetente) throws Exception {
        
        // 1 cifra simétrica 
        byte[] textoCifrado = AESUtils.cifrar(mensagemPura, chaveAES);
        
        // 2 geração de hash
        byte[] hashDoTextoCifrado = HashUtils.gerarHash(textoCifrado);
        
        // 3 assinatura assimétrica 
        byte[] assinatura = RSAUtils.assinar(hashDoTextoCifrado, chavePrivadaRemetente);
        
        // 4 retorna o envelope de rede
        return new Pacote(textoCifrado, assinatura);
    }

    /**
      fluxo do destinatário:
      1 recebe o Pacote [C, As]
      2 calcula o Hash local do texto cifrado (H -> R_local)
      3 decifra a Assinatura com a Chave Pública RSA (A -> R_original)
      4 compara R_local ?= R_original. Se falhar, bloqueia a execução
      5 se for válido, decifra o texto com AES (S^-1 -> M) e devolve a mensagem
     */
    public static byte[] abrirPacote(Pacote pacote, SecretKey chaveAES, PublicKey chavePublicaRemetente) throws Exception {
        
        byte[] textoCifrado = pacote.getTextoCifrado();
        byte[] assinaturaRecebida = pacote.getAssinatura();

        // 1 calcula o hash local 
        byte[] hashCalculadoLocalmente = HashUtils.gerarHash(textoCifrado);

        // 2 decifra a assinatura 
        byte[] hashOriginalDaAssinatura = RSAUtils.decifrarAssinatura(assinaturaRecebida, chavePublicaRemetente);

        // 3 validação segura 
        if (!HashUtils.compararHashSeguro(hashCalculadoLocalmente, hashOriginalDaAssinatura)) {
    
            throw new SecurityException("ALERTA CRÍTICO: Falha de integridade ou autenticidade! Assinatura RSA inválida.");
        }

        // 4 decifra a mensagem
        return AESUtils.decifrar(textoCifrado, chaveAES);
    }
}