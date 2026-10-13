package shared;

import java.io.Serializable;

public class Pacote implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] textoCifrado; 
    private final byte[] assinatura; 

    public Pacote(byte[] textoCifrado, byte[] assinatura) {
        this.textoCifrado = textoCifrado;
        this.assinatura = assinatura;
    }

    public byte[] getTextoCifrado() {
        return textoCifrado;
    }

    public byte[] getAssinatura() {
        return assinatura;
    }
}