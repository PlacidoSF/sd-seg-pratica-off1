package q1_minidns;

import crypto.AESUtils;
import crypto.CryptoManager;
import crypto.RSAUtils;
import shared.Pacote;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

public class ClienteComum {

    private final DatagramSocket socket;
    private final InetAddress enderecoServidor;
    private final int portaServidor = 5000;

    private KeyPair parChavesRSA;
    private SecretKey chaveAES;
    private PublicKey chavePublicaServidor;

    private final java.util.concurrent.ConcurrentHashMap<String, String> tabelaLocal = new java.util.concurrent.ConcurrentHashMap<>();

    public ClienteComum() throws Exception {
        this.socket = new DatagramSocket(); 
        this.enderecoServidor = InetAddress.getByName("127.0.0.1"); 
        this.socket.setSoTimeout(5000); 
    }

    public void iniciar() {
        try {
            System.out.println("==================================================");
            System.out.println("[CLIENTE] INICIANDO SESSÃO E HANDSHAKE");
            System.out.println("==================================================");
            executarHandshake();

            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 1] CONSULTA RESOLUÇÃO DE NOME");
            System.out.println("==================================================");
            consultar("servidor1", false);

            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 3.A] ENTRADA INVÁLIDA (servidor99)");
            System.out.println("==================================================");
            consultar("servidor99", false);

            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 3.B] FALHA DE INTEGRIDADE / ADULTERAÇÃO");
            System.out.println("==================================================");
            consultar("servidor2", true);

            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 2] AGUARDANDO NOTIFICAÇÃO DE BINDING DINÂMICO (Op 3, cifrada)");
            System.out.println("==================================================");
            System.out.println("[Cliente] Tabela local antes: " + tabelaLocal);
            aguardarNotificacoes(15000);
            System.out.println("[Cliente] Tabela local depois: " + tabelaLocal);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }

    private void executarHandshake() throws Exception {
        enviarOperacao(0, null);
        this.chavePublicaServidor = (PublicKey) receberObjeto();
        System.out.println("[Handshake] Chave pública do Servidor recebida com sucesso.");

        this.parChavesRSA = RSAUtils.gerarParDeChaves();
        this.chaveAES = AESUtils.gerarChave();

        byte[] aesCifrado = RSAUtils.cifrarHandshake(chaveAES.getEncoded(), chavePublicaServidor);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeInt(1);
        oos.writeObject(parChavesRSA.getPublic());
        oos.writeObject(aesCifrado);
        oos.flush();
        enviarBytes(baos.toByteArray());

        System.out.println("[Handshake] Chaves enviadas. Canal seguro estabelecido via AES+RSA!");

        Thread.sleep(500);
    }


    private void consultar(String nomeServidor, boolean simularAdulteracao) {
        try {
            String comando = "CONSULTAR " + nomeServidor;
            byte[] msgBytes = comando.getBytes(StandardCharsets.UTF_8);

            Pacote pacoteSeguro = CryptoManager.gerarPacote(msgBytes, chaveAES, parChavesRSA.getPrivate());

            if (simularAdulteracao) {
                System.out.println("[Cliente] Simulando interceptação e adulteração do pacote antes do envio...");
                byte[] assinaturaCorrompida = new byte[256];
                pacoteSeguro = new Pacote(pacoteSeguro.getTextoCifrado(), assinaturaCorrompida);
            }

            System.out.println("[Cliente] Enviando requisição segura: " + comando);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeInt(2);
            oos.writeObject(pacoteSeguro);
            oos.flush();
            enviarBytes(baos.toByteArray());

            String resposta = receberEResolverResposta();

            // Guarda a resolução no cache/mapa local do cliente (transparência de mobilidade)
            if (resposta != null && resposta.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
                tabelaLocal.put(nomeServidor, resposta);
                System.out.println("[Cliente] Cache local atualizado: " + nomeServidor + " -> " + resposta);
            }

        } catch (java.net.SocketTimeoutException timeout) {
            if (simularAdulteracao) {
                System.out.println("[Resultado 3.B] Sucesso do Servidor! O Servidor descartou o pacote corrompido silenciosamente, conforme exigido. Nenhum dado foi vazado.");
            } else {
                System.err.println("[Erro] Servidor demorou a responder.");
            }
        } catch (Exception e) {
            System.err.println("[Erro na Consulta] " + e.getMessage());
        }
    }

    private String receberEResolverResposta() throws Exception {
        long deadline = System.currentTimeMillis() + 5000;
        while (true) {
            long resto = deadline - System.currentTimeMillis();
            if (resto <= 0) throw new java.net.SocketTimeoutException("Timeout aguardando resposta");
            socket.setSoTimeout((int) Math.min(resto, 5000));
            byte[] buffer = new byte[4096];
            DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
            socket.receive(pacoteRecebido);

            ByteArrayInputStream bais = new ByteArrayInputStream(pacoteRecebido.getData(), 0, pacoteRecebido.getLength());
            ObjectInputStream ois = new ObjectInputStream(bais);

            int operacao = ois.readInt();
            if (operacao == 3) {
    
                Pacote pctNotif = (Pacote) ois.readObject();
                processarNotificacao(pctNotif);
                continue;
            }
            if (operacao == 2) {
                Pacote pacoteResposta = (Pacote) ois.readObject();
                byte[] respostaBytes = CryptoManager.abrirPacote(pacoteResposta, chaveAES, chavePublicaServidor);
                String resposta = new String(respostaBytes, StandardCharsets.UTF_8);

                System.out.println("[Resultado] Resposta autenticada recebida: " + resposta + " (assinatura RSA validada)");
                // Se for ip, guarda na tabela local
                if (resposta.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
                    System.out.println("[Cliente] Assinatura RSA validada com sucesso.");
                }
                return resposta;
            }
            System.out.println("[Cliente] Op code inesperado: " + operacao + " (ignorado)");
        }
    }

    private void processarNotificacao(Pacote pct) {
        try {
            byte[] aberto = CryptoManager.abrirPacote(pct, chaveAES, chavePublicaServidor);
            String msg = new String(aberto, StandardCharsets.UTF_8);
            System.out.println("[Notificação segura] " + msg + " (assinatura validada)");
            String[] p = msg.trim().split("\\s+");
            if (p.length >= 3 && p[0].equals("ATUALIZACAO")) {
                tabelaLocal.put(p[1], p[2]);
                System.out.println("[Cliente] Tabela local atualizada: " + p[1] + " -> " + p[2]);
            }
        } catch (SecurityException | java.security.GeneralSecurityException se) {
            System.err.println("[Cliente-ALERTA] Notificação com falha de integridade descartada.");
        } catch (Exception e) {
            System.err.println("[Cliente-ERRO] Falha ao processar notificação: " + e.getMessage());
        }
    }

    private void aguardarNotificacoes(long millis) {
        long fim = System.currentTimeMillis() + millis;
        System.out.println("[Cliente] Ouvindo notificações cifradas por " + (millis / 1000) + "s...");
        while (System.currentTimeMillis() < fim) {
            try {
                long resto = fim - System.currentTimeMillis();
                socket.setSoTimeout((int) Math.min(resto, 2000));
                byte[] buffer = new byte[4096];
                DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
                socket.receive(dp);
                ByteArrayInputStream bais = new ByteArrayInputStream(dp.getData(), 0, dp.getLength());
                ObjectInputStream ois = new ObjectInputStream(bais);
                int op = ois.readInt();
                if (op == 3) {
                    processarNotificacao((Pacote) ois.readObject());
                } else if (op == 2) {
                    Pacote pr = (Pacote) ois.readObject();
                    byte[] rb = CryptoManager.abrirPacote(pr, chaveAES, chavePublicaServidor);
                    System.out.println("[Cliente] Resposta tardia: " + new String(rb, StandardCharsets.UTF_8));
                }
            } catch (java.net.SocketTimeoutException to) {
                // intervalo sem notificação, continua até o fim da janela
            } catch (Exception e) {
                System.err.println("[Cliente-ERRO] " + e.getMessage());
            }
        }
        try { socket.setSoTimeout(5000); } catch (Exception ignored) {}
    }

    private void enviarOperacao(int op, Object payload) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeInt(op);
        if (payload != null) {
            oos.writeObject(payload);
        }
        oos.flush();
        enviarBytes(baos.toByteArray());
    }

    private void enviarBytes(byte[] bytes) throws Exception {
        DatagramPacket pacote = new DatagramPacket(bytes, bytes.length, enderecoServidor, portaServidor);
        socket.send(pacote);
    }

    private Object receberObjeto() throws Exception {
        byte[] buffer = new byte[4096];
        DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
        socket.receive(pacoteRecebido);

        ByteArrayInputStream bais = new ByteArrayInputStream(pacoteRecebido.getData(), 0, pacoteRecebido.getLength());
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }

    public static void main(String[] args) {
        try {
            new ClienteComum().iniciar();
        } catch (Exception e) {
            System.err.println("Falha ao inicializar o Cliente Comum: " + e.getMessage());
        }
    }
}