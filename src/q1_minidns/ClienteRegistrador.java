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
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;


public class ClienteRegistrador {

    private final DatagramSocket socket;
    private final InetAddress enderecoServidor;
    private final int portaServidor = 5000;

    private KeyPair parChavesRSA;
    private SecretKey chaveAES;
    private PublicKey chavePublicaServidor;

    private final java.util.concurrent.ConcurrentHashMap<String, String> tabelaLocal = new java.util.concurrent.ConcurrentHashMap<>();

    public ClienteRegistrador() throws Exception {
        this.socket = new DatagramSocket(); 
        this.socket.setSoTimeout(5000);
        this.enderecoServidor = InetAddress.getByName("127.0.0.1"); 
    }

    public void iniciar() {
        try {
            System.out.println("==================================================");
            System.out.println("[REGISTRADOR] INICIANDO SESSÃO E HANDSHAKE");
            System.out.println("==================================================");
            executarHandshake();

            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 2] BINDING DINÂMICO (ATUALIZAR)");
            System.out.println("==================================================");

            enviarAtualizacao("servidor1", "192.168.0.111");
            aguardarConfirmacaoENotificacoes();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }


    private void aguardarConfirmacaoENotificacoes() throws Exception {
        socket.setSoTimeout(8000);
        long fim = System.currentTimeMillis() + 12000;
        boolean confirmou = false;
        while (System.currentTimeMillis() < fim) {
            try {
                long resto = fim - System.currentTimeMillis();
                socket.setSoTimeout((int) Math.min(resto, 3000));
                byte[] buffer = new byte[4096];
                DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
                socket.receive(dp);
                ByteArrayInputStream bais = new ByteArrayInputStream(dp.getData(), 0, dp.getLength());
                ObjectInputStream ois = new ObjectInputStream(bais);
                int op = ois.readInt();
                if (op == 2 || op == 3) {
                    Pacote pct = (Pacote) ois.readObject();
                    try {
                        byte[] aberto = CryptoManager.abrirPacote(pct, chaveAES, chavePublicaServidor);
                        String msg = new String(aberto, StandardCharsets.UTF_8);
                        System.out.println((op == 2 ? "[Confirmação segura] " : "[Notificação segura] ") + msg + " (assinatura validada)");
                        String[] p = msg.trim().split("\\s+");
                        if (p.length >= 3 && p[0].equals("ATUALIZACAO")) {
                            tabelaLocal.put(p[1], p[2]);
                            System.out.println("[Registrador] Tabela local atualizada: " + p[1] + " -> " + p[2]);
                        } else if (p.length >= 5 && p[0].equals("OK:")) {
                            
                            tabelaLocal.put(p[1], p[p.length - 1]);
                            System.out.println("[Registrador] Tabela local atualizada: " + p[1] + " -> " + p[p.length - 1]);
                        }
                        if (op == 2) confirmou = true;
                        if (confirmou && tabelaLocal.containsKey("servidor1")) {
                            System.out.println("[Resultado 2] Binding dinâmico propagado com canal seguro. Tabela local: " + tabelaLocal);
                            if (System.currentTimeMillis() > fim - 8000) {
                                Thread.sleep(2000);
                            }
                            break;
                        }
                    } catch (SecurityException | java.security.GeneralSecurityException se) {
                        System.err.println("[Registrador-ALERTA] Pacote com falha de integridade descartado.");
                    }
                }
            } catch (java.net.SocketTimeoutException to) {
                if (confirmou) break;
                System.out.println("[Registrador] Aguardando confirmação/notificação...");
            }
        }
    }

    private void executarHandshake() throws Exception {
        enviarOperacao(0, null);
        this.chavePublicaServidor = (PublicKey) receberObjeto();

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

        System.out.println("[Handshake] Concluído! Canal seguro aberto com o Servidor DNS.");
        Thread.sleep(500);
    }

    private void enviarAtualizacao(String nomeServidor, String novoIp) throws Exception {
        String comando = "ATUALIZAR " + nomeServidor + " " + novoIp;
        byte[] msgBytes = comando.getBytes(StandardCharsets.UTF_8);

        Pacote pacoteSeguro = CryptoManager.gerarPacote(msgBytes, chaveAES, parChavesRSA.getPrivate());

        System.out.println("[Registrador] A enviar pedido seguro: " + comando);
        

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeInt(2);
        oos.writeObject(pacoteSeguro);
        oos.flush();
        enviarBytes(baos.toByteArray());
    }

    private void enviarOperacao(int op, Object payload) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeInt(op);
        if (payload != null) oos.writeObject(payload);
        oos.flush();
        enviarBytes(baos.toByteArray());
    }

    private void enviarBytes(byte[] bytes) throws Exception {
        socket.send(new DatagramPacket(bytes, bytes.length, enderecoServidor, portaServidor));
    }

    private Object receberObjeto() throws Exception {
        byte[] buffer = new byte[4096];
        DatagramPacket pacote = new DatagramPacket(buffer, buffer.length);
        socket.receive(pacote);

        ByteArrayInputStream bais = new ByteArrayInputStream(pacote.getData(), 0, pacote.getLength());
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }

    public static void main(String[] args) {
        try {
            new ClienteRegistrador().iniciar();
        } catch (Exception e) {
            System.err.println("Falha ao inicializar o Registrador: " + e.getMessage());
        }
    }
}