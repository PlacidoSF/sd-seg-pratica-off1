package q4_cdn;

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
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

public class ClienteCDN {

    private final String ipGeoDNS = "127.0.0.1";
    private final int portaGeoDNS = 5453; 

    public void iniciar() {
        try {
            System.out.println("==================================================");
            System.out.println("[FASE 1] CONSULTA DE ROTA AO GEODNS (UDP)");
            System.out.println("==================================================");
            
            String ipPortaEdge = consultarGeoDNS("ONDE arquivo20.ext BRASIL");
            
            if (ipPortaEdge.startsWith("ERRO") || ipPortaEdge.startsWith("Erro")) {
                System.err.println("Falha ao obter rota: " + ipPortaEdge);
                return;
            }

            String[] partes = ipPortaEdge.split(":");
            String ipEdge = partes[0];
            int portaEdge = Integer.parseInt(partes[1]);

            System.out.println("\n==================================================");
            System.out.println("[FASE 2] CONSUMO NO EDGE SERVER (TCP)");
            System.out.println("==================================================");
            System.out.println("-> Conectando ao Edge Server atribuído em " + ipPortaEdge + "...\n");

            // teste 1: Cache MISS 
            System.out.println("--- TESTE A: Primeiro Acesso (Deverá ser MISS e demorado) ---");
            executarGetTCP(ipEdge, portaEdge, "GET /arquivo20.ext");
            
            Thread.sleep(1000); 

            // teste 1: Cache HIT
            System.out.println("\n--- TESTE B: Segundo Acesso Rápido (Deverá ser HIT instantâneo) ---");
            executarGetTCP(ipEdge, portaEdge, "GET /arquivo20.ext");

            Thread.sleep(1000);

            // teste 3: formatação inválida
            System.out.println("\n--- TESTE C: Entrada Inválida (formato, deverá ser rejeitado na borda) ---");
            executarGetTCP(ipEdge, portaEdge, "GET arquivo20"); // Falta a barra "/"

            // teste 3: nome fora da faixa 
            System.out.println("\n--- TESTE D: Arquivo Inexistente/Fora da Faixa (deverá ser rejeitado na borda) ---");
            executarGetTCP(ipEdge, portaEdge, "GET /arquivoXYZ.ext");

            // teste 3: pacote adulterado
            System.out.println("\n--- TESTE E: Fraude (HMAC inválido: conteúdo cifrado adulterado; Edge deve cortar a ligação) ---");
            executarGetFraude(ipEdge, portaEdge, "GET /arquivo20.ext");

            // teste 2: por TTL
            System.out.println("\n--- TESTE F: Expiração por TTL (aguarda 16s e repete; deverá ser MISS) ---");
            System.out.println("[Cliente] Aguardando expiração do TTL...");
            Thread.sleep(16000);
            executarGetTCP(ipEdge, portaEdge, "GET /arquivo20.ext");
            System.out.println("\n[Cliente] Para o INVALIDATE ativo (Caso 2 completo), digite 'invalidate arquivo20.ext' no console da Origem e repita o GET para observar MISS + PUSH no Edge.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private String consultarGeoDNS(String comando) throws Exception {
        try (DatagramSocket socketUDP = new DatagramSocket()) {
            socketUDP.setSoTimeout(5000);
            InetAddress enderecoGeoDNS = InetAddress.getByName(ipGeoDNS);

            enviarInt(socketUDP, 0, enderecoGeoDNS, portaGeoDNS);
            PublicKey rsaGeoDNS = (PublicKey) receberObjeto(socketUDP);

            KeyPair meuParRSA = RSAUtils.gerarParDeChaves();
            SecretKey minhaChaveAES = AESUtils.gerarChave();
            byte[] aesCifrado = RSAUtils.cifrarHandshake(minhaChaveAES.getEncoded(), rsaGeoDNS);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeInt(1);
            oos.writeObject(meuParRSA.getPublic());
            oos.writeObject(aesCifrado);
            oos.flush();
            enviarBytes(socketUDP, baos.toByteArray(), enderecoGeoDNS, portaGeoDNS);
            Thread.sleep(500); // garante que o GeoDNS registrou a sessão antes da consulta

            Pacote pacoteConsulta = CryptoManager.gerarPacote(comando.getBytes(StandardCharsets.UTF_8), minhaChaveAES, meuParRSA.getPrivate());
            
            baos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(baos);
            oos.writeInt(2);
            oos.writeObject(pacoteConsulta);
            oos.flush();
            enviarBytes(socketUDP, baos.toByteArray(), enderecoGeoDNS, portaGeoDNS);

            byte[] buffer = new byte[8192];
            DatagramPacket dpResp = new DatagramPacket(buffer, buffer.length);
            socketUDP.receive(dpResp);
            ByteArrayInputStream bais = new ByteArrayInputStream(dpResp.getData(), 0, dpResp.getLength());
            ObjectInputStream oisResp = new ObjectInputStream(bais);
            int op = oisResp.readInt();
            if (op != 2) throw new java.io.IOException("Resposta inesperada do GeoDNS (op=" + op + ")");
            Pacote pacoteResposta = (Pacote) oisResp.readObject();
            byte[] msgAberta = CryptoManager.abrirPacote(pacoteResposta, minhaChaveAES, rsaGeoDNS);
            
            String resposta = new String(msgAberta, StandardCharsets.UTF_8);
            System.out.println("[Cliente] GeoDNS indicou a rota: " + resposta + " (HMAC/assinatura validados)");
            return resposta;
        }
    }


    private void executarGetTCP(String ip, int porta, String requisicao) {
        try (Socket socketTCP = new Socket(ip, porta);
             ObjectOutputStream outTCP = new ObjectOutputStream(socketTCP.getOutputStream());
             ObjectInputStream inTCP = new ObjectInputStream(socketTCP.getInputStream())) {
            outTCP.flush(); // evita deadlock de header
            socketTCP.setSoTimeout(15000);

            // 1. Handshake Duplo com o Edge Server
            PublicKey rsaEdge = (PublicKey) inTCP.readObject();
            
            KeyPair meuParRSA = RSAUtils.gerarParDeChaves();
            SecretKey minhaChaveAES = AESUtils.gerarChave();
            byte[] aesCifrado = RSAUtils.cifrarHandshake(minhaChaveAES.getEncoded(), rsaEdge);

            outTCP.writeObject(meuParRSA.getPublic());
            outTCP.writeObject(aesCifrado);
            outTCP.flush();


            long inicioTempo = System.currentTimeMillis();
            Pacote pacoteGet = CryptoManager.gerarPacote(requisicao.getBytes(StandardCharsets.UTF_8), minhaChaveAES, meuParRSA.getPrivate());
            outTCP.writeObject(pacoteGet);
            outTCP.flush();

            Pacote pacoteResposta = (Pacote) inTCP.readObject();
            byte[] msgAberta = CryptoManager.abrirPacote(pacoteResposta, minhaChaveAES, rsaEdge);
            
            long tempoTotal = System.currentTimeMillis() - inicioTempo;
            
            System.out.println("[Cliente] Resposta recebida em " + tempoTotal + "ms:");
            System.out.println(new String(msgAberta, StandardCharsets.UTF_8));

        } catch (Exception e) {
            System.err.println("[Cliente-ERRO TCP] " + e.getMessage());
        }
    }


    private void executarGetFraude(String ip, int porta, String requisicao) {
        try (Socket socketTCP = new Socket(ip, porta);
             ObjectOutputStream outTCP = new ObjectOutputStream(socketTCP.getOutputStream());
             ObjectInputStream inTCP = new ObjectInputStream(socketTCP.getInputStream())) {
            outTCP.flush();
            socketTCP.setSoTimeout(8000);

            PublicKey rsaEdge = (PublicKey) inTCP.readObject();
            KeyPair meuParRSA = RSAUtils.gerarParDeChaves();
            SecretKey minhaChaveAES = AESUtils.gerarChave();
            byte[] aesCifrado = RSAUtils.cifrarHandshake(minhaChaveAES.getEncoded(), rsaEdge);
            outTCP.writeObject(meuParRSA.getPublic());
            outTCP.writeObject(aesCifrado);
            outTCP.flush();

            Pacote pct = CryptoManager.gerarPacote(requisicao.getBytes(StandardCharsets.UTF_8), minhaChaveAES, meuParRSA.getPrivate());
            System.out.println("[Cliente] Simulando adulteração do conteúdo cifrado (o HMAC deixará de corresponder)...");
            byte[] adulterado = pct.getTextoCifrado().clone();
            adulterado[adulterado.length - 1] ^= 0x01; // inverte 1 bit do texto cifrado
            pct = new Pacote(adulterado, pct.getAssinatura());
            outTCP.writeObject(pct);
            outTCP.flush();

            Pacote resp = (Pacote) inTCP.readObject();
            byte[] aberta = CryptoManager.abrirPacote(resp, minhaChaveAES, rsaEdge);
            System.out.println("[Cliente] Resposta inesperada: " + new String(aberta, StandardCharsets.UTF_8));
        } catch (java.io.EOFException | java.net.SocketException | java.net.SocketTimeoutException e) {
            System.out.println("[Resultado E] Sucesso! O Edge cortou a ligação devido à falha de HMAC/integridade.");
        } catch (Exception e) {
            System.err.println("[Cliente-ERRO TCP] " + e.getMessage());
        }
    }

    private void enviarInt(DatagramSocket socket, int valor, InetAddress ip, int porta) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeInt(valor);
        oos.flush();
        enviarBytes(socket, baos.toByteArray(), ip, porta);
    }

    private void enviarBytes(DatagramSocket socket, byte[] bytes, InetAddress ip, int porta) throws Exception {
        socket.send(new DatagramPacket(bytes, bytes.length, ip, porta));
    }

    private Object receberObjeto(DatagramSocket socket) throws Exception {
        byte[] buffer = new byte[8192];
        DatagramPacket pacote = new DatagramPacket(buffer, buffer.length);
        socket.receive(pacote);

        ByteArrayInputStream bais = new ByteArrayInputStream(pacote.getData(), 0, pacote.getLength());
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }

    public static void main(String[] args) {
        new ClienteCDN().iniciar();
    }
}