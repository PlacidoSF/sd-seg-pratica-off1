package q4_cdn;

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
import java.util.concurrent.ConcurrentHashMap;

public class GeoDNS {

    private static final int PORTA_GEODNS = 5453;
    
    private final ConcurrentHashMap<String, SessaoGeo> sessoesAtivas;
    
    private final KeyPair parChavesRSA;

    public GeoDNS() throws Exception {
        this.sessoesAtivas = new ConcurrentHashMap<>();
        
        System.out.println("[GEODNS] A gerar chaves RSA (2048 bits) para o Router...");
        this.parChavesRSA = RSAUtils.gerarParDeChaves();
    }

    public void iniciar() {
        try (DatagramSocket socketServidor = new DatagramSocket(PORTA_GEODNS)) {
            System.out.println("[GEODNS] Servidor UDP a rodar na porta " + PORTA_GEODNS);
            System.out.println("[GEODNS] A aguardar consultas de localização...");

            while (true) {
                byte[] buffer = new byte[4096];
                DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
                
                socketServidor.receive(pacoteRecebido);
                String idCliente = pacoteRecebido.getAddress().getHostAddress() + ":" + pacoteRecebido.getPort();

                new Thread(new ProcessadorGeoDNS(socketServidor, pacoteRecebido, idCliente)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class SessaoGeo {
        private final SecretKey chaveAES;
        private final PublicKey chavePublicaRSA;

        public SessaoGeo(SecretKey chaveAES, PublicKey chavePublicaRSA) {
            this.chaveAES = chaveAES;
            this.chavePublicaRSA = chavePublicaRSA;
        }
    }

    class ProcessadorGeoDNS implements Runnable {
        private final DatagramSocket socket;
        private final DatagramPacket pacoteRecebido;
        private final String idCliente;

        public ProcessadorGeoDNS(DatagramSocket socket, DatagramPacket pacoteRecebido, String idCliente) {
            this.socket = socket;
            this.pacoteRecebido = pacoteRecebido;
            this.idCliente = idCliente;
        }

        @Override
        public void run() {
            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(pacoteRecebido.getData(), 0, pacoteRecebido.getLength());
                ObjectInputStream ois = new ObjectInputStream(bais);

                int operacao = ois.readInt();

                if (operacao == 0) {

                    enviarObjeto(parChavesRSA.getPublic(), pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                    
                } else if (operacao == 1) {
            
                    PublicKey chavePubCliente = (PublicKey) ois.readObject();
                    byte[] aesCifrado = (byte[]) ois.readObject();

                    byte[] aesBytes = RSAUtils.decifrarHandshake(aesCifrado, parChavesRSA.getPrivate());
                    SecretKey chaveAES = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");

                    sessoesAtivas.put(idCliente, new SessaoGeo(chaveAES, chavePubCliente));
                    System.out.println("[GEODNS] Handshake UDP concluído com o cliente " + idCliente);

                } else if (operacao == 2) {
       
                    Pacote pacote = (Pacote) ois.readObject();
                    SessaoGeo sessao = sessoesAtivas.get(idCliente);

                    if (sessao == null) throw new SecurityException("Cliente não autenticado.");

                    byte[] payloadAberto = CryptoManager.abrirPacote(pacote, sessao.chaveAES, sessao.chavePublicaRSA);
                    String comando = new String(payloadAberto, StandardCharsets.UTF_8);

                    System.out.println("[GEODNS] Cliente questionou: " + comando);

                    String respostaRota;
                    if (comando.startsWith("ONDE")) {
                        String[] cmdPartes = comando.trim().split("\\s+");
                        String alvo = cmdPartes.length > 1 ? cmdPartes[1] : "?";
                        String local = cmdPartes.length > 2 ? cmdPartes[2] : "desconhecida";
                        System.out.println("[GEODNS] Consulta por '" + alvo + "' a partir de '" + local + "'.");
                        respostaRota = "127.0.0.1:8001"; 
                        System.out.println("[GEODNS] A redirecionar cliente para o Edge em " + respostaRota);
                    } else {
                        respostaRota = "Erro na entrada de dados. Tente outra vez!";
                    }

                    Pacote pacoteResposta = CryptoManager.gerarPacote(
                            respostaRota.getBytes(StandardCharsets.UTF_8),
                            sessao.chaveAES,
                            parChavesRSA.getPrivate()
                    );

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeInt(2); 
                    oos.writeObject(pacoteResposta);
                    oos.flush();
                    byte[] bytesEnvio = baos.toByteArray();

                    socket.send(new DatagramPacket(bytesEnvio, bytesEnvio.length, pacoteRecebido.getAddress(), pacoteRecebido.getPort()));
                }

            } catch (SecurityException | java.security.GeneralSecurityException se) {
                System.err.println("[GEODNS-ALERTA] Falha de integridade com " + idCliente + ": pacote descartado.");
            } catch (Exception e) {
                System.err.println("[GEODNS-ERRO] " + e.getMessage());
            }
        }

        private void enviarObjeto(Object obj, InetAddress endereco, int porta) throws Exception {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(obj);
            oos.flush();
            byte[] bytes = baos.toByteArray();
            socket.send(new DatagramPacket(bytes, bytes.length, endereco, porta));
        }
    }

    public static void main(String[] args) {
        try {
            new GeoDNS().iniciar();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}