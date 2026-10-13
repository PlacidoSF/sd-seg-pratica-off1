package q1_minidns;

import crypto.RSAUtils;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;

public class ServidorDNS {

    private static final int PORTA_SERVIDOR = 5000;

    private final ConcurrentHashMap<String, String> tabelaPrincipal;

    private final ConcurrentHashMap<String, SessaoSegura> tabelaChaves;

    private final KeyPair parChavesRSA;

    public ServidorDNS() throws Exception {
        this.tabelaPrincipal = new ConcurrentHashMap<>();
        this.tabelaChaves = new ConcurrentHashMap<>();
        
        System.out.println("[DNS] Gerando par de chaves RSA do Servidor...");
        this.parChavesRSA = RSAUtils.gerarParDeChaves();

        inicializarTabelaPrincipal();
    }

    private void inicializarTabelaPrincipal() {
        System.out.println("[DNS] Populando tabela DNS...");
        for (int i = 1; i <= 10; i++) {
            tabelaPrincipal.put("servidor" + i, "192.168.0." + (i * 10));
        }
    }

    public void iniciar() {
        try (DatagramSocket socketServidor = new DatagramSocket(PORTA_SERVIDOR)) {
            System.out.println("[DNS] Servidor UDP rodando na porta " + socketServidor.getLocalPort());
            System.out.println("[DNS] Aguardando conexões e consultas...");

            while (true) {
               
                byte[] buffer = new byte[4096];
                DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);

                socketServidor.receive(pacoteRecebido);

                String identificadorCliente = pacoteRecebido.getAddress().getHostAddress() + ":" + pacoteRecebido.getPort();

                ThreadProcessamento processador = new ThreadProcessamento(
                        socketServidor, 
                        pacoteRecebido, 
                        identificadorCliente
                );
                new Thread(processador).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class SessaoSegura {
        private final SecretKey chaveAES;
        private final PublicKey chavePublicaRSA;

        public SessaoSegura(SecretKey chaveAES, PublicKey chavePublicaRSA) {
            this.chaveAES = chaveAES;
            this.chavePublicaRSA = chavePublicaRSA;
        }

        public SecretKey getChaveAES() { return chaveAES; }
        public PublicKey getChavePublicaRSA() { return chavePublicaRSA; }
    }

    class ThreadProcessamento implements Runnable {
        private final DatagramSocket socket;
        private final DatagramPacket pacoteRecebido;
        private final String idCliente;

        public ThreadProcessamento(DatagramSocket socket, DatagramPacket pacoteRecebido, String idCliente) {
            this.socket = socket;
            this.pacoteRecebido = pacoteRecebido;
            this.idCliente = idCliente;
        }

       @Override
        public void run() {
            try {
        
                java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(pacoteRecebido.getData(), 0, pacoteRecebido.getLength());
                java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bais);

                
                int operacao = ois.readInt();

                if (operacao == 0) {
                    
                    enviarObjeto(parChavesRSA.getPublic(), pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                    System.out.println("[DNS] Handshake (Passo 3): Chave pública RSA enviada para " + idCliente);

                } else if (operacao == 1) {
                    
                    PublicKey chavePubCliente = (PublicKey) ois.readObject();
                    byte[] aesCifrado = (byte[]) ois.readObject();

                    byte[] aesBytes = crypto.RSAUtils.decifrarHandshake(aesCifrado, parChavesRSA.getPrivate());
                    SecretKey chaveAES = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");

                    tabelaChaves.put(idCliente, new SessaoSegura(chaveAES, chavePubCliente));
                    System.out.println("[DNS] Handshake concluído: Sessão segura estabelecida com " + idCliente);

                } else if (operacao == 2) {
                
                    shared.Pacote pacote = (shared.Pacote) ois.readObject();
                    SessaoSegura sessao = tabelaChaves.get(idCliente);

                    if (sessao == null) {
                        throw new SecurityException("Cliente não autenticado. Realize o handshake primeiro.");
                    }

                    byte[] payloadAberto = crypto.CryptoManager.abrirPacote(pacote, sessao.getChaveAES(), sessao.getChavePublicaRSA());
                    String comando = new String(payloadAberto, java.nio.charset.StandardCharsets.UTF_8);

                    processarComando(comando, sessao, pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                }

            } catch (SecurityException | GeneralSecurityException se) {
                System.err.println("[DNS-ALERTA] Falha de integridade com " + idCliente + ": Pacote adulterado ou remetente não autenticado.");
            } catch (Exception e) {
                System.err.println("[DNS-ERRO] Erro no processamento do cliente " + idCliente + ": " + e.getMessage());
            }
        }

        private void processarComando(String comando, SessaoSegura sessao, java.net.InetAddress endereco, int porta) throws Exception {
            String[] partes = comando.trim().split("\\s+");
            if (partes.length < 2) {
                responder("Erro na entrada de dados. Tente outra vez!", sessao, endereco, porta);
                return;
            }
            String acao = partes[0]; 
            String nomeServidor = partes[1];

            if (!nomeServidor.matches("servidor([1-9]|10)")) {
                responder("Erro na entrada de dados. Tente outra vez!", sessao, endereco, porta);
                return;
            }

            if (acao.equals("CONSULTAR")) {
                if (!tabelaPrincipal.containsKey(nomeServidor)) {
                    responder("Erro na entrada de dados. Tente outra vez!", sessao, endereco, porta);
                } else {
                   
                    responder(tabelaPrincipal.get(nomeServidor), sessao, endereco, porta);
                    System.out.println("[DNS] Consulta do " + nomeServidor + " respondida para " + idCliente);
                }
            } else if (acao.equals("ATUALIZAR")) {
                
                if (partes.length < 3 || !isIpValido(partes[2])) {
                    responder("Erro na entrada de dados. Tente outra vez!", sessao, endereco, porta);
                    return;
                }
                String novoIp = partes[2];
                tabelaPrincipal.put(nomeServidor, novoIp);
                System.out.println("[DNS] Binding dinâmico: " + nomeServidor + " atualizado para " + novoIp);

                
                responder("OK: " + nomeServidor + " atualizado para " + novoIp, sessao, endereco, porta);

                notificarClientes(nomeServidor, novoIp);
            } else {
                responder("Erro na entrada de dados. Tente outra vez!", sessao, endereco, porta);
            }
        }

        private boolean isIpValido(String ip) {
            if (!ip.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) return false;
            try {
                for (String oct : ip.split("\\.")) {
                    int v = Integer.parseInt(oct);
                    if (v < 0 || v > 255) return false;
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        private void responder(String mensagemResposta, SessaoSegura sessao, java.net.InetAddress endereco, int porta) throws Exception {
            
            shared.Pacote pacoteResposta = crypto.CryptoManager.gerarPacote(
                    mensagemResposta.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    sessao.getChaveAES(),
                    parChavesRSA.getPrivate()
            );

            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(baos);
            oos.writeInt(2); 
            oos.writeObject(pacoteResposta);
            oos.flush();
            byte[] bytesEnvio = baos.toByteArray();

            DatagramPacket pctEnvio = new DatagramPacket(bytesEnvio, bytesEnvio.length, endereco, porta);
            socket.send(pctEnvio);
        }

        private void notificarClientes(String nomeServidor, String novoIp) {
            String atualizacao = "ATUALIZACAO " + nomeServidor + " " + novoIp;
            int enviadas = 0;
            for (java.util.Map.Entry<String, SessaoSegura> e : tabelaChaves.entrySet()) {
                String idDestino = e.getKey();
                SessaoSegura sessaoDestino = e.getValue();
                try {
                    int sep = idDestino.lastIndexOf(':');
                    java.net.InetAddress endDest = java.net.InetAddress.getByName(idDestino.substring(0, sep));
                    int portaDest = Integer.parseInt(idDestino.substring(sep + 1));

                    shared.Pacote pct = crypto.CryptoManager.gerarPacote(
                            atualizacao.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                            sessaoDestino.getChaveAES(),
                            parChavesRSA.getPrivate());

                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(baos);
                    oos.writeInt(3); 
                    oos.writeObject(pct);
                    oos.flush();
                    byte[] bytes = baos.toByteArray();
                    socket.send(new DatagramPacket(bytes, bytes.length, endDest, portaDest));
                    enviadas++;
                } catch (Exception ex) {
                    System.err.println("[DNS-NOTIFY] Falha ao notificar " + idDestino + ": " + ex.getMessage());
                }
            }
            System.out.println("[DNS-NOTIFY] Notificação segura enviada para " + enviadas + " cliente(s).");
        }

        private void enviarObjeto(Object obj, java.net.InetAddress endereco, int porta) throws Exception {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(baos);
            oos.writeObject(obj);
            oos.flush();
            byte[] bytes = baos.toByteArray();
            socket.send(new DatagramPacket(bytes, bytes.length, endereco, porta));
        }
    }

    public static void main(String[] args) {
        try {
            new ServidorDNS().iniciar();
        } catch (Exception e) {
            System.err.println("Erro crítico: " + e.getMessage());
        }
    }
}