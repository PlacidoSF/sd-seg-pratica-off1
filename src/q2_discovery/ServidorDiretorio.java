package q2_discovery;

import crypto.CryptoManager;
import crypto.RSAUtils;
import shared.Pacote;

import javax.crypto.SecretKey;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;


public class ServidorDiretorio {

    private static final int PORTA_DIRETORIO = 6001;
    
    private final ConcurrentHashMap<String, List<String>> catalogoServicos;
    
    private final KeyPair parChavesRSA;

    public ServidorDiretorio() throws Exception {
        this.catalogoServicos = new ConcurrentHashMap<>();
        
        System.out.println("[DIRETORIO] A gerar chaves RSA (2048 bits) para o Catálogo...");
        this.parChavesRSA = RSAUtils.gerarParDeChaves();
    }

    public void iniciar() {
        try (ServerSocket serverSocket = new ServerSocket(PORTA_DIRETORIO)) {
            System.out.println("[DIRETORIO] Servidor de Diretório TCP rodando na porta " + PORTA_DIRETORIO);
            System.out.println("[DIRETORIO] A aguardar inscrições e buscas...");

            while (true) {
                Socket conexao = serverSocket.accept();
                System.out.println("\n[DIRETORIO] Nova ligação TCP estabelecida com " + conexao.getInetAddress().getHostAddress());
                                
                new Thread(new ThreadTrataConexao(conexao)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class ThreadTrataConexao implements Runnable {
        private final Socket socket;

        public ThreadTrataConexao(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())
            ) {
                oos.flush();
                oos.writeObject(parChavesRSA.getPublic());
                oos.flush();

                PublicKey chavePubCliente = (PublicKey) ois.readObject();
                byte[] aesCifrado = (byte[]) ois.readObject();

                byte[] aesBytes = RSAUtils.decifrarHandshake(aesCifrado, parChavesRSA.getPrivate());
                SecretKey chaveAES = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");
                
                System.out.println("[DIRETORIO] Handshake TCP concluído. Canal seguro aberto.");

                Pacote pacoteRecebido = (Pacote) ois.readObject();
                
                byte[] payloadAberto = CryptoManager.abrirPacote(pacoteRecebido, chaveAES, chavePubCliente);
                String comando = new String(payloadAberto, StandardCharsets.UTF_8);

                String resposta = processarComando(comando);

                Pacote pacoteResposta = CryptoManager.gerarPacote(
                        resposta.getBytes(StandardCharsets.UTF_8), 
                        chaveAES, 
                        parChavesRSA.getPrivate()
                );
                oos.writeObject(pacoteResposta);
                oos.flush();

                System.out.println("[DIRETORIO] Requisição processada e resposta enviada. A encerrar sessão TCP.");

            } catch (SecurityException | java.security.GeneralSecurityException se) {
                System.err.println("[DIRETORIO-ALERTA] Falha de integridade: " + se.getMessage());
            } catch (Exception e) {
                System.err.println("[DIRETORIO-ERRO] Erro na comunicação TCP: " + e.getMessage());
            }
        }

        private String processarComando(String comando) {
            String[] partes = comando.trim().split("\\s+");
            if (partes.length < 2) return "Erro na entrada de dados. Tente outra vez!";
            String acao = partes[0];
            String servico = partes[1].replace("_", " "); 
            if (acao.equals("REGISTRAR")) {
                if (partes.length < 3 || !partes[2].matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d+")) {
                    return "Erro na entrada de dados. Tente outra vez!";
                }
                String ipPorta = partes[2];
                
            
                catalogoServicos.putIfAbsent(servico, new CopyOnWriteArrayList<>());
                
                if (!catalogoServicos.get(servico).contains(ipPorta)) {
                    catalogoServicos.get(servico).add(ipPorta);
                }
                
                System.out.println("[DIRETORIO] Registo efetuado: '" + servico + "' -> " + ipPorta);
                return "OK: Servico registrado com sucesso.";

            } else if (acao.equals("BUSCAR")) {
                List<String> provedores = catalogoServicos.get(servico);
                
                if (provedores == null || provedores.isEmpty()) {
                    System.out.println("[DIRETORIO] Busca falhou: Serviço '" + servico + "' não possui instâncias ativas.");
                    return "ERRO: Serviço não encontrado.";
                }
                
                // junta a lista num formato simples
                String listaIps = String.join(",", provedores);
                System.out.println("[DIRETORIO] Busca atendida para '" + servico + "'. Devolvendo: " + listaIps);
                return listaIps;
            }
            
            return "ERRO: Comando desconhecido.";
        }
    }

    public static void main(String[] args) {
        try {
            new ServidorDiretorio().iniciar();
        } catch (Exception e) {
            System.err.println("Erro crítico no Diretório: " + e.getMessage());
        }
    }
}