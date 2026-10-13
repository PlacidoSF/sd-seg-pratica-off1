package q4_cdn;

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
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class OriginServer {

    private static final int PORTA_ORIGEM = 8000;
    
    // banco de dados simulando 1000 arquivos
    private final ConcurrentHashMap<String, String> bancoDeDados;
    
    private final CopyOnWriteArrayList<SessaoEdge> edgesAtivos;
    
    private final KeyPair parChavesRSA;

    public OriginServer() throws Exception {
        this.bancoDeDados = new ConcurrentHashMap<>();
        this.edgesAtivos = new CopyOnWriteArrayList<>();
        
        System.out.println("[ORIGEM] A gerar chaves RSA (2048 bits)...");
        this.parChavesRSA = RSAUtils.gerarParDeChaves();
        
        inicializarBancoDeDados();
    }

    private void inicializarBancoDeDados() {
        System.out.println("[ORIGEM] A popular a base de dados mestre com 1000 ficheiros...");
        for (int i = 1; i <= 1000; i++) {
            bancoDeDados.put("arquivo" + i + ".ext", "Conteúdo oficial, pesado e seguro do [arquivo" + i + ".ext]");
        }
    }

    public void iniciar() {
        new Thread(this::aguardarEdges).start();
        
        menuAdmin();
    }

    private void aguardarEdges() {
        try (ServerSocket serverSocket = new ServerSocket(PORTA_ORIGEM)) {
            System.out.println("[ORIGEM] Servidor TCP mestre a rodar na porta " + PORTA_ORIGEM);

            while (true) {
                Socket conexaoEdge = serverSocket.accept();
                System.out.println("\n[ORIGEM] Nova ligação TCP de um Edge detetada: " + conexaoEdge.getInetAddress().getHostAddress());
                new Thread(new TratadorEdge(conexaoEdge)).start();
            }
        } catch (Exception e) {
            System.err.println("[ORIGEM-ERRO CRÍTICO] " + e.getMessage());
        }
    }


    class SessaoEdge {
        final ObjectOutputStream oos;
        final SecretKey chaveAES;
        final PublicKey chavePubEdge;
        final String ip;

        public SessaoEdge(ObjectOutputStream oos, SecretKey chaveAES, PublicKey chavePubEdge, String ip) {
            this.oos = oos;
            this.chaveAES = chaveAES;
            this.chavePubEdge = chavePubEdge;
            this.ip = ip;
        }
    }

    class TratadorEdge implements Runnable {
        private final Socket socket;

        public TratadorEdge(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            SessaoEdge sessaoAtual = null;
            try {
                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                oos.flush(); 
                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

                oos.writeObject(parChavesRSA.getPublic());
                oos.flush();

                PublicKey chavePubEdge = (PublicKey) ois.readObject();
                byte[] aesCifrado = (byte[]) ois.readObject();

                byte[] aesBytes = RSAUtils.decifrarHandshake(aesCifrado, parChavesRSA.getPrivate());
                SecretKey chaveAES = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");

                sessaoAtual = new SessaoEdge(oos, chaveAES, chavePubEdge, socket.getInetAddress().getHostAddress());
                edgesAtivos.add(sessaoAtual);
                System.out.println("[ORIGEM] Handshake TCP concluído. Edge registado com sucesso.");

                while (true) {
                    Pacote pctRecebido;
                    try {
                        pctRecebido = (Pacote) ois.readObject();
                    } catch (java.io.EOFException | java.net.SocketException e) {
                        break; 
                    }
                    
                    try {
                        byte[] payloadAberto = CryptoManager.abrirPacote(pctRecebido, chaveAES, chavePubEdge);
                        String comando = new String(payloadAberto, StandardCharsets.UTF_8);
                        
                        System.out.println("[ORIGEM] Edge requisitou: " + comando);

                        if (comando.startsWith("GET /")) {
                            String ficheiroAlvo = comando.substring(5).trim();
                            
                            String resposta;
                            if (bancoDeDados.containsKey(ficheiroAlvo)) {
                                resposta = bancoDeDados.get(ficheiroAlvo);
                            } else {
                                resposta = "ERRO: Ficheiro não existe na base de dados.";
                            }

                            Pacote pctResposta = CryptoManager.gerarPacote(
                                    resposta.getBytes(StandardCharsets.UTF_8), 
                                    chaveAES, 
                                    parChavesRSA.getPrivate()
                            );
                            synchronized (oos) {
                                oos.writeObject(pctResposta);
                                oos.flush();
                            }
                            System.out.println("[ORIGEM] Ficheiro servido de volta ao Edge via canal seguro (assinatura RSA).");
                        } else {
                            Pacote pctErro = CryptoManager.gerarPacote(
                                    "Erro na entrada de dados. Tente outra vez!".getBytes(StandardCharsets.UTF_8),
                                    chaveAES, parChavesRSA.getPrivate());
                            synchronized (oos) {
                                oos.writeObject(pctErro);
                                oos.flush();
                            }
                        }
                    } catch (SecurityException | java.security.GeneralSecurityException se) {
                        System.err.println("[ORIGEM-ALERTA] Falha de integridade do Edge " + socket.getInetAddress().getHostAddress() + ": pacote descartado.");
                    }
                }

            } catch (Exception e) {
                System.err.println("[ORIGEM-AVISO] Ligação TCP com o Edge cortada.");
            } finally {
                if (sessaoAtual != null) {
                    edgesAtivos.remove(sessaoAtual);
                }
            }
        }
    }

    private void menuAdmin() {
        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNextLine()) {
            System.out.println("\n[ORIGEM] Comando: 'invalidate arquivoX.ext' (Limpar cache dos Edges) ou 'sair'");
            String input;
            try {
                input = scanner.nextLine().trim();
            } catch (java.util.NoSuchElementException e) {
                break;
            }

            if (input.equalsIgnoreCase("sair")) {
                System.out.println("[ORIGEM] Encerrando servidor de origem...");
                System.exit(0);
            }

            if (input.toLowerCase().startsWith("invalidate ")) {
                String ficheiro = input.substring(11).trim();
                dispararInvalidacao(ficheiro);
            } else {
                System.out.println("Erro na entrada de dados. Tente outra vez!");
            }
        }
        scanner.close();
    }

    private void dispararInvalidacao(String ficheiro) {
        if (!ficheiro.matches("arquivo\\d+\\.ext")) {
            System.out.println("Erro na entrada de dados. Tente outra vez!");
            return;
        }
        if (edgesAtivos.isEmpty()) {
            System.out.println("[ORIGEM] Aviso: Não há Edges conectados no momento.");
            return;
        }

        String comandoInvalidate = "INVALIDATE /" + ficheiro;
        byte[] payloadCmd = comandoInvalidate.getBytes(StandardCharsets.UTF_8);

        System.out.println("[ORIGEM] A empurrar a invalidação para " + edgesAtivos.size() + " Edges ativos...");

        for (SessaoEdge sessao : edgesAtivos) {
            try {
                // Cifra e assina com a chave específica daquela sessão com o Edge
                Pacote pctPush = CryptoManager.gerarPacote(payloadCmd, sessao.chaveAES, parChavesRSA.getPrivate());
                synchronized (sessao.oos) {
                    sessao.oos.writeObject(pctPush);
                    sessao.oos.flush();
                }
                System.out.println(" -> Push executado com sucesso para Edge em " + sessao.ip);
            } catch (Exception e) {
                System.err.println(" -> Falha ao empurrar para Edge em " + sessao.ip + ". A remover sessão morta.");
                edgesAtivos.remove(sessao);
            }
        }
    }

    public static void main(String[] args) {
        try {
            new OriginServer().iniciar();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}