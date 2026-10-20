package q4_cdn;

import crypto.AESUtils;
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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

public class EdgeServer {

    private final int portaEdge;

    private static final long TTL_MS = 15000;
    
    private final String ipOrigem = "127.0.0.1";
    private final int portaOrigem = 8000;

    private final KeyPair parChavesRSA;
    private SecretKey aesOrigem;
    private PublicKey rsaOrigem;

    private ObjectOutputStream outOrigem;
    private ObjectInputStream inOrigem;
    private final Object lockOrigem = new Object();
    
    private final ArrayBlockingQueue<String> filaRespostasOrigem = new ArrayBlockingQueue<>(1);


    static class RegistroCache {
        final String conteudo;
        final long expiracaoTTL;

        public RegistroCache(String conteudo, long ttlMilissegundos) {
            this.conteudo = conteudo;
            this.expiracaoTTL = System.currentTimeMillis() + ttlMilissegundos;
        }
        
        public boolean isExpirado() {
            return System.currentTimeMillis() > expiracaoTTL;
        }
    }

    private final Map<String, RegistroCache> cacheLRU = Collections.synchronizedMap(
            new LinkedHashMap<String, RegistroCache>(100, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, RegistroCache> eldest) {
                    return size() > 100; // Mantém no máximo 100 itens
                }
            }
    );

    public EdgeServer(int porta) throws Exception {
        this.portaEdge = porta;
        System.out.println("[EDGE] A gerar chaves RSA (2048 bits)...");
        this.parChavesRSA = RSAUtils.gerarParDeChaves();
    }

    static boolean isArquivoValido(String nome) {
        if (nome == null || !nome.matches("arquivo\\d+\\.ext")) return false;
        try {
            int n = Integer.parseInt(nome.substring(7, nome.length() - 4));
            return n >= 1 && n <= 1000;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public void iniciar() {
        try {
           
            conectarAOrigem();

            ServerSocket serverSocket = new ServerSocket(portaEdge);
            System.out.println("[EDGE] Nó de Cache a rodar na porta " + portaEdge);
            System.out.println("[EDGE] A aguardar pedidos (GET) dos clientes...");

            while (true) {
                Socket clienteSocket = serverSocket.accept();
                new Thread(new TratadorCliente(clienteSocket)).start();
            }

        } catch (Exception e) {
            System.err.println("[EDGE-ERRO CRÍTICO] " + e.getMessage());
        }
    }

    private void conectarAOrigem() throws Exception {
        System.out.println("[EDGE] A ligar ao Servidor de Origem para sincronização...");
        Exception falha = null;
        for (int tentativa = 1; tentativa <= 10; tentativa++) {
            try {
                Socket socketOrigem = new Socket(ipOrigem, portaOrigem);
                socketOrigem.setSoTimeout(0);
                outOrigem = new ObjectOutputStream(socketOrigem.getOutputStream());
                outOrigem.flush(); // evita deadlock de header
                inOrigem = new ObjectInputStream(socketOrigem.getInputStream());

                this.rsaOrigem = (PublicKey) inOrigem.readObject();
                this.aesOrigem = AESUtils.gerarChave();
                byte[] aesCifrado = RSAUtils.cifrarHandshake(aesOrigem.getEncoded(), rsaOrigem);

                outOrigem.writeObject(parChavesRSA.getPublic());
                outOrigem.writeObject(aesCifrado);
                outOrigem.flush();
                
                System.out.println("[EDGE] Sessão segura estabelecida com a Origem.");

                Thread t = new Thread(this::escutarOrigem);
                t.setDaemon(false);
                t.start();
                return;
            } catch (Exception e) {
                falha = e;
                System.err.println("[EDGE] Origem indisponível (tentativa " + tentativa + "/10), aguardando...");
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
            }
        }
        throw new java.io.IOException("Não foi possível conectar à Origem após 10 tentativas: " + (falha == null ? "" : falha.getMessage()));
    }

    private void escutarOrigem() {
        try {
            while (true) {
                Pacote pctRecebido;
                try {
                    pctRecebido = (Pacote) inOrigem.readObject();
                } catch (java.io.EOFException | java.net.SocketException e) {
                    break;
                }
                try {
                    byte[] payloadAberto = CryptoManager.abrirPacote(pctRecebido, aesOrigem, rsaOrigem);
                    System.out.println("[EDGE-SEG] HMAC e assinatura da Origem validados.");
                    String mensagem = new String(payloadAberto, StandardCharsets.UTF_8);

                    if (mensagem.startsWith("INVALIDATE /")) {
                        String ficheiroInvalido = mensagem.substring(12).trim();
                        cacheLRU.remove(ficheiroInvalido);
                        System.out.println("\n[EDGE-PUSH] Comando da Origem recebido! O ficheiro '" + ficheiroInvalido + "' foi purgado da Cache.");
                    } else {
                       if (!filaRespostasOrigem.offer(mensagem)) {
                            filaRespostasOrigem.poll();
                            filaRespostasOrigem.offer(mensagem);
                        }
                    }
                } catch (SecurityException | java.security.GeneralSecurityException se) {
                    System.err.println("[EDGE-ALERTA] Invalidação/resposta da Origem com falha de integridade descartada.");
                }
            }
        } catch (Exception e) {
            System.err.println("[EDGE-AVISO] Ligação com a Origem interrompida.");
        }
    }

    class TratadorCliente implements Runnable {
        private final Socket socket;

        public TratadorCliente(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (ObjectOutputStream outCliente = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream inCliente = new ObjectInputStream(socket.getInputStream())) {
                outCliente.flush();
                socket.setSoTimeout(15000);

                outCliente.writeObject(parChavesRSA.getPublic());
                outCliente.flush();

                PublicKey rsaCliente = (PublicKey) inCliente.readObject();
                byte[] aesCifrado = (byte[]) inCliente.readObject();

                byte[] aesBytes = RSAUtils.decifrarHandshake(aesCifrado, parChavesRSA.getPrivate());
                SecretKey aesCliente = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");

                Pacote pctRequisicao = (Pacote) inCliente.readObject();
                byte[] reqAberta = CryptoManager.abrirPacote(pctRequisicao, aesCliente, rsaCliente);
                String requisicao = new String(reqAberta, StandardCharsets.UTF_8);

                System.out.println("\n[EDGE] Pedido recebido do cliente: " + requisicao);

                String respostaFinal;

                if (!requisicao.startsWith("GET /") || !isArquivoValido(requisicao.substring(5).trim())) {
                    respostaFinal = "Erro na entrada de dados. Tente outra vez!";
                    System.out.println("[EDGE] Nome inválido/fora da faixa detetado. Rejeitado na borda sem consultar a Origem.");
                } else {
                    String nomeFicheiro = requisicao.substring(5).trim(); // Extrai "arquivoX.ext"
                    respostaFinal = processarCacheHitMiss(nomeFicheiro);
                }

                Pacote pctResposta = CryptoManager.gerarPacote(
                        respostaFinal.getBytes(StandardCharsets.UTF_8), 
                        aesCliente, 
                        parChavesRSA.getPrivate()
                );
                outCliente.writeObject(pctResposta);
                outCliente.flush();

            } catch (SecurityException | java.security.GeneralSecurityException se) {
                System.err.println("[EDGE-ALERTA] Violação de Segurança: " + se.getMessage());
            } catch (Exception e) {
                System.err.println("[EDGE-ERRO] " + e.getMessage());
            }
        }

        private String processarCacheHitMiss(String nomeFicheiro) throws Exception {
            RegistroCache registo = cacheLRU.get(nomeFicheiro);

            if (registo != null && !registo.isExpirado()) {
                System.out.println("[EDGE] CACHE HIT para '" + nomeFicheiro + "'. A devolver da memória.");
                return "200 OK | Cache: HIT | Length: " + registo.conteudo.length() + "\n" + registo.conteudo;
            }

            System.out.println("[EDGE] CACHE MISS (ou expirado) para '" + nomeFicheiro + "'. A solicitar à Origem...");
            
            String conteudoOrigem;
            synchronized (lockOrigem) {
                // descarta resposta tardia de MISS anterior, se houver
                filaRespostasOrigem.clear();
                
                String pedidoOrigem = "GET /" + nomeFicheiro;
                Pacote pctMiss = CryptoManager.gerarPacote(
                        pedidoOrigem.getBytes(StandardCharsets.UTF_8), 
                        aesOrigem, 
                        parChavesRSA.getPrivate()
                );
                
                outOrigem.writeObject(pctMiss);
                outOrigem.flush();

                conteudoOrigem = filaRespostasOrigem.poll(10, java.util.concurrent.TimeUnit.SECONDS);
                if (conteudoOrigem == null) {
                    return "Erro na entrada de dados. Tente outra vez!";
                }
            }

            if (conteudoOrigem.startsWith("ERRO:")) {
                return conteudoOrigem;
            }

            cacheLRU.put(nomeFicheiro, new RegistroCache(conteudoOrigem, TTL_MS));
            System.out.println("[EDGE] Ficheiro '" + nomeFicheiro + "' gravado no Cache LRU.");

            return "200 OK | Cache: MISS | Length: " + conteudoOrigem.length() + "\n" + conteudoOrigem;
        }
    }

    public static void main(String[] args) {
        int porta = 8001;
        if (args.length > 0) {
            try {
                porta = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.out.println("Erro na entrada de dados. Tente outra vez!");
                return;
            }
        }
        try {
            new EdgeServer(porta).iniciar();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}