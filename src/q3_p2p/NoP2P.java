package q3_p2p;

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
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class NoP2P {

    private final int idLocal;
    private final int portaLocal;
    private final int portaSucessor;
    
    private final List<String> arquivosLocais;

    private volatile Socket socketSucessor;
    private volatile ObjectOutputStream outSucessor;
    private volatile ObjectInputStream inSucessor;

    private volatile Socket socketAntecessor;
    private volatile ObjectOutputStream outAntecessor;
    private volatile ObjectInputStream inAntecessor;

    private final KeyPair meuParRSA;
    private volatile SecretKey aesParaSucessor;
    private volatile PublicKey rsaSucessor;
    
    private volatile SecretKey aesDoAntecessor;
    private volatile PublicKey rsaAntecessor;

    public NoP2P(int id) throws Exception {
        this.idLocal = id;
        this.portaLocal = 9000 + id; 
        this.portaSucessor = (id == 5) ? 9000 : 9000 + id + 1; 
        
        this.arquivosLocais = gerarArquivos(id);
        this.meuParRSA = RSAUtils.gerarParDeChaves();
        
        System.out.println("==================================================");
        System.out.println("[P" + idLocal + "] INICIALIZADO NA PORTA " + portaLocal);
        System.out.println("[P" + idLocal + "] Arquivos guardados: " + arquivosLocais.get(0) + " a " + arquivosLocais.get(arquivosLocais.size()-1));
        System.out.println("==================================================");
    }

    private List<String> gerarArquivos(int id) {
        List<String> lista = new ArrayList<>();
        int inicio = (id * 10) + 1;
        for (int i = inicio; i < inicio + 10; i++) {
            lista.add("arquivo" + i + ".ext");
        }
        return lista;
    }

    public void iniciar() {
        new Thread(this::aguardarAntecessor).start();
        new Thread(this::conectarAoSucessor).start();
        menuUsuario();
    }

    private void aguardarAntecessor() {
        try (ServerSocket serverSocket = new ServerSocket(portaLocal)) {
            System.out.println("[P" + idLocal + "] A escuta do antecessor...");
            while (true) {
            try {
            this.socketAntecessor = serverSocket.accept();
            this.outAntecessor = new ObjectOutputStream(socketAntecessor.getOutputStream());
            
            // evita deadlock
            this.outAntecessor.flush();
            this.inAntecessor = new ObjectInputStream(socketAntecessor.getInputStream());
            
            // Handshake 
            outAntecessor.writeObject(meuParRSA.getPublic());
            outAntecessor.flush();

            this.rsaAntecessor = (PublicKey) inAntecessor.readObject();
            byte[] aesCifrado = (byte[]) inAntecessor.readObject();
            
            byte[] aesBytes = RSAUtils.decifrarHandshake(aesCifrado, meuParRSA.getPrivate());
            this.aesDoAntecessor = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");
            System.out.println("[P" + idLocal + "] [SEGURANÇA] Handshake com Antecessor concluído.");
            
            while (true) {
                Pacote pacoteRecebido = (Pacote) inAntecessor.readObject();
                
                try {
                    byte[] payloadAberto = CryptoManager.abrirPacote(pacoteRecebido, aesDoAntecessor, rsaAntecessor);
                    System.out.println("[P" + idLocal + "] [SEGURANÇA] Assinatura do antecessor validada (RSA OK).");
                    String mensagem = new String(payloadAberto, StandardCharsets.UTF_8);
                    
                    processarMensagemDaRede(mensagem);
                    
                } catch (SecurityException | java.security.GeneralSecurityException se) {
                
                    System.err.println("\n[P" + idLocal + "-ALERTA] FALHA DE INTEGRIDADE DETETADA!");
                    System.err.println("Pacote recebido do antecessor adulterado ou com assinatura inválida.");
                    System.err.println("Ação: Pacote DESCARTADO. O roteamento foi interrompido para proteger o anel.\n");
                } catch (Exception e) {
                    System.err.println("[P" + idLocal + "-ERRO] Mensagem malformada descartada: " + e.getMessage());
                }
            }
            } catch (java.io.EOFException | java.net.SocketException e) {
                System.err.println("[P" + idLocal + "-Erro] Antecessor desconectou, aguardando reconexão...");
                try { if (socketAntecessor != null) socketAntecessor.close(); } catch (Exception ignored) {}
            } catch (Exception e) {
                System.err.println("[P" + idLocal + "-Erro] Falha com antecessor: " + e.getMessage() + " (aguardando reconexão)");
                try { if (socketAntecessor != null) socketAntecessor.close(); } catch (Exception ignored) {}
                try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
            }
            }
        } catch (Exception e) {
            System.err.println("[P" + idLocal + "-Erro] Não foi possível escutar na porta " + portaLocal + ": " + e.getMessage());
        }
    }

    private void conectarAoSucessor() {
        // reconecta se o socket cair
        while (true) {
            try {
                Socket cur = socketSucessor;
                if (cur == null || cur.isClosed() || !cur.isConnected() || outSucessor == null || aesParaSucessor == null) {
                    Socket s = new Socket("127.0.0.1", portaSucessor);
                    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
                    oos.flush(); // evita deadlock de header
                    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
                    this.socketSucessor = s;
                    this.outSucessor = oos;
                    this.inSucessor = ois;
                    
                    // Handshake
                    this.rsaSucessor = (PublicKey) inSucessor.readObject();
                    
                    this.aesParaSucessor = AESUtils.gerarChave();
                    byte[] aesCifrado = RSAUtils.cifrarHandshake(aesParaSucessor.getEncoded(), rsaSucessor);
                    
                    outSucessor.writeObject(meuParRSA.getPublic());
                    outSucessor.writeObject(aesCifrado);
                    outSucessor.flush();
                    System.out.println("[P" + idLocal + "] [SEGURANÇA] Handshake com Sucessor concluído.");
                }
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
            } catch (Exception e) {
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
            }
        }
    }
    private void processarMensagemDaRede(String mensagem) {
        // formato: BUSCA|alvo|origem  ou  RESPOSTA|destino|conteudo
        String[] partes = mensagem.split("\\|", -1);
        if (partes.length < 3) {
            System.err.println("[P" + idLocal + "-ERRO] Mensagem malformada descartada (sem repasse).");
            return;
        }
        String tipo = partes[0];

        if (tipo.equals("BUSCA")) {
            String alvo = partes[1];
            String origem = partes[2];
            if (!isArquivoValido(alvo) || !origem.matches("P[0-5]")) {
                System.err.println("[P" + idLocal + "-ERRO] BUSCA malformada descartada (sem repasse).");
                return;
            }
            System.out.println("[P" + idLocal + "] Recebeu BUSCA por '" + alvo + "' originada em " + origem + " (tráfego salto a salto)");

            if (arquivosLocais.contains(alvo)) {
                System.out.println("[P" + idLocal + "] SUCESSO: Arquivo encontrado no meu disco local!");
                System.out.println("[P" + idLocal + "] A gerar pacote de RESPOSTA e a devolver ao anel...");
                
                String conteudoSimulado = "[Simulação: Conteúdo do " + alvo + " resgatado no P" + idLocal + "]";
                String resposta = "RESPOSTA|" + origem + "|" + conteudoSimulado;
                
                repassarParaSucessor(resposta, false);
            } else {
                System.out.println("[P" + idLocal + "] Ficheiro não encontrado. A re-encriptar e repassar ao sucessor...");
                repassarParaSucessor(mensagem, false);
            }
            
        } else if (tipo.equals("RESPOSTA")) {
            String destinoFinal = partes[1];

            String conteudo = mensagem.substring(tipo.length() + 1 + destinoFinal.length() + 1);
            if (!destinoFinal.matches("P[0-5]")) {
                System.err.println("[P" + idLocal + "-ERRO] RESPOSTA malformada descartada (sem repasse).");
                return;
            }

            if (destinoFinal.equals("P" + idLocal)) {
                System.out.println("\n==================================================");
                System.out.println("[SUCESSO ABSOLUTO] RESPOSTA CHEGOU À ORIGEM!");
                System.out.println("Conteúdo: " + conteudo);
                System.out.println("==================================================\n");
            } else {
                System.out.println("[P" + idLocal + "] Repassando pacote de RESPOSTA em direção a " + destinoFinal + "...");
                repassarParaSucessor(mensagem, false);
            }
        } else {
            System.err.println("[P" + idLocal + "-ERRO] Tipo desconhecido descartado (sem repasse): " + tipo);
        }
    }

    // válida a mensagem
    static boolean isArquivoValido(String nome) {
        if (nome == null || !nome.matches("arquivo\\d+\\.ext")) return false;
        try {
            int n = Integer.parseInt(nome.substring(7, nome.length() - 4));
            return n >= 1 && n <= 60;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean repassarParaSucessor(String mensagemAberta, boolean simularAdulteracao) {
        synchronized (this) {
        try {
            if (outSucessor == null || aesParaSucessor == null) {
                System.err.println("[P" + idLocal + "] Aguarde. O sucessor ainda não está online.");
                return false;
            }

            
            byte[] msgBytes = mensagemAberta.getBytes(StandardCharsets.UTF_8);
            Pacote pacoteSeguro = CryptoManager.gerarPacote(msgBytes, aesParaSucessor, meuParRSA.getPrivate());

            if (simularAdulteracao) {
                System.out.println("[P" + idLocal + "] (SIMULAÇÃO) A corromper a Assinatura RSA do pacote antes do envio...");
                pacoteSeguro = new Pacote(pacoteSeguro.getTextoCifrado(), new byte[256]);
            }

            outSucessor.writeObject(pacoteSeguro);
            outSucessor.flush();
            return true;

        } catch (java.io.IOException ioe) {
    
            System.err.println("[P" + idLocal + "-Erro] Ligação com sucessor quebrada, reconectando...");
            try { if (socketSucessor != null) socketSucessor.close(); } catch (Exception ignored) {}
            socketSucessor = null; outSucessor = null; aesParaSucessor = null;
            return false;
        } catch (Exception e) {
            System.err.println("[P" + idLocal + "-Erro] Falha ao enviar pacote ao sucessor: " + e.getMessage());
            return false;
        }
        }
    }

    private void menuUsuario() {
        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNextLine()) {
            System.out.println("\n[P" + idLocal + "] Comandos: 'buscar arquivoX.ext', 'fraude arquivoX.ext' ou 'sair'");
            String input;
            try {
                input = scanner.nextLine().trim();
            } catch (java.util.NoSuchElementException e) {
                break; 
            }
            
            if (input.equalsIgnoreCase("sair")) {
                encerrar();
                break;
            }

            String[] argsInput = input.split("\\s+");
            if (argsInput.length != 2) {
                System.out.println("Erro na entrada de dados. Tente outra vez!");
                continue;
            }

            String acao = argsInput[0];
            String alvo = argsInput[1];

            if (!acao.equalsIgnoreCase("buscar") && !acao.equalsIgnoreCase("fraude")) {
                System.out.println("Erro na entrada de dados. Tente outra vez!");
                continue;
            }

            // rejeita fora 1-60 e sem número sem propagar.
            if (!isArquivoValido(alvo)) {
                System.out.println("Erro na entrada de dados. Tente outra vez!");
                continue;
            }

            if (acao.equalsIgnoreCase("buscar")) {
                String mensagemBusca = "BUSCA|" + alvo + "|P" + idLocal;
                boolean ok = repassarParaSucessor(mensagemBusca, false);
                if (ok) System.out.println("[P" + idLocal + "] Busca por " + alvo + " encriptada e inserida no anel!");
                
            } else if (acao.equalsIgnoreCase("fraude")) {
                String mensagemBusca = "BUSCA|" + alvo + "|P" + idLocal;
                boolean ok = repassarParaSucessor(mensagemBusca, true);
                if (ok) System.out.println("[P" + idLocal + "] Ataque iniciado! Pacote corrompido foi enviado ao anel.");
            }
        }
        scanner.close();
    }

    // encerra o nó e fecha sockets
    private void encerrar() {
        System.out.println("[P" + idLocal + "] Encerrando este nó...");
        try { if (socketSucessor != null) socketSucessor.close(); } catch (Exception ignored) {}
        try { if (socketAntecessor != null) socketAntecessor.close(); } catch (Exception ignored) {}
        System.exit(0);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Erro: Forneça o ID do nó (0 a 5) como argumento da linha de comandos.");
            return;
        }
        try {
            int id = Integer.parseInt(args[0]);
            if (id < 0 || id > 5) {
                System.out.println("Erro na entrada de dados. Tente outra vez!");
                return;
            }
            new NoP2P(id).iniciar();
        } catch (NumberFormatException e) {
            System.out.println("Erro na entrada de dados. Tente outra vez!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}