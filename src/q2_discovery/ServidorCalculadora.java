package q2_discovery;

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

public class ServidorCalculadora {

    private final int portaServidor;
    private final String nomeServico;
    
    private final String ipDiretorio = "127.0.0.1";
    private final int portaDiretorio = 6001;
    
    private final KeyPair parChavesRSA;

    public ServidorCalculadora(int porta, String servico) throws Exception {
        this.portaServidor = porta;
        this.nomeServico = servico;
        System.out.println("[S" + porta + "] A gerar chaves RSA (2048 bits)...");
        this.parChavesRSA = RSAUtils.gerarParDeChaves();
    }

    public void iniciar() {
        try {
            registrarNoDiretorio();

            iniciarServidorTCP();
            
        } catch (Exception e) {
            System.err.println("[S" + portaServidor + "] Falha crítica: " + e.getMessage());
        }
    }

    private void registrarNoDiretorio() throws Exception {
        System.out.println("[S" + portaServidor + "] A ligar ao Diretório para registo...");
        try (Socket socket = new Socket(ipDiretorio, portaDiretorio);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            oos.flush();

            PublicKey pubDiretorio = (PublicKey) ois.readObject();

            SecretKey aesTemp = AESUtils.gerarChave();
            byte[] aesCifrado = RSAUtils.cifrarHandshake(aesTemp.getEncoded(), pubDiretorio);
            
            oos.writeObject(parChavesRSA.getPublic());
            oos.writeObject(aesCifrado);
            oos.flush();

            String comando = "REGISTRAR " + nomeServico.replace(" ", "_") + " 127.0.0.1:" + portaServidor;
            Pacote pacoteRegisto = CryptoManager.gerarPacote(comando.getBytes(StandardCharsets.UTF_8), aesTemp, parChavesRSA.getPrivate());
            
            oos.writeObject(pacoteRegisto);
            oos.flush();

            Pacote pacoteResposta = (Pacote) ois.readObject();
            byte[] msgAberta = CryptoManager.abrirPacote(pacoteResposta, aesTemp, pubDiretorio);
            System.out.println("[S" + portaServidor + "] Resposta do Diretório: " + new String(msgAberta, StandardCharsets.UTF_8));
        }
    }

    private void iniciarServidorTCP() {
        try (ServerSocket serverSocket = new ServerSocket(portaServidor)) {
            System.out.println("[S" + portaServidor + "] Microsserviço '" + nomeServico + "' a rodar. A aguardar clientes...");

            while (true) {
                Socket conexaoCliente = serverSocket.accept();
                System.out.println("\n[S" + portaServidor + "] Cliente conectado: " + conexaoCliente.getInetAddress().getHostAddress());
                new Thread(new ThreadCalculadora(conexaoCliente)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class ThreadCalculadora implements Runnable {
        private final Socket socket;

        public ThreadCalculadora(Socket socket) {
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
                System.out.println("[S" + portaServidor + "] Handshake TCP fechado com o Cliente.");

                Pacote pacoteRecebido = (Pacote) ois.readObject();
                byte[] payloadAberto = CryptoManager.abrirPacote(pacoteRecebido, chaveAES, chavePubCliente);
                String expressao = new String(payloadAberto, StandardCharsets.UTF_8);
                
                System.out.println("[S" + portaServidor + "] Recebeu para calcular: " + expressao);

                String resultado = processarCalculo(expressao);

                Pacote pacoteResposta = CryptoManager.gerarPacote(
                        resultado.getBytes(StandardCharsets.UTF_8), 
                        chaveAES, 
                        parChavesRSA.getPrivate()
                );
                oos.writeObject(pacoteResposta);
                oos.flush();

            } catch (SecurityException | java.security.GeneralSecurityException se) {
                System.err.println("[S" + portaServidor + "-ALERTA] Falha de segurança com o Cliente: " + se.getMessage());
            } catch (Exception e) {
                System.err.println("[S" + portaServidor + "-ERRO] " + e.getMessage());
            }
        }

        private String processarCalculo(String expressao) {
            try {
                expressao = expressao.trim();
                if (expressao.contains("+")) {
                    String[] partes = expressao.split("\\+");
                    if (partes.length != 2) throw new IllegalArgumentException();
                    return String.valueOf(Double.parseDouble(partes[0].trim()) + Double.parseDouble(partes[1].trim()));
                } else if (expressao.contains("-")) {
                    // subtração 
                    String exp = expressao.startsWith("-") ? expressao.substring(1) : expressao;
                    String[] partes = exp.split("-", 2);
                    if (partes.length != 2) throw new IllegalArgumentException();
                    double a = expressao.startsWith("-") ? -Double.parseDouble(partes[0].trim()) : Double.parseDouble(partes[0].trim());
                    return String.valueOf(a - Double.parseDouble(partes[1].trim()));
                } else if (expressao.contains("*")) {
                    String[] partes = expressao.split("\\*");
                    if (partes.length != 2) throw new IllegalArgumentException();
                    return String.valueOf(Double.parseDouble(partes[0].trim()) * Double.parseDouble(partes[1].trim()));
                } else if (expressao.contains("/")) {
                    String[] partes = expressao.split("/", 2);
                    if (partes.length != 2) throw new IllegalArgumentException();
                    double divisor = Double.parseDouble(partes[1].trim());
                    if (divisor == 0) return "Erro na entrada de dados. Tente outra vez!";
                    return String.valueOf(Double.parseDouble(partes[0].trim()) / divisor);
                }
                // se a expressão não bater com o serviço de forma limpa, força o erro exigido
                throw new IllegalArgumentException();
                
            } catch (Exception e) {
                return "Erro na entrada de dados. Tente outra vez!";
            }
        }
    }

    public static void main(String[] args) {

        int porta = (args.length > 0) ? Integer.parseInt(args[0]) : 8001;
        String servico = (args.length > 1) ? args[1] : "Calcular soma";
        
        try {
            new ServidorCalculadora(porta, servico).iniciar();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}