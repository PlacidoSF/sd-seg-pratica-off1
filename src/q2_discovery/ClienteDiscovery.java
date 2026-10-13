package q2_discovery;

import crypto.AESUtils;
import crypto.CryptoManager;
import crypto.RSAUtils;
import shared.Pacote;

import javax.crypto.SecretKey;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;


public class ClienteDiscovery {

    private final String ipDiretorio = "127.0.0.1";
    private final int portaDiretorio = 6001;

    public void iniciar() {
        try {
            System.out.println("==================================================");
            System.out.println("[CASO DE TESTE 1] DESCOBERTA DE SERVIÇO");
            System.out.println("==================================================");
            
            List<String> servidoresAtivos = buscarServicoNoDiretorio("Calcular soma");
            
            if (servidoresAtivos.isEmpty() || servidoresAtivos.get(0).startsWith("ERRO")) {
                System.err.println("Não foi possível encontrar servidores para o serviço requisitado.");
                return;
            }

            System.out.println("\n[Descoberta] Consultando segundo serviço: 'Calcular multiplicação'...");
            List<String> servidoresMult = buscarServicoNoDiretorio("Calcular multiplicação");
            if (servidoresMult.isEmpty() || servidoresMult.get(0).startsWith("ERRO")) {
                System.out.println("[Descoberta] Serviço 'Calcular multiplicação' sem instâncias (inicie um S com esse nome para ver). Usando lista da soma como fallback.");
            } else {
                System.out.println("[Descoberta] Serviço 'Calcular multiplicação' OK: " + servidoresMult);
            }
            
            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 2] LOAD BALANCING (ROUND ROBIN)");
            System.out.println("==================================================");
            
            // variável de controlo do Round Robin
            int rrIndex = 0;
            
            String[] contas = { "10+20", "5*4", "100+300", "20-8", "20/4" };
            
            for (String conta : contas) {
                // aplica a matemática do Round Robin para escolher o próximo servidor
                String servidorEscolhido = servidoresAtivos.get(rrIndex);
                rrIndex = (rrIndex + 1) % servidoresAtivos.size();
                
                System.out.println("\n[Load Balancer] A enviar '" + conta + "' para o nó -> " + servidorEscolhido);
                
                executarCalculoNoServidor(servidorEscolhido, conta, false);
            }

            System.out.println("\n==================================================");
            System.out.println("[CASO DE TESTE 3] TRATAMENTO DE ERROS E SEGURANÇA");
            System.out.println("==================================================");
            
            String noAlvo = servidoresAtivos.get(0);
            
            System.out.println("-> Teste 3.A: Entrada Inválida (Operação não cadastrada)");
            executarCalculoNoServidor(noAlvo, "Calcular modulo", false); // Falhará graciosamente
            
            System.out.println("\n-> Teste 3.B: Falha de Integridade / Adulteração de Pacote");
            executarCalculoNoServidor(noAlvo, "50+50", true); // O servidor cortará a ligação

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private List<String> buscarServicoNoDiretorio(String servico) throws Exception {
        System.out.println("[Cliente] A ligar ao Diretório em " + ipDiretorio + ":" + portaDiretorio + "...");
        
        try (Socket socket = new Socket(ipDiretorio, portaDiretorio);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            oos.flush();

            PublicKey pubDiretorio = (PublicKey) ois.readObject();
            KeyPair meuParRSA = RSAUtils.gerarParDeChaves();
            SecretKey minhaChaveAES = AESUtils.gerarChave();
            
            byte[] aesCifrado = RSAUtils.cifrarHandshake(minhaChaveAES.getEncoded(), pubDiretorio);
            oos.writeObject(meuParRSA.getPublic());
            oos.writeObject(aesCifrado);
            oos.flush();
            System.out.println("[Cliente] Canal seguro com Diretório estabelecido.");

            String comando = "BUSCAR " + servico.replace(" ", "_");
            Pacote pacoteBusca = CryptoManager.gerarPacote(comando.getBytes(StandardCharsets.UTF_8), minhaChaveAES, meuParRSA.getPrivate());
            
            oos.writeObject(pacoteBusca);
            oos.flush();

            Pacote pacoteResposta = (Pacote) ois.readObject();
            byte[] msgAberta = CryptoManager.abrirPacote(pacoteResposta, minhaChaveAES, pubDiretorio);
            String resposta = new String(msgAberta, StandardCharsets.UTF_8);
            
            System.out.println("[Cliente] Diretório devolveu os IPs: " + resposta);
            return Arrays.asList(resposta.split(","));
        }
    }

    private void executarCalculoNoServidor(String ipPorta, String conta, boolean simularFraude) {
        String[] partes = ipPorta.split(":");
        String ip = partes[0];
        int porta = Integer.parseInt(partes[1]);

        try (Socket socket = new Socket(ip, porta);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            oos.flush();

            PublicKey pubServidor = (PublicKey) ois.readObject();
            KeyPair meuParRSA = RSAUtils.gerarParDeChaves();
            SecretKey minhaChaveAES = AESUtils.gerarChave();
            
            byte[] aesCifrado = RSAUtils.cifrarHandshake(minhaChaveAES.getEncoded(), pubServidor);
            oos.writeObject(meuParRSA.getPublic());
            oos.writeObject(aesCifrado);
            oos.flush();

            Pacote pacoteConta = CryptoManager.gerarPacote(conta.getBytes(StandardCharsets.UTF_8), minhaChaveAES, meuParRSA.getPrivate());
            
            if (simularFraude) {
                System.out.println("[Cliente] A simular adulteração da Assinatura RSA no pacote...");
                byte[] assinaturaFalsa = new byte[256]; 
                pacoteConta = new Pacote(pacoteConta.getTextoCifrado(), assinaturaFalsa);
            }

            oos.writeObject(pacoteConta);
            oos.flush();

            Pacote pacoteResposta = (Pacote) ois.readObject();
            byte[] msgAberta = CryptoManager.abrirPacote(pacoteResposta, minhaChaveAES, pubServidor);
            
            System.out.println("[Resultado] A resposta matemática é: " + new String(msgAberta, StandardCharsets.UTF_8));

        } catch (java.io.EOFException | java.net.SocketException e) {
            if (simularFraude) {
                System.out.println("[Resultado 3.B] Sucesso! O microsserviço cortou a ligação TCP abruptamente (EOF) devido à falha de segurança.");
            } else {
                System.err.println("[Erro TCP] A ligação caiu: " + e.getMessage());
            }
        } catch (Exception e) {
            System.err.println("[Erro no Cálculo] " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        new ClienteDiscovery().iniciar();
    }
}