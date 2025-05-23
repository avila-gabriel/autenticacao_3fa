use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use hmac::{Hmac, Mac};
use ipinfo::{IpInfo, IpInfoConfig};
use rand::{RngCore, rng};
use scrypt::{Params, scrypt};
use sha1::Sha1;
use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

// Tipo para HMAC-SHA1
type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
struct User {
    nome: String,
    pais: String,
    hash: Vec<u8>,
    salt: Vec<u8>,
    telefone: Option<String>, // em producao isso poderia ser usado pra enviar sms totp por exemplo
}

struct Server {
    usuarios: HashMap<String, User>,
}

impl Server {
    fn new() -> Self {
        println!("[Server] Novo servidor inicializado");
        Self {
            usuarios: HashMap::new(),
        }
    }

    fn cadastrar(&mut self, nome: &str, pais: &str, senha: &str, telefone: Option<String>) {
        // em producao o cadastro envolveria validacao de email ou sms
        println!("[Server] Cadastrando usuario: {} do pais: {}", nome, pais);
        let (hash_hex, salt_hex) = hash_password(senha.to_string());
        println!("[Server] Hash gerado: {}", hash_hex);
        println!("[Server] Salt gerado: {}", salt_hex);

        let usuario = User {
            nome: nome.to_string(),
            pais: pais.to_string(),
            hash: hex::decode(hash_hex).unwrap(),
            salt: hex::decode(salt_hex).unwrap(),
            telefone,
        };
        // em producao isso iria pra um banco de dados seguro
        self.usuarios.insert(nome.to_string(), usuario);
        println!("[Server] Usuario '{}' cadastrado com sucesso", nome);
    }
    fn autenticar(&self, nome: &str, senha: &str) -> bool {
        match self.usuarios.get(nome) {
            Some(user) => {
                let params = scrypt::Params::recommended();
                let mut output = [0u8; 64];
                let result = scrypt(senha.as_bytes(), &user.salt, &params, &mut output);

                match result {
                    Ok(_) => {
                        let hash_matches = output == user.hash.as_slice();
                        if hash_matches {
                            println!("[Server] Autenticação bem-sucedida para '{}'", nome);
                        } else {
                            println!("[Server] Falha na autenticação: hash não confere.");
                        }
                        hash_matches
                    }
                    Err(_) => {
                        println!("[Server] Erro ao gerar hash na autenticação.");
                        false
                    }
                }
            }
            None => {
                println!("[Server] Usuário '{}' não encontrado.", nome);
                false
            }
        }
    }
    fn receber_mensagem(
        &self,
        nome: &str,
        pais_obtido: &str,
        totp: &str,
        nonce: &[u8],
        cifrado: &[u8],
    ) {
        println!(
            "[Server] Recebendo mensagem do usuario '{}', pais: {}, TOTP: {}",
            nome, pais_obtido, totp
        );
        println!("[Server] Nonce recebido: {:02x?}", nonce);
        println!("[Server] Mensagem cifrada recebida: {:02x?}", cifrado);

        let user = match self.usuarios.get(nome) {
            Some(u) => u,
            None => {
                println!("usuario nao encontrado");
                return;
            }
        };

        // em producao a verificacao de localizacao seria mais refinada
        // talvez usando historico de logins ou heuristicas de confiabilidade do ip
        if user.pais != pais_obtido {
            println!("pais nao confere");
            return;
        }

        let chave = derive_key(totp, &user.salt);
        println!("[Server] Chave derivada: {:02x?}", chave);
        let cifra = Aes256Gcm::new_from_slice(&chave).unwrap();
        let nonce_obj = Nonce::from_slice(nonce);
        match cifra.decrypt(nonce_obj, cifrado) {
            Ok(texto) => println!(
                "mensagem decifrada pelo servidor: {}",
                String::from_utf8(texto).unwrap()
            ),
            Err(_) => println!("falha na decifragem"), // em producao logaria isso com cuidado
        };
    }

    fn listar_usuarios(&self) {
        println!("\n[Server] Lista de usuários cadastrados:");
        if self.usuarios.is_empty() {
            println!("Nenhum usuário cadastrado.");
        } else {
            for (nome, usuario) in &self.usuarios {
                println!("-> {} ({})", nome, usuario.pais);
            }
        }
    }
}

struct Client {
    nome: String,
    senha: String,
    secret_totp: Vec<u8>, // esse segredo normalmente estaria salvo num app tipo google authenticator
}

impl Client {
    fn novo(nome: String, senha: String, secret_totp: Vec<u8>) -> Self {
        println!("[Client] Novo cliente criado: {}", nome);
        Self {
            nome,
            senha,
            secret_totp,
        }
    }

    async fn obter_pais(&self, token: &str) -> String {
        println!("[Client] Obtendo pais usando IP publico");

        let config = IpInfoConfig {
            token: Some(token.to_string()),
            ..Default::default()
        };
        let mut cliente = IpInfo::new(config).unwrap();
        let detalhes = cliente.lookup_self_v4().await.unwrap();

        println!("[Client] Pais obtido: {}", detalhes.country);
        detalhes.country
    }

    fn gerar_totp(&self) -> String {
        // em producao esse totp deveria ser validado no maximo com 1 ou 2 janelas de tolerancia
        let intervalo = 30;
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let contador = time / intervalo;
        println!(
            "[Client] Tempo atual em segundos: {}, contador TOTP: {}",
            time, contador
        );
        let contador_bytes = contador.to_be_bytes();
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.secret_totp).unwrap();
        mac.update(&contador_bytes);
        let hash = mac.finalize().into_bytes();
        let offset = (hash[19] & 0xf) as usize;
        let code = ((u32::from(hash[offset]) & 0x7f) << 24)
            | ((u32::from(hash[offset + 1]) & 0xff) << 16)
            | ((u32::from(hash[offset + 2]) & 0xff) << 8)
            | (u32::from(hash[offset + 3]) & 0xff);
        let totp = format!("{:06}", code % 1_000_000);
        println!("[Client] TOTP gerado: {}", totp);
        totp
    }

    fn cifrar_mensagem(&self, totp: &str, salt: &[u8], mensagem: &str) -> (Vec<u8>, Vec<u8>) {
        println!(
            "[Client] Cifrando mensagem: '{}', com TOTP: {}",
            mensagem, totp
        );
        let chave = derive_key(totp, salt);
        println!("[Client] Chave derivada para cifra: {:02x?}", chave);
        let cifra = Aes256Gcm::new_from_slice(&chave).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rng().fill_bytes(&mut nonce_bytes);
        println!("[Client] Nonce gerado: {:02x?}", nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = cifra.encrypt(nonce, mensagem.as_bytes()).unwrap();
        println!("[Client] Mensagem cifrada: {:02x?}", cipher);
        (nonce_bytes.to_vec(), cipher)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    dotenv::dotenv().ok();

    let token_ipinfo = env::var("IPINFO_TOKEN").expect("IPINFO_TOKEN not set");
    let secret_totp = env::var("TOTP_SECRET").expect("TOTP_SECRET not set");

    let mut servidor = Server::new();
    let mut logged_user: Option<(String, Client, String)> = None;

    // test user
    let nome_teste = "teste";
    let senha_teste = "1234";
    let pais_teste = "US";
    let (hash_hex, salt_hex) = hash_password(senha_teste.to_string());

    let user_teste = User {
        nome: nome_teste.to_string(),
        pais: pais_teste.to_string(),
        hash: hex::decode(hash_hex).unwrap(),
        salt: hex::decode(salt_hex).unwrap(),
        telefone: None,
    };

    servidor.usuarios.insert(nome_teste.to_string(), user_teste);
    println!(
        "[Setup] Usuário de teste '{}' criado com país '{}'",
        nome_teste, pais_teste
    );

    loop {
        println!("\n--- Menu ---");
        println!("1. Criar usuário");
        println!("2. Login");
        println!("3. Enviar mensagem");
        println!("4. Listar usuários");
        println!("5. Sair");

        print!("Escolha uma opção: ");
        io::stdout().flush()?;
        let mut opcao = String::new();
        io::stdin().read_line(&mut opcao)?;
        let opcao = opcao.trim();

        match opcao {
            "1" => {
                // Criar usuário
                println!("Nome de usuário:");
                let mut nome = String::new();
                io::stdin().read_line(&mut nome)?;
                let nome = nome.trim().to_string();

                println!("Senha:");
                let mut senha = String::new();
                io::stdin().read_line(&mut senha)?;
                let senha = senha.trim().to_string();

                let cliente =
                    Client::novo(nome.clone(), senha.clone(), secret_totp.as_bytes().to_vec());
                let pais = cliente.obter_pais(&token_ipinfo).await;
                servidor.cadastrar(&nome, &pais, &senha, None);
                println!("Usuário criado com sucesso!");
            }
            "2" => {
                // Login
                println!("Nome de usuário:");
                let mut nome = String::new();
                io::stdin().read_line(&mut nome)?;
                let nome = nome.trim().to_string();

                println!("Senha:");
                let mut senha = String::new();
                io::stdin().read_line(&mut senha)?;
                let senha = senha.trim().to_string();

                if servidor.autenticar(&nome, &senha) {
                    let cliente =
                        Client::novo(nome.clone(), senha.clone(), secret_totp.as_bytes().to_vec());
                    logged_user = Some((nome.clone(), cliente, senha.clone()));
                    println!("Login bem-sucedido.");
                } else {
                    println!("Credenciais inválidas.");
                }
            }
            "3" => {
                // Enviar mensagem
                if let Some((nome, cliente, _senha)) = &logged_user {
                    println!("Mensagem:");
                    let mut mensagem = String::new();
                    io::stdin().read_line(&mut mensagem)?;
                    let mensagem = mensagem.trim().to_string();
                    let pais = cliente.obter_pais(&token_ipinfo).await;
                    let totp = cliente.gerar_totp();
                    let user_info = servidor.usuarios.get(nome).unwrap();

                    let (nonce, cipher) =
                        cliente.cifrar_mensagem(&totp, &user_info.salt, &mensagem);

                    servidor.receber_mensagem(nome, &pais, &totp, &nonce, &cipher);
                } else {
                    println!("Você precisa estar logado para enviar mensagens.");
                }
            }
            "4" => {
                // Listar usuários
                servidor.listar_usuarios();
            }
            "5" => break,
            _ => println!("Opção inválida."),
        }
    }

    Ok(())
}

fn hash_password(senha: String) -> (String, String) {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    println!("[Utils] Salt gerado: {:02x?}", salt);
    let params = Params::recommended();
    let mut output = [0u8; 64];
    scrypt(senha.as_bytes(), &salt, &params, &mut output).unwrap();
    println!("[Utils] Hash da senha gerado: {:02x?}", output);
    (hex::encode(output), hex::encode(salt)) // em producao isso seria armazenado com controle de acesso
}

fn derive_key(segredo: &str, salt: &[u8]) -> Vec<u8> {
    let params = Params::recommended();
    let mut chave = [0u8; 32];
    scrypt(segredo.as_bytes(), salt, &params, &mut chave).unwrap();
    println!(
        "[Utils] Chave derivada com segredo '{}': {:02x?}",
        segredo, chave
    );
    chave.to_vec()
}
