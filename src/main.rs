use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hmac::{Hmac, Mac};
use ipinfo::{IpInfo, IpInfoConfig};
use local_ip_address::local_ip;
use rand::{RngCore, rng, thread_rng};
use scrypt::{Params, scrypt};
use sha1::Sha1;
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

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
        Self {
            usuarios: HashMap::new(),
        }
    }

    fn cadastrar(&mut self, nome: &str, pais: &str, senha: &str, telefone: Option<String>) {
        // em producao o cadastro envolveria validacao de email ou sms
        let (hash_hex, salt_hex) = hash_password(senha.to_string());
        let usuario = User {
            nome: nome.to_string(),
            pais: pais.to_string(),
            hash: hex::decode(hash_hex).unwrap(),
            salt: hex::decode(salt_hex).unwrap(),
            telefone,
        };
        // em producao isso iria pra um banco de dados seguro
        self.usuarios.insert(nome.to_string(), usuario);
    }

    fn receber_mensagem(
        &self,
        nome: &str,
        pais_obtido: &str,
        totp: &str,
        nonce: &[u8],
        cifrado: &[u8],
    ) {
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
}

struct Client {
    nome: String,
    senha: String,
    secret_totp: Vec<u8>, // esse segredo normalmente estaria salvo num app tipo google authenticator
}

impl Client {
    fn novo(nome: String, senha: String, secret_totp: Vec<u8>) -> Self {
        Self {
            nome,
            senha,
            secret_totp,
        }
    }

    async fn obter_pais(&self, ip: &str, token: &str) -> String {
        // em producao o uso de ipinfo precisa respeitar limites de api
        let config = IpInfoConfig {
            token: Some(token.to_string()),
            ..Default::default()
        };
        let mut cliente = IpInfo::new(config).unwrap();
        let detalhes = cliente.lookup(ip).await.unwrap();
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
        let contador_bytes = contador.to_be_bytes();
        let mut mac = HmacSha1::new_from_slice(&self.secret_totp).unwrap();
        mac.update(&contador_bytes);
        let hash = mac.finalize().into_bytes();
        let offset = (hash[19] & 0xf) as usize;
        let code = ((u32::from(hash[offset]) & 0x7f) << 24)
            | ((u32::from(hash[offset + 1]) & 0xff) << 16)
            | ((u32::from(hash[offset + 2]) & 0xff) << 8)
            | (u32::from(hash[offset + 3]) & 0xff);
        format!("{:06}", code % 1_000_000)
    }

    fn cifrar_mensagem(&self, totp: &str, salt: &[u8], mensagem: &str) -> (Vec<u8>, Vec<u8>) {
        let chave = derive_key(totp, salt);
        let cifra = Aes256Gcm::new_from_slice(&chave).unwrap();
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = cifra.encrypt(nonce, mensagem.as_bytes()).unwrap();
        (nonce_bytes.to_vec(), cipher)
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let nome_usuario = env::var("USER_NAME").unwrap_or("carla".to_string());
    let senha = env::var("USER_PASSWORD").expect("USER_PASSWORD not set");
    let token_ipinfo = env::var("IPINFO_TOKEN").expect("IPINFO_TOKEN not set");
    let secret_totp = env::var("TOTP_SECRET").expect("TOTP_SECRET not set");

    // em producao usaria ip publico obtido por um serviço confiavel tipo whatismyip
    let args: Vec<String> = env::args().collect();
    let mut ip_manual = None;
    if args.len() > 2 && args[1] == "--ip" {
        ip_manual = Some(args[2].clone());
    }

    let ip_usuario = match ip_manual {
        Some(ip) => ip,
        None => local_ip().unwrap().to_string(),
    };

    let cliente = Client::novo(
        nome_usuario.clone(),
        senha.clone(),
        secret_totp.as_bytes().to_vec(),
    );
    let pais = cliente.obter_pais(&ip_usuario, &token_ipinfo).await;

    let mut servidor = Server::new();
    servidor.cadastrar(&nome_usuario, &pais, &senha, None);

    println!("iniciando autenticacao 3fa");

    let totp_codigo = cliente.gerar_totp();
    let user_info = servidor.usuarios.get(&nome_usuario).unwrap();
    let (nonce, cipher) = cliente.cifrar_mensagem(
        &totp_codigo,
        &user_info.salt,
        "mensagem segura para o servidor",
    );

    servidor.receber_mensagem(&nome_usuario, &pais, &totp_codigo, &nonce, &cipher);
}

fn hash_password(senha: String) -> (String, String) {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let params = Params::recommended();
    let mut output = [0u8; 64];
    scrypt(senha.as_bytes(), &salt, &params, &mut output).unwrap();
    (hex::encode(output), hex::encode(salt)) // em producao isso seria armazenado com controle de acesso
}

fn derive_key(segredo: &str, salt: &[u8]) -> Vec<u8> {
    let params = Params::recommended();
    let mut chave = [0u8; 32];
    scrypt(segredo.as_bytes(), salt, &params, &mut chave).unwrap();
    chave.to_vec()
}
