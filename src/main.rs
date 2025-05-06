use scrypt::{scrypt, Params};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rand::{rng, RngCore};
use ipinfo::{IpInfo, IpInfoConfig};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let senha = std::env::var("USER_PASSWORD").expect("USER_PASSWORD not set");
    let ip_usuario = std::env::var("USER_IP").expect("USER_IP not set");
    let token_ipinfo = std::env::var("IPINFO_TOKEN").expect("IPINFO_TOKEN not set");
    let segredo_totp = std::env::var("TOTP_SECRET").expect("TOTP_SECRET not set");

    println!("iniciando sistema de autenticação 3fa com rust");

    // 1. cadastro do usuário com hash de senha usando scrypt
    let (hash_senha, salt) = hash_password(senha);
    println!("hash da senha: {}\nsalt: {}", hash_senha, salt);

    // 2. verificação de ip para obter localização
    let local = get_location(ip_usuario.clone(), token_ipinfo).await;
    println!("local detectado pelo ip {}: {}", ip_usuario, local);

    // 3. geração do código totp com segredo conhecido
    let codigo_totp = gerar_totp(segredo_totp.as_bytes());
    println!("código totp atual: {}", codigo_totp);

    // 4. derivação de chave simétrica usando totp como base
    let chave_simetrica = derive_key(&codigo_totp, &hex::decode(&salt).unwrap());
    println!("chave simétrica derivada: {}", hex::encode(&chave_simetrica));

    // 5. cifragem de mensagem para envio ao servidor
    let mensagem = "mensagem segura para o servidor";
    let cifrado = encrypt_message(&chave_simetrica, mensagem);
    println!("mensagem cifrada: {}", hex::encode(&cifrado));

    // 6. decifragem da mensagem do lado do servidor
    let decifrado = decrypt_message(&chave_simetrica, &cifrado);
    println!("mensagem decifrada: {}", decifrado);
}

fn hash_password(senha: String) -> (String, String) {
    let mut salt = [0u8; 16];
    rng().fill_bytes(&mut salt);
    let params = Params::recommended();

    let mut output = [0u8; 64];
    scrypt(senha.as_bytes(), &salt, &params, &mut output).unwrap();

    (hex::encode(output), hex::encode(salt))
}

async fn get_location(ip: String, token: String) -> String {
    let config = IpInfoConfig { token: Some(token.to_string()), ..Default::default() };
    let mut cliente = IpInfo::new(config).unwrap();
    let detalhes = cliente.lookup(&ip).await.unwrap();

    detalhes.country
}

fn gerar_totp(secret: &[u8]) -> String {
    let intervalo = 30;
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let contador = time / intervalo;
    let contador_bytes = contador.to_be_bytes();

    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).unwrap();
    mac.update(&contador_bytes);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[19] & 0xf) as usize;
    let code = ((u32::from(hash[offset]) & 0x7f) << 24)
        | ((u32::from(hash[offset + 1]) & 0xff) << 16)
        | ((u32::from(hash[offset + 2]) & 0xff) << 8)
        | (u32::from(hash[offset + 3]) & 0xff);

    format!("{:06}", code % 1_000_000)
}

fn derive_key(segredo: &str, salt: &[u8]) -> Vec<u8> {
    let params = Params::recommended();
    let mut chave = [0u8; 32];
    scrypt(segredo.as_bytes(), salt, &params, &mut chave).unwrap();
    chave.to_vec()
}

fn encrypt_message(chave: &[u8], mensagem: &str) -> Vec<u8> {
    let cifra = Aes256Gcm::new_from_slice(chave).unwrap();
    let nonce = Nonce::from_slice(b"unicnonce1");
    cifra.encrypt(nonce, mensagem.as_bytes()).unwrap()
}

fn decrypt_message(chave: &[u8], cifrado: &[u8]) -> String {
    let cifra = Aes256Gcm::new_from_slice(chave).unwrap();
    let nonce = Nonce::from_slice(b"unicnonce1");
    let texto = cifra.decrypt(nonce, cifrado).unwrap();
    String::from_utf8(texto).unwrap()
}