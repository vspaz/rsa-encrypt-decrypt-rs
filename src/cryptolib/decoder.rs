use base64;
use base85;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{PaddingScheme, RsaPrivateKey};

pub struct Decoder {
    pem: RsaPrivateKey,
}

impl Decoder {
    pub fn new(private_key: &str) -> Decoder {
        let pem = RsaPrivateKey::from_pkcs1_pem(private_key).expect("failed to parse key");
        Decoder { pem }
    }

    pub fn decrypt(&self, text: Vec<u8>) -> String {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let decrypted_text = self
            .pem
            .decrypt(padding, &text)
            .expect("failed to read the key");
        String::from_utf8(decrypted_text).expect("failed to convert to string")
    }

    pub fn from_base64(text: String) -> Vec<u8> {
        base64::decode(text.into_bytes()).expect("failed to decode")
    }

    pub fn from_base85(text: String) -> Vec<u8> {
        base85::decode(&text).expect("failed to decode")
    }
}
