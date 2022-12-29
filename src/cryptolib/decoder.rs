use base64;
use base64::DecodeError;
use base85;
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey};

pub struct Decoder {
    pem: RsaPrivateKey,
}

impl Decoder {
    pub fn new(private_key: &str) -> Decoder {
        let pem = RsaPrivateKey::from(private_key).unwrap();
        Decoder { pem }
    }

    pub fn decrypt(&self, text: Vec<u8>) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        self.pem.decrypt(padding, text.as_bytes()).unwrap()
    }

    pub fn from_base64(text: String) -> Vec<u8> {
        base64::decode(text.into_bytes()).unwrap()
    }

    pub fn from_base85(text: String) -> Vec<u8> {
        base85::decode(&text).unwrap()
    }
}
