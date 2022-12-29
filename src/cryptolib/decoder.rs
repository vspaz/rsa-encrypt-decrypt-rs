use base64;
use base64::DecodeError;
use base85;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
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
        let decrypted_text = self.pem.decrypt(padding, &text).unwrap();
        String::from_utf8(decrypted_text).unwrap()
    }

    pub fn from_base64(text: String) -> Vec<u8> {
        base64::decode(text.into_bytes()).unwrap()
    }

    pub fn from_base85(text: String) -> Vec<u8> {
        base85::decode(&text).unwrap()
    }
}
