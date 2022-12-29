use base64;
use base85;
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};

pub struct Encoder {
    pem: RsaPublicKey,
}

impl Encoder {
    pub fn new(public_key: &str) -> Encoder {
        let pem = RsaPublicKey::from_public_key_pem(public_key).unwrap();
        Encoder { pem }
    }

    pub fn encrypt(&self, text: &str) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        self.pem
            .encrypt(&mut rng, padding, text.as_bytes())
            .unwrap()
    }

    pub fn to_base64(text: Vec<u8>) -> String {
        base64::encode(text)
    }

    pub fn to_base85(text: Vec<u8>) -> String {
        base85::encode(text.as_ref())
    }
}
