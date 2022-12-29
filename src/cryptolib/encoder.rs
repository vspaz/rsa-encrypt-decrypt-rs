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

    pub fn encrypt(&self, text: String) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        self.pem
            .encrypt(&mut rng, padding, text.as_bytes())
            .unwrap()
    }
}
