use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

pub struct Encoder {
    pub(crate) pem: RsaPublicKey,
}

impl Encoder {
    pub fn new(public_key: &str) -> Encoder {
        Encoder {
            pem: RsaPublicKey::from_public_key_pem(public_key).expect("failed to read key"),
        }
    }

    pub fn encrypt(&self, text: &str) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        self.pem
            .encrypt(&mut rng, padding, text.as_bytes())
            .expect("failed to encrypt")
    }

    pub fn to_base64(text: Vec<u8>) -> String {
        BASE64.encode(text)
    }

    pub fn to_base85(text: Vec<u8>) -> String {
        base85::encode(text.as_ref())
    }

    #[allow(dead_code)]
    pub fn to_bytes(serializable: String) -> Vec<u8> {
        serializable.as_bytes().to_vec()
    }
}
