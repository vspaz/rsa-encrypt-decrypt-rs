use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{PaddingScheme, RsaPrivateKey};

pub struct Decoder {
    pem: RsaPrivateKey,
}

impl Decoder {
    pub fn new(private_key: &str) -> Decoder {
        Decoder {
            pem: RsaPrivateKey::from_pkcs1_pem(private_key).expect("failed to parse key"),
        }
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

    pub fn from_bytes(deserializable: Vec<u8>) -> String {
        String::from_utf8(deserializable).expect("failed to convert to string")
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptolib::decoder::Decoder;
    use crate::cryptolib::encoder::Encoder;

    #[test]
    fn test_from_base64_ok() {
        let some_text = Encoder::to_base64(b"foobar".to_vec());
        let byte_decoded_text = Decoder::from_base64(some_text);
        let decoded_text = Decoder::from_bytes(byte_decoded_text);
        assert_eq!("foobar", decoded_text);
    }

    #[test]
    fn test_from_base85_ok() {
        let some_text = Encoder::to_base85(b"foobar".to_vec());
        let byte_decoded_text = Decoder::from_base85(some_text);
        let decoded_text = Decoder::from_bytes(byte_decoded_text);
        assert_eq!("foobar", decoded_text);
    }

    #[test]
    fn test_from_bytes_ok() {
        let some_text = "foobar";
        let encoded_text = Encoder::to_bytes(String::from(some_text));
        let decoded_text = Decoder::from_bytes(encoded_text);
        assert_eq!(some_text, decoded_text);
    }
}
