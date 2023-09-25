use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::Engine as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

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
        let decrypted_text = self
            .pem
            .decrypt(Pkcs1v15Encrypt, &text)
            .expect("failed to read the key");
        String::from_utf8(decrypted_text).expect("failed to convert to string")
    }

    pub fn from_base64(text: String) -> Vec<u8> {
        BASE64.decode(text.into_bytes()).expect("failed to decode")
    }

    pub fn from_base85(text: String) -> Vec<u8> {
        base85::decode(&text).expect("failed to decode")
    }

    #[allow(dead_code)]
    pub fn from_bytes(deserializable: Vec<u8>) -> String {
        String::from_utf8(deserializable).expect("failed to convert to string")
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptolib::decoder::Decoder;
    use crate::cryptolib::encoder::Encoder;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_from_base64_ok() {
        let text = Encoder::to_base64(b"foobar".to_vec());
        let decoded_text = Decoder::from_base64(text);
        assert_eq!(b"foobar".to_vec(), decoded_text);
    }

    #[test]
    fn test_from_base85_ok() {
        let text = Encoder::to_base85(b"foobar".to_vec());
        let decoded_text = Decoder::from_base85(text);
        assert_eq!(b"foobar".to_vec(), decoded_text);
    }

    #[test]
    fn test_from_bytes_ok() {
        let text = "foobar";
        let encoded_text = Encoder::to_bytes(String::from(text));
        let decoded_text = Decoder::from_bytes(encoded_text);
        assert_eq!(text, decoded_text);
    }

    #[test]
    fn test_decrypt_ok() {
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        let text = "some text";
        let encoder = Encoder {
            pem: RsaPublicKey::from(&private_key),
        };
        let encrypted_text = encoder.encrypt(text);

        let decoder = Decoder { pem: private_key };
        let decrypted_text = decoder.decrypt(encrypted_text);
        assert_eq!(text, decrypted_text);
    }

    #[test]
    fn test_encrypt_decrypt_ok() {
        let test_private_key: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxGDcSAjiHKP9v2ITR+BjQmt9Tx2zW08ZyrjOxPew+Gxl2m5z
JyoP8sicZV81BeMNFkMg6q7sMtRXHhX1nFiTql5HBIqhZohYlN3LIXK2bdPWpDtt
rOFXfsSbZ4Wqy3XhXBhiPNn3kkkRv1N5L/IYcdrxwqaqvTlJzOeQnDsd3+AmkYst
uD4rgElOFkcUawtF7lKIYYFi42cYkJo51UD460mYieBezP6dZhFZB56pZ2rV8cQU
NrUQy2llpj+PxX/yhGnYI88ij0FST0gI2l4UsjtwXVB1Y2SxqrhNMdBU7W6ZA8WU
QQidr4MBxEFoujsLjaCl8LMsbEpAAilKezwubQIDAQABAoIBAFgkwbrzgcopMXP9
qXnRlbvyU0R3qFGLp5/+Y5C1PJHE1dK9UKJ7lrz6nnhBy6Lgzrb3Wob8DLij5pZy
dNPATkdiGa5IKznCaUAobUyOGKQjOWxt4ESAwKz9wmMs9ARu3MBhkXaOvzjB411l
Mjf7Ck3QYENmW6yjUiTOq3H0duxM/rn1Y88a9z2+aoWXQTltWvu0qKfb8SsqKzzx
HQFSalgNUxIqs+NoHRAT4ygzGGgipdP2/gXA966UonYuFAkpkutCeKVd7/6dMbm8
bgnr/x6ivGeLkbIaVkHNPRU+P4SYX1/XZohYIkTbggIih2aeH6+lEka8yZURANI6
HSUwLAECgYEA4bfavKu12NiIUO75/ZcqF8ojXq5+7HXP59t5X5MrURj2jizWs8YH
vPdrvYqxQNMZ0U0ZQBdAUWCn0Z11OXEak7YpKP78yoLIw2YnhgLVFvp3xZ+pIjjN
yidWbIvoq8SLMiUYHrMy3lMwVyFjM/AuA6bqNffCbHXqs9Ut+WnDN6ECgYEA3rlZ
S1gnE0sJrAJQ/5FnKgY/+TP6p+/k1SmRahNxYqpdP2t4CSwtYvjExRYcZefWFV1V
G04KvFuKf4p9zasYnISvWV735KU++li/QEw0LrVzXcnoRXiZwXauQzYQI6tuMYmc
NQRGBma3R7lQ/93YV3+hdubG+VCUsAC/B42zk00CgYAJ8zngQU2F3p27u50nkadY
Xx/KB7UupU7h8KncDbfGHmyX/eAFEsC6ksmcFGYV7nhf4p8vVRcPv0wGkINfYd4D
Du+nj/4Cy1sgSfuKC8vq9GWdP5mMGabwt2U26b/6+nIMZtg2Wj3u0Qn7fUxLONY+
cPg4ItDeSSBshwQ8z228oQKBgGyXL/s1OrAEaO3Nn1JLwWHS9EP7XN2ecBKiFr0C
R8kUSSyPqFHIkURtB/sTobrpww5dmA4dCcz2UNuIWXf6UKCXbKsFS5XWH5ONy4l8
3gBcBaiXtcCRYV3bEHHCnTHW9n3+mwOaVs3uLLQynVRzBHT8zGudbyvFZwk9A+aZ
5xENAoGBALO842ymiZmFYiv9CIdfBGFokbokQMci+4cJm4wWzxEiDjAzSglRHAei
/+oGBiPm8mKmx/dcU408x4PK76JlfduuoXuzE9jEmx46kwU4jGDS1GZYkwjGVPY8
8UmZ7fFkjNFJH0Rh5y+tmoFyou3FsWzL2lpd1mIryAH2LR3PGE/t
-----END RSA PRIVATE KEY-----";

        let test_public_key: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGDcSAjiHKP9v2ITR+Bj
Qmt9Tx2zW08ZyrjOxPew+Gxl2m5zJyoP8sicZV81BeMNFkMg6q7sMtRXHhX1nFiT
ql5HBIqhZohYlN3LIXK2bdPWpDttrOFXfsSbZ4Wqy3XhXBhiPNn3kkkRv1N5L/IY
cdrxwqaqvTlJzOeQnDsd3+AmkYstuD4rgElOFkcUawtF7lKIYYFi42cYkJo51UD4
60mYieBezP6dZhFZB56pZ2rV8cQUNrUQy2llpj+PxX/yhGnYI88ij0FST0gI2l4U
sjtwXVB1Y2SxqrhNMdBU7W6ZA8WUQQidr4MBxEFoujsLjaCl8LMsbEpAAilKezwu
bQIDAQAB
-----END PUBLIC KEY-----";

        let text = "some text data";
        let encoder = Encoder::new(test_public_key);
        let encrypted_text = encoder.encrypt(text);
        let base_85_encoded_text = Encoder::to_base85(encrypted_text);

        let decoder = Decoder::new(test_private_key);
        let base85_decoded_text = Decoder::from_base85(base_85_encoded_text);
        let decrypted_text = decoder.decrypt(base85_decoded_text);

        assert_eq!(text, decrypted_text);

        let encrypted_text = encoder.encrypt(text);
        let base_64_encoded_text = Encoder::to_base64(encrypted_text);

        let based_64_decoded_text = Decoder::from_base64(base_64_encoded_text);
        let decrypted_text = decoder.decrypt(based_64_decoded_text);

        assert_eq!(text, decrypted_text);
    }
}
