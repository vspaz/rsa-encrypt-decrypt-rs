use rsa_encrypt_decrypt_rs::cryptolib::decoder::Decoder;
use rsa_encrypt_decrypt_rs::cryptolib::encoder::Encoder;

const TEST_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
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

const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGDcSAjiHKP9v2ITR+Bj
Qmt9Tx2zW08ZyrjOxPew+Gxl2m5zJyoP8sicZV81BeMNFkMg6q7sMtRXHhX1nFiT
ql5HBIqhZohYlN3LIXK2bdPWpDttrOFXfsSbZ4Wqy3XhXBhiPNn3kkkRv1N5L/IY
cdrxwqaqvTlJzOeQnDsd3+AmkYstuD4rgElOFkcUawtF7lKIYYFi42cYkJo51UD4
60mYieBezP6dZhFZB56pZ2rV8cQUNrUQy2llpj+PxX/yhGnYI88ij0FST0gI2l4U
sjtwXVB1Y2SxqrhNMdBU7W6ZA8WUQQidr4MBxEFoujsLjaCl8LMsbEpAAilKezwu
bQIDAQAB
-----END PUBLIC KEY-----";


fn main() {
    let text = "some text data";
    let encoder = Encoder::new(TEST_PUBLIC_KEY);
    let encrypted_text = encoder.encrypt(text);
    let base_85_encoded_text = Encoder::to_base85(encrypted_text);

    let decoder = Decoder::new(TEST_PRIVATE_KEY);
    let base85_decoded_text = Decoder::from_base85(base_85_encoded_text);
    let decrypted_text = decoder.decrypt(base85_decoded_text);

    assert_eq!(text, decrypted_text);
    println!("decrypted text: {}", decrypted_text);

    let encrypted_text = encoder.encrypt(text);
    let base_64_encoded_text = Encoder::to_base64(encrypted_text);

    let based_64_decoded_text = Decoder::from_base64(base_64_encoded_text);
    let decrypted_text = decoder.decrypt(based_64_decoded_text);

    assert_eq!(text, decrypted_text);
    println!("decrypted text: {}", decrypted_text);
}
