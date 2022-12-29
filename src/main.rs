mod cryptolib;
use crate::cryptolib::encoder::Encoder;

fn main() {
    println!("Hello, world!");
    let pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtsQsUV8QpqrygsY+2+JC
Q6Fw8/omM71IM2N/R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04
LHb2HJAYlz25+lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrX
yrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0N
fFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejI
n04APPKIjpMyQdnWlby7rNyQtE4+CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uH
LwIDAQAB
-----END PUBLIC KEY-----";
    let encoder = Encoder::new(pem);
    let encrypted_text = encoder.encrypt("foo");
    let encrypted_text_2 = encrypted_text.clone();
    let encoded_text_with_base64 = Encoder::to_base64(encrypted_text);
    let encoded_text_with_base85 = Encoder::to_base85(encrypted_text_2);
    println!("{}", encoded_text_with_base64);
    println!("{}", encoded_text_with_base85);
}
