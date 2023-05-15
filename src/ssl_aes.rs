use openssl::symm::{Cipher, Crypter, Mode};
use openssl::bn::BigNum;
use openssl::rand::rand_bytes;

fn main() {
    // 原始明文
    let plaintext = b"Hello, world!";

    // 使用 BigNum 类型生成密钥
    let mut big_number = BigNum::new().unwrap();
    big_number.rand(256, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    let key = big_number.to_vec();

    // 使用 AES-256-GCM 进行加密
    let cipher = Cipher::aes_256_gcm();
    let mut iv = vec![0; cipher.iv_len().unwrap()];
    rand_bytes(&mut iv).unwrap();
    let mut tag = vec![0; 16];

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();
    let mut ciphertext = vec![0; plaintext.len()];
    encrypter.update(plaintext, &mut ciphertext).unwrap();
    encrypter.finalize(&mut ciphertext).unwrap();
    encrypter.get_tag(&mut tag).unwrap();

    // 使用 AES-256-GCM 进行解密
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).unwrap();
    decrypter.set_tag(&tag).unwrap();
    let mut decrypted_text = vec![0; ciphertext.len()];
    decrypter.update(&ciphertext, &mut decrypted_text).unwrap();
    decrypter.finalize(&mut decrypted_text).unwrap();

    // 检查解密结果是否与原始明文匹配
    assert_eq!(plaintext.to_vec(), decrypted_text);
    println!("Decrypted text: {:?}", std::str::from_utf8(&decrypted_text).unwrap());
}