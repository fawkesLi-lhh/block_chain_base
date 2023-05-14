use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 创建 secp256k1 椭圆曲线组
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;

    // 生成 EC 密钥对
    let keypair = EcKey::generate(&group)?;

    // 将 EC 密钥转换为通用 PKey
    let private_key = PKey::from_ec_key(keypair.clone())?;
    // 获取公钥
    let public_key_pem = private_key.public_key_to_pem()?;
    println!("public key {:?}",String::from_utf8(public_key_pem.clone()));

    // 获取公钥
    let public_key = EcKey::public_key_from_pem(&public_key_pem)?;

    // 要签名的消息
    let message = "This is the message we want to sign.";

    // 对消息进行 SHA-256 摘要
    let message_digest = hash(MessageDigest::sha256(), message.as_bytes())?;

    // 使用私钥对消息摘要进行签名
    let signature = EcdsaSig::sign(&message_digest, &keypair)?;

    // 用公钥验证签名
    let is_signature_valid = signature.verify(&message_digest, &public_key)?;

    if is_signature_valid {
        println!("The signature is valid.");
    } else {
        println!("The signature is invalid.");
    }

    Ok(())
}