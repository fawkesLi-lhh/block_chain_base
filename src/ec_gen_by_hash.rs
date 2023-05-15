use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use std::error::Error;

pub fn generate_eckey_by_hash(group: &EcGroup, hash: BigNum) -> Result<EcKey<Private>,Box<dyn Error>>{
    // 计算公钥
    let mut ctx = BigNumContext::new()?;
    let mut pubkey_point = openssl::ec::EcPoint::new(&group)?;
    pubkey_point.mul_generator(&group, &hash, &mut ctx)?;

    // 使用私有组件创建 EcKey
    let eckey = EcKey::from_private_components(&group, &hash, &pubkey_point)?;

    Ok(eckey)
}

pub fn generate_eckey_by_string(group: &EcGroup, message: String) -> Result<EcKey<Private>,Box<dyn Error>>{
    // 使用 SHA-256 计算消息的哈希值
    let digest = openssl::hash::hash(MessageDigest::sha256(), message.as_bytes())?;

    // 从哈希值创建一个 BigNum 对象
    let hash = BigNum::from_slice(&digest)?;
    generate_eckey_by_hash(group,hash)
}

fn main() -> Result<(), Box<dyn Error>> {
    // 创建 secp256k1 椭圆曲线组
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;

    // 使用私有组件创建 EcKey
    let eckey = generate_eckey_by_string(&group, String::from("This is a unique seed message for generating the private key."))?;

    // 将 EC 私钥转换为通用 PKey
    let private_key = PKey::from_ec_key(eckey)?;

    // 获取私钥
    let private_key_pem = private_key.private_key_to_pem_pkcs8()?;

    // 打印私钥
    println!("Private Key (PEM):\n{}", String::from_utf8(private_key_pem)?);

    Ok(())
}