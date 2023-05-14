use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 用作种子的消息
    let message = "This is a unique seed message for generating the private key.";

    // 使用 SHA-256 计算消息的哈希值
    let digest = openssl::hash::hash(MessageDigest::sha256(), message.as_bytes())?;

    // 从哈希值创建一个 BigNum 对象
    let bn = BigNum::from_slice(&digest)?;

    // 创建 secp256k1 椭圆曲线组
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;

    // 计算公钥
    let mut ctx = BigNumContext::new()?;
    let mut pubkey_point = openssl::ec::EcPoint::new(&group)?;
    pubkey_point.mul_generator(&group, &bn, &mut ctx)?;

    // 使用私有组件创建 EcKey
    let eckey = EcKey::from_private_components(&group, &bn, &pubkey_point)?;

    // 将 EC 私钥转换为通用 PKey
    let private_key = PKey::from_ec_key(eckey)?;

    // 获取私钥
    let private_key_pem = private_key.private_key_to_pem_pkcs8()?;

    // 打印私钥
    println!("Private Key (PEM):\n{}", String::from_utf8(private_key_pem)?);

    Ok(())
}