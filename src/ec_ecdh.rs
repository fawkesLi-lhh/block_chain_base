use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use hex::encode;

fn main() {
    // 创建一个新的EcGroup，使用 SECP256K1 曲线
    let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();

    // 生成 Alice 的密钥对
    let alice_keypair = EcKey::generate(&group).unwrap();
    let alice_privkey = alice_keypair.private_key();
    let alice_pubkey = alice_keypair.public_key();

    // 生成 Bob 的密钥对
    let bob_keypair = EcKey::generate(&group).unwrap();
    let bob_privkey = bob_keypair.private_key();
    let bob_pubkey = bob_keypair.public_key();

    // 使用 Alice 的私钥和 Bob 的公钥计算共享密钥
    let mut ctx = BigNumContext::new().unwrap();
    let mut alice_shared_key = EcPoint::new(&group).unwrap();
    alice_shared_key.mul(&group, bob_pubkey, alice_privkey, &mut ctx).unwrap();

    // 使用 Bob 的私钥和 Alice 的公钥计算共享密钥
    let mut bob_shared_key = EcPoint::new(&group).unwrap();
    bob_shared_key.mul(&group, alice_pubkey, bob_privkey, &mut ctx).unwrap();

    // 将 EcPoint 转换为字节表示形式并比较
    assert_eq!(
        alice_shared_key.to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx).unwrap(),
        bob_shared_key.to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx).unwrap()
    );

    // 提取共享密钥的 x 和 y 坐标
    let mut shared_key_x = BigNum::new().unwrap();
    let mut shared_key_y = BigNum::new().unwrap();
    alice_shared_key.affine_coordinates(&group, &mut shared_key_x, &mut shared_key_y, &mut ctx).unwrap();

    // 将共享密钥的 x 坐标转换为字节数组
    let shared_key_bytes = shared_key_x.to_vec();

    // 将共享密钥转换为十六进制字符串
    let shared_key_hex = encode(&shared_key_bytes);

    println!("共享密钥: {}", shared_key_hex);
}