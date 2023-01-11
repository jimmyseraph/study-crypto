use rsa::RsaPrivateKey;
use rsa::pss::{BlindedSigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, Signature, Verifier};
use sha2::{Sha256, Sha384, Sha512};
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};

const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

fn main() {
    // 准备一个线程安全的随机数生成器
    let mut rng = rand::thread_rng();

    // 定义私钥长度
    let bits = 2048;
    // 生成RSA私钥
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    // 需要进行签名的数据
    let data = b"Hello World";

    // PS256签名
    let signing_key: BlindedSigningKey<Sha256> = BlindedSigningKey::<Sha256>::new(private_key.clone());
    let verifying_key: VerifyingKey<Sha256> = (&signing_key).into();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    // base64编码
    let signature_string = CUSTOM_ENGINE.encode(signature.as_bytes());
    println!("PS256 String is: {}", signature_string);

    // PS256签名验证
    verifying_key.verify(data, &signature).expect("failed to verify");

    // PS384签名
    let signing_key: BlindedSigningKey<Sha384> = BlindedSigningKey::<Sha384>::new(private_key.clone());
    let verifying_key: VerifyingKey<Sha384> = (&signing_key).into();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    // base64编码
    let signature_string = CUSTOM_ENGINE.encode(signature.as_bytes());
    println!("PS384 String is: {}", signature_string);

    // PS384签名验证
    verifying_key.verify(data, &signature).expect("failed to verify");

    // PS512签名
    let signing_key: BlindedSigningKey<Sha512> = BlindedSigningKey::<Sha512>::new(private_key.clone());
    let verifying_key: VerifyingKey<Sha512> = (&signing_key).into();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    // base64编码
    let signature_string = CUSTOM_ENGINE.encode(signature.as_bytes());
    println!("PS512 String is: {}", signature_string);

    // PS512签名验证
    verifying_key.verify(data, &signature).expect("failed to verify");

}