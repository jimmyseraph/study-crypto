use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, Signature, Verifier};
use sha2::{Sha256, Sha384, Sha512};
use hex;


fn main() {
    // 准备一个线程安全的随机数生成器
    let mut rng = rand::thread_rng();

    // 定义私钥长度
    let bits = 2048;
    // 生成RSA私钥
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    // 需要进行签名的数据
    let data = b"Hello World";

    // RS256签名
    let signing_key: SigningKey<Sha256> = SigningKey::<Sha256>::new_with_prefix(private_key.clone());
    let verifying_key: VerifyingKey<Sha256> = (&signing_key).into();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    let signature_string = hex::encode(signature.as_bytes());
    println!("RS256 String is: {}", signature_string);

    // RS256签名验证
    verifying_key.verify(data, &signature).expect("failed to verify");

    // RS384签名
    let signing_key: SigningKey<Sha384> = SigningKey::<Sha384>::new_with_prefix(private_key.clone());
    let verifying_key: VerifyingKey<Sha384> = (&signing_key).into();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    let signature_string = hex::encode(signature.as_bytes());
    println!("RS384 String is: {}", signature_string);

    // RS384签名验证
    verifying_key.verify(data, &signature).expect("failed to verify");

    // RS512签名
    let signing_key: SigningKey<Sha512> = SigningKey::<Sha512>::new_with_prefix(private_key.clone());
    let verifying_key: VerifyingKey<Sha512> = (&signing_key).into();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    let signature_string = hex::encode(signature.as_bytes());
    println!("RS512 String is: {}", signature_string);

    // RS512签名验证
    verifying_key.verify(data, &signature).expect("failed to verify");

}