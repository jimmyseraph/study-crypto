use p256::ecdsa::{SigningKey as SigningKey256, signature::Signer as Signer256};
use p384::ecdsa::SigningKey as SigningKey384;
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};

const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

fn main()  {
    // ES256签名
    // 准备一个线程安全的随机数生成器
    let mut rng = rand::thread_rng();
    // 使用随机函数生成ECDSA的私钥，然后使用私钥生成签名，hash函数使用的是sha256
    let signing_key = SigningKey256::random(&mut rng); 
    // 准备需要签名的数据
    let message = b"Hello World";
    // 生成签名
    let signature = signing_key.sign(message);

    // base64编码
    let es256_string = CUSTOM_ENGINE.encode(signature.as_ref());
    println!("ES256 string: {}", es256_string);

    // 用一个代码块来写验证的代码，这样可以避免变量名冲突
    {
        use p256::ecdsa::{VerifyingKey, signature::Verifier};
        // 生成验证签名的公钥
        let verifying_key = VerifyingKey::from(&signing_key); 
        assert!(verifying_key.verify(message, &signature).is_ok());
    }
    
    // ES384签名
    // 使用随机函数生成ECDSA的私钥，然后使用私钥生成签名，hash函数使用的是sha384
    let signing_key = SigningKey384::random(&mut rng); 
    // 准备需要签名的数据
    let message = b"Hello World";
    // 生成签名
    let signature = signing_key.sign(message);
    // base64编码
    let es384_string = CUSTOM_ENGINE.encode(signature.as_ref());
    println!("ES384 string: {}", es384_string);
    // 用一个代码块来写验证的代码，这样可以避免变量名冲突
    {
        use p384::ecdsa::{VerifyingKey, signature::Verifier};
        // 生成验证签名的公钥
        let verifying_key = VerifyingKey::from(&signing_key); 
        assert!(verifying_key.verify(message, &signature).is_ok());
    }
    
}
