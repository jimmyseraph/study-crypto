use sha2::{Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac};
use hex;

// 定义相关别名
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

fn main() {

    // HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"Hello World");
    let result = mac.finalize();
    let hs256_string = hex::encode(result.into_bytes());
    println!("HS256 String is: {}", hs256_string);

    // HMAC-SHA384
    let mut mac = HmacSha384::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"Hello World");
    let result = mac.finalize();
    let hs384_string = hex::encode(result.into_bytes());
    println!("HS384 String is: {}", hs384_string);

    // HMAC-SHA512
    let mut mac = HmacSha512::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"Hello World");
    let result = mac.finalize();
    let hs512_string = hex::encode(result.into_bytes());
    println!("HS512 String is: {}", hs512_string);
}