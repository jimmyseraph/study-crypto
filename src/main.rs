use sha2::Sha256;
use hmac::{Hmac, Mac};
use hex;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"Hello World");
    let result = mac.finalize();
    let code_bytes = hex::encode(result.into_bytes());
    println!("{}", code_bytes);
}
