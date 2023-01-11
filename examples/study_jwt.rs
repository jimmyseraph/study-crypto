use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::ErrorKind};
use chrono::{prelude::{DateTime, Local}, Duration};

// 准备Claim结构体，用于存放JWT的payload部分
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    // registered claims
    iss: String,
    sub: String,
    exp: usize,

    // public claims
    website: String,

    // private claims
    user_id: String,
}

fn main() {
    // 定义header部分的“alg”参数，也就是算法名称
    let header = Header::new(Algorithm::ES384);

    // 准备过期时间
    let exp: DateTime<Local> = Local::now();
    exp.checked_add_signed(Duration::seconds(60));

    // 准备claims数据
    let claims = Claims {
        iss: "Louis".to_string(),
        sub: "testops.vip".to_string(),
        exp: exp.timestamp() as usize,
        website: "https://testops.vip".to_string(),
        user_id: "123456".to_string(),
    };

    // 从pem文件中读取私钥
    let key = EncodingKey::from_ec_pem(include_bytes!("../ec-private.pem")).unwrap();

    // 将header和claims进行签名，组合后生成token
    let token = encode(&header, &claims, &key).unwrap();

    println!("token: {}", token);

    // 校验token
    let mut validation = Validation::new(Algorithm::ES384);
    // 定义需要校验payload中的iss
    validation.set_issuer(&["Louis"]);
    // 定义需要校验payload中的sub
    validation.sub = Some("testops.vip".to_string());
    // 从公钥文件生成解码的密钥
    let key = DecodingKey::from_ec_pem(include_bytes!("../ec-public.pem")).unwrap();
    // 进行校验，并返回Payload的Claim结构体
    let token_data = match decode::<Claims>(&token, &key, &validation) {
        Ok(c) => c, // 校验通过
        Err(err) => match *err.kind() { //校验不通过
            ErrorKind::InvalidToken => panic!("Token 不存在"), 
            ErrorKind::InvalidIssuer => panic!("Issuer 不存在"),
            ErrorKind::InvalidSubject => panic!("Subject 不存在"),
            _ => panic!("其他错误: {:?}", err),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}