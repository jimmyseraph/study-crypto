# 学习各种签名算法

# 生成ECC私钥文件，椭圆曲线名称为secp384r1
```shell
openssl ecparam -genkey -noout -name secp384r1 | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
```
# 生成公钥文件
```shell
openssl ec -in ec-private.pem -pubout -out ec-public.pem 
```