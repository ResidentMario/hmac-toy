use crypto_learn::hmac_encode;

fn main() {
    let pkg = hmac_encode("Hello World", "Sekrit");
    println!("{:?}", pkg.msg);
}
