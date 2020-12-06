use hmac_toy::{hmac_encode, IntegrityVerifiedPackage};

fn main() {
    let pkg: IntegrityVerifiedPackage = hmac_encode("Hello World", "Sekrit");
    println!("{:?}", pkg.msg);
    println!("{:?}", pkg.verify("Sekrit"));
}
