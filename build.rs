use rustls_pki_types::{CertificateDer, pem::PemObject};
use std::{env, fs, path::PathBuf};
fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }
    println!("cargo:rustc-link-arg-bin=miaomiaoce-c5=-Tlinkall.x");
    println!("cargo:rerun-if-changed=firmware/broker-ca.pem");
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ca = fs::read(root.join("firmware/broker-ca.pem")).expect("Read broker CA");
    let ca = CertificateDer::from_pem_slice(&ca).expect("Parse broker CA PEM");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("broker-ca.der"),
        ca.as_ref(),
    )
    .unwrap();
}
