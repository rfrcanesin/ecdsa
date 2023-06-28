use ecdsa;
use curv::{BigInt, arithmetic::Converter};

//Implemented curve: secp256k1  (you can enter manually other curves in lib.rs)

fn main() { 

    //let priv_key = ecdsa::generate_private_key();
    let priv_key = BigInt::from_hex("bb307211567f2cb78c58fe9c089a30f9b5868334ee1015c52d74b57594b6b831").unwrap();
    let pub_key = ecdsa::generate_public_key(&priv_key);

    let hash_msg = BigInt::from_hex("ac4e151e612b0669c89b4bead166a7e788a22d7edef8070fa469eb2194e49f14").unwrap();
    let sig = ecdsa::generate_signature(&hash_msg, &priv_key);
    let (r,s) = &sig;

    let verify = ecdsa::verify_signature(&hash_msg, &pub_key, r, s);

    //If you want to verify the public key and other signatures, use this website: https://paulmillr.com/noble/
    //For a random signature, in the section "Signature", copy the number called "compact" and split it in half in the strings below

    let sig_web = (BigInt::from_hex("bb7c12dc3a46de64fb06d73314695570b90095fc99dc95f96ac35214bd36446e").unwrap(), BigInt::from_hex("6609c43b2c60fbcc984b1a7dcb1616b51788aab402416e042c0299fa6dc2dc16").unwrap());
    let (r_web,s_web) = &sig_web;
    let verify_web = ecdsa::verify_signature(&hash_msg, &pub_key, r_web, s_web);

    println!("Private key: {priv_key}");
    println!("Public key: {:?}", pub_key);
    println!("Hashed message: {hash_msg}");
    println!("Signature: {:?}", sig);
    println!("Verification: {verify}");
    println!("Signature from website: {:?}", sig_web);
    println!("Verification: {verify_web}");

}
