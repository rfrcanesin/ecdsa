use ecdsa::{self, GEN_ORDER};
use rand::Rng;

//a = 2, b = 2, p = 17, gen_x = 5, gen_y = 1, gen_order = 19

fn main() { 

    let priv_key = ecdsa::generate_private_key();
    let pub_key = ecdsa::generate_public_key(priv_key);

    let hash_msg = rand::thread_rng().gen_range(1..=GEN_ORDER) as i32;
    let sig = ecdsa::generate_signature(hash_msg as i32, priv_key);
    let (r,s) = sig;

    let verify = ecdsa::verify_signature(hash_msg as i32, &pub_key, r, s);

    let rand_r = rand::thread_rng().gen_range(1..GEN_ORDER) as i32;
    let rand_s = rand::thread_rng().gen_range(1..GEN_ORDER) as i32;
    let rand_verify = ecdsa::verify_signature(hash_msg as i32, &pub_key, rand_r, rand_s);

    println!("Private key: {priv_key}");
    println!("Public key: {:?}", pub_key);
    println!("Hashed message: {hash_msg}");
    println!("Signature: {:?}", sig);
    println!("Verification: {verify}");
    println!("Random signature: {:?}", (rand_r,rand_s));
    println!("Verification: {rand_verify}");

}
