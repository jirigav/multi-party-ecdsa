use std::io::BufReader;
use crypto::aead::AeadDecryptor;
use crypto::aead::AeadEncryptor;
use crypto::aes_gcm::AesGcm;
use crypto::aes::KeySize::KeySize256;
use std::iter::repeat;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use std::thread::sleep;
use serde::{Deserialize, Serialize};
use curv::elliptic::curves::p256::{FE, GE};
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[allow(dead_code)]
pub fn set_connection(parties : u16, index : u16, lowest_port : u16, ips: String) -> (Vec<TcpStream>, Vec<BufReader<TcpStream>>) {

	let mut sendvec:Vec<TcpStream> = Vec::with_capacity((parties - 1) as usize);
    let mut recvvec: Vec<BufReader<TcpStream>> = Vec::with_capacity((parties - 1) as usize);
    let addrs: Vec<&str> = ips.split(",").collect();

	for jj in 0..parties {
        if jj < index {
            let port = format!("0.0.0.0:{}", lowest_port + jj);
            println!("{} waiting for {} to connect on {}", index, jj, port);
            let listener = TcpListener::bind(port).unwrap_or_else(|e| { panic!(e) });
            let (recv, _) = listener.accept().unwrap_or_else(|e| {panic!(e)} );
            let send = recv.try_clone().unwrap();
            sendvec.push(send);
            recvvec.push(BufReader::new(recv));
        } else if jj > index {
            let port = format!("{}:{}", addrs[(jj) as usize], lowest_port + index);
            println!("{} connecting to {} server {:?}...", index, (jj), port);
            let mut send = TcpStream::connect(&port);
            let connection_wait_time = 2*60;
            let poll_interval = 100;
            for _ in 0..(connection_wait_time*1000/poll_interval) {
                if send.is_err() {
                    sleep(Duration::from_millis(poll_interval));
                    send = TcpStream::connect(&port);    
                }
            }
            let send = send.unwrap();
            let recv = send.try_clone().unwrap();
            sendvec.push(send);
            recvvec.push(BufReader::new(recv));
        } 
    }

    (sendvec, recvvec)
}

#[allow(dead_code)]
pub fn send_to_all(sendvec : &mut Vec<TcpStream>, data : &[u8]) {
        for i in 0..sendvec.len() {
        sendvec[i].write(data).unwrap();
        sendvec[i].flush().unwrap(); 
    }
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
    let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
    gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
    AEAD {
        ciphertext: out.to_vec(),
        tag: out_tag.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
    out
}

#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: String, pk: &GE) {
    use p256::ecdsa::Signature;
    use p256::ecdsa::{VerifyKey, signature::Verifier};

    let public_key : VerifyKey = pk.get_element();
    let signature : Signature = Signature::from_scalars(r.get_element(), s.get_element()).unwrap();


    let is_correct = public_key.verify(msg.as_bytes(), &signature).is_ok();
    assert!(is_correct);

}