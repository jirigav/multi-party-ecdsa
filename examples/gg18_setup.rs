use std::io::BufRead;
use std::io::Write;
use std::{env, fs};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::p256::{FE, GE},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};

use paillier::EncryptionKey;

mod utils;
use utils::{send_to_all, set_connection, AES_KEY_BYTES_LEN, aes_encrypt, aes_decrypt, AEAD};


fn main() {
    let parties = env::args().nth(1).unwrap().parse::<u16>().unwrap();
    let threshold = env::args().nth(2).unwrap().parse::<u16>().unwrap();
    let index = env::args().nth(3).unwrap().parse::<u16>().unwrap();
    let port = env::args().nth(4).unwrap().parse::<u16>().unwrap();
    let ips = env::args().nth(5).unwrap();
    let path = env::args().nth(6).unwrap();

	setup(parties, threshold, index, port, ips, path);
}

fn setup(parties : u16, threshold : u16, index : u16, lowest_port : u16, ips: String, path: String) {
    let (mut sendvec, mut recvvec) = set_connection(parties, index, lowest_port, ips);
    let params = Parameters {
        threshold: threshold - 1,
        share_count: parties,
    };

    let party_keys = Keys::create(index as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&bc_i).unwrap()).as_bytes());

    let mut bc1_vec:Vec<KeyGenBroadcastMessage1> = Vec::with_capacity(parties as usize);

    for i in 0..(parties-1) {
         
        let mut received = "".to_string();
        loop {
        	let num_bytes = recvvec[i as usize].read_line(&mut received).unwrap();

        	if num_bytes > 0 {
        		break;
        	}
    	}
        received.pop();
        bc1_vec.push(serde_json::from_str::<KeyGenBroadcastMessage1>(&received).unwrap());  
        
    }

    bc1_vec.insert(index as usize, bc_i);




    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&decom_i).unwrap()).as_bytes());

    let mut round2_ans_vec:Vec<KeyGenDecommitMessage1> = Vec::with_capacity(parties as usize);

    for i in 0..(parties-1) {
        
        let mut received = "".to_string();
        loop {
        	let num_bytes = recvvec[i as usize].read_line(&mut received).unwrap();

        	if num_bytes > 0 {
        		break;
        	}
    	}
        received.pop();
        round2_ans_vec.push(serde_json::from_str::<KeyGenDecommitMessage1>(&received).unwrap());  
        
    }

    let mut j = 0;
    let mut point_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 0..parties {
        if i == index {
            point_vec.push(decom_i.y_i);
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j  = &round2_ans_vec[j];
            point_vec.push(decom_j.y_i);
            decom_vec.push(decom_j.clone());
            let key_bn: BigInt = (decom_j.y_i.clone() * party_keys.u_i).x_coor().unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    let mut j = 0;
    for i in 0..parties {
        if i != index {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[i as usize].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);

            sendvec[j].write(&format!("{}\n", serde_json::to_string(&aead_pack_i).unwrap()).as_bytes()).unwrap();
            sendvec[j].flush().unwrap(); 
            j += 1;
        }
    }

    let mut round3_ans_vec:Vec<String> = Vec::with_capacity(parties as usize);
    for i in 0..(parties-1) {
        
        let mut received = "".to_string();
        loop {
        	let num_bytes = recvvec[i as usize].read_line(&mut received).unwrap();

        	if num_bytes > 0 {
        		break;
        	}
    	}
        received.pop();
        round3_ans_vec.push(received);  
        
    }

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 0..parties {
        if i == index {
            party_shares.push(secret_shares[(i) as usize]);
        } else {
            let aead_pack : AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }


    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&vss_scheme).unwrap()).as_bytes());


    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
    for i in 0..parties {
        if i == index {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
        	let mut received = "".to_string();
        	loop {
	        	let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

	        	if num_bytes > 0 {
	        		break;
	        	}
    		}
        	received.pop();
            let vss_scheme_j: VerifiableSS<GE> = serde_json::from_str(&received).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            index as usize + 1,
        )
        .expect("invalid vss");


    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&dlog_proof).unwrap()).as_bytes());

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
    for i in 0..parties {
        if i == index {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
        	let mut received = "".to_string();
        	loop {
	        	let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

	        	if num_bytes > 0 {
	        		break;
	        	}
    		}
        	received.pop();

            let dlog_proof_j: DLogProof<GE> = serde_json::from_str(&received).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    let paillier_key_vec = (0..parties)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        index,
        threshold,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
    ))
    .unwrap();
    fs::write(path, keygen_json).expect("Unable to save !");

}

