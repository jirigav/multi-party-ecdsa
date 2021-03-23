#![allow(non_snake_case)]

use std::io::Write;
use std::io::BufRead;
use std::convert::TryInto;
use sha256::digest;
use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::p256::{FE, GE},
    elliptic::curves::traits::ECScalar,
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::utilities::mta::*;

use paillier::EncryptionKey;

use std::{env, fs};

mod utils;
use utils::{send_to_all, set_connection, check_sig};



fn main() {
    let message = env::args().nth(1).unwrap();
    let port = env::args().nth(2).unwrap().parse::<u16>().unwrap();
    let ips = env::args().nth(3).unwrap();
    let indices = env::args().nth(4).unwrap();
    let setup_path = env::args().nth(5).unwrap();
    let signature_path = env::args().nth(6).unwrap();

    sign(message, port, ips, indices, setup_path, signature_path);

}

fn sign(message: String, lowest_port : u16, ips: String, indices: String, setup_path: String, signature_path: String) {


	let data = fs::read_to_string(setup_path)
        .expect("Unable to load keys, did you run keygen first? ");
    let (party_keys, shared_keys, party_id, threshold, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        u16,
        Vec<VerifiableSS<GE>>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    let indices: Vec<usize> = indices.split(",").map(|x| x.parse::<usize>().unwrap()).collect();
    let threshold_index = indices.iter().position(|&x| x == party_id as usize).unwrap();
    let (mut sendvec, mut recvvec) = set_connection(threshold, threshold_index.try_into().unwrap(), lowest_port, ips);

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[party_id as usize],
        party_id as usize, 
        &indices,
    );


    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek);

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap()).as_bytes());


    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 0..threshold {
        if (i as usize) == threshold_index {
            bc1_vec.push(com.clone());

        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&received).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);

            j += 1;
            
        }
    }
    assert_eq!(indices.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<FE> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<FE> = Vec::new();
    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) != threshold_index{
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &paillier_key_vector[indices[i as usize]],
                m_a_vec[j].clone(),
            );
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &paillier_key_vector[indices[i as usize]],
                m_a_vec[j].clone(),
            );
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }



    for i in 0..(threshold - 1) {
        sendvec[i as usize].write(format!("{}\n", serde_json::to_string(&(m_b_gamma_send_vec[i as usize].clone(), m_b_w_send_vec[i as usize].clone())).unwrap()).as_bytes()).unwrap();
        sendvec[i as usize].flush().unwrap(); 
    }


    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();
    for i in 0..(threshold - 1) {
        let mut received = "".to_string();
        loop {
            let num_bytes = recvvec[i as usize].read_line(&mut received).unwrap();

            if num_bytes > 0 {
                break;
            }
        }
        received.pop();

        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&received).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
        
    }
    let mut alpha_vec: Vec<FE> = Vec::new();
    let mut miu_vec: Vec<FE> = Vec::new();

    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) != threshold_index {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[indices[i as usize]],
                &vss_scheme_vec[indices[i as usize]],
                indices[i as usize],
                &indices,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }


    //////////////////////////////////////////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);


    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&delta_i).unwrap()).as_bytes());


    let mut delta_vec: Vec<FE> = Vec::new();

    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) == threshold_index {
            delta_vec.push(delta_i.clone());
        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let value_j: FE = serde_json::from_str(&received).unwrap();
            delta_vec.push(value_j);
            j += 1;
        }
    }

    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&decommit).unwrap()).as_bytes());

    
    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();

    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) == threshold_index {
            decommit_vec.push(decommit.clone());
        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let value_j: SignDecommitPhase1 = serde_json::from_str(&received).unwrap();
            decommit_vec.push(value_j);
            j += 1;
        }
    }

    let decomm_i = decommit_vec.remove(threshold_index);
    bc1_vec.remove(threshold_index);
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<GE>>>();
    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * delta_inv;


    let message_bn = BigInt::from_bytes(&hex::decode(digest(message.clone())).unwrap());
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&phase5_com).unwrap()).as_bytes());

    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();

    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) == threshold_index {
            commit5a_vec.push(phase5_com.clone());
        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let value_j: Phase5Com1 = serde_json::from_str(&received).unwrap();
            commit5a_vec.push(value_j);
            j += 1;
        }
    }

    //phase (5B)  broadcast decommit and (5B) ZK proof

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&(
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone()
        ))
        .unwrap()).as_bytes());
    
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<GE>,
        DLogProof<GE>,
    )> = Vec::new();

    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) == threshold_index {
            decommit5a_and_elgamal_and_dlog_vec.push((
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ));
        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let value_j: (Phase5ADecom1, HomoELGamalProof<GE>, DLogProof<GE>) = serde_json::from_str(&received).unwrap();
            decommit5a_and_elgamal_and_dlog_vec.push(value_j);
            j += 1;
        }
    }

    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove(threshold_index);
    commit5a_vec.remove(threshold_index);
    let phase_5a_decomm_vec = (0..(threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..(threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<GE>>>();
    let phase_5a_dlog_vec = (0..(threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<GE>>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &phase_5a_decom.V_i,
            &R,
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&phase5_com2).unwrap()).as_bytes());

    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) == threshold_index {
            commit5c_vec.push(phase5_com2.clone());
        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let value_j: Phase5Com2 = serde_json::from_str(&received).unwrap();
            commit5c_vec.push(value_j);
            j += 1;
        }
    }

    //phase (5B)  broadcast decommit and (5B) ZK proof

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&phase_5d_decom2).unwrap()).as_bytes());

    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    let mut j = 0;
    for i in 0..threshold {
        if (i as usize) == threshold_index {
            decommit5d_vec.push(phase_5d_decom2.clone());
        } else {
            let mut received = "".to_string();
            loop {
                let num_bytes = recvvec[j as usize].read_line(&mut received).unwrap();

                if num_bytes > 0 {
                    break;
                }
            }
            received.pop();
            let value_j: Phase5DDecom2 = serde_json::from_str(&received).unwrap();
            decommit5d_vec.push(value_j);
            j += 1;
        }
    }

    let phase_5a_decomm_vec_includes_i = (0..threshold)
        .map(|i| {
            decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////

    send_to_all(&mut sendvec, &format!("{}\n", serde_json::to_string(&s_i).unwrap()).as_bytes());

    let mut s_i_vec: Vec<FE> = Vec::new();

    for i in 0..(threshold - 1) {
        let mut received = "".to_string();
        loop {
            let num_bytes = recvvec[i as usize].read_line(&mut received).unwrap();

            if num_bytes > 0 {
                break;
            }
        }
        received.pop();
        let value_j: FE= serde_json::from_str(&received).unwrap();
        s_i_vec.push(value_j);   
    }

    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");
    println!("party {:?} Output Signature: \n", threshold_index);
    println!("R: {:?}", sig.r.get_element());
    println!("s: {:?} \n", sig.s.get_element());
    println!("recid: {:?} \n", sig.recid.clone());

    let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from_bytes(&(sig.r.get_element().to_bytes())[..])).to_str_radix(16),
        "s",
        (BigInt::from_bytes(&(sig.s.get_element().to_bytes())[..])).to_str_radix(16),
    ))
    .unwrap();

    // check sig against p256
    check_sig(&sig.r, &sig.s, message, &y_sum);

    fs::write(signature_path, sign_json).expect("Unable to save !");

}