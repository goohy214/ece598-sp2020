use rand::Rng; 
use rand::distributions::Alphanumeric;
use serde::{Serialize,Deserialize};
use ring::signature::{self,Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters,UnparsedPublicKey};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Transaction {
    Input: String,
    Output: String,
}
pub struct SignedTransaction<'a> {
    Transaction: &'a str,
    Signature: &'a str,
}
    
/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let mut bytes = t.Input.clone();
    bytes.push_str(t.Output.as_str());
    key.sign(bytes.as_bytes())
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let mut bytes = t.Input.clone();
    bytes.push_str(t.Output.as_str());
    let peer_pub_key = UnparsedPublicKey::new(&signature::ED25519,public_key.as_ref());
    let result = peer_pub_key.verify(bytes.as_bytes(),signature.as_ref());
    result.is_ok()
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;

    pub fn generate_random_transaction() -> Transaction {
        Transaction {
            Input : rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(10)
                        .collect::<String>(),
            Output : rand::thread_rng()
                         .sample_iter(&Alphanumeric)
                         .take(10)
                         .collect::<String>()
        }

        //Default::default()
        //unimplemented!()
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
}
