use std::convert::TryFrom;

use anyhow::{anyhow, ensure, Context, Result};

use libsignal_protocol::{IdentityKeyPair, KeyPair, PrivateKey, PublicKey, HKDF};
use rand::{CryptoRng, Rng};

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hmac::{Hmac, Mac, NewMac};
use prost::Message as _;
use sha2::Sha256;

use super::DecryptedProvision;
use crate::proto;

pub struct ProvisionCipher {
    key_pair: KeyPair,
}

impl ProvisionCipher {
    pub fn generate<R: Rng + CryptoRng>(rnd: &mut R) -> Self {
        Self {
            key_pair: KeyPair::generate(rnd),
        }
    }

    pub fn public_key(&self) -> Box<[u8]> {
        self.key_pair.public_key.serialize()
    }

    pub fn decrypt(&self, msg: crate::proto::ProvisionEnvelope) -> Result<DecryptedProvision> {
        let master_ephemeral = PublicKey::deserialize(msg.public_key())
            .map_err(|e| anyhow!("deserialize master ephemeral key: {}", e))?;
        let msg: &[u8] = msg.body();

        ensure!(msg.len() >= 1 + 16 + 32, "message too small");
        ensure!(msg[0] == 1, "bad version number on ProvisioningMessage");

        let iv = &msg[1..16 + 1];
        let mac = &msg[msg.len() - 32..];
        let iv_and_ciphertext = &msg[..msg.len() - 32];
        let ciphertext = &msg[16 + 1..msg.len() - 32];

        let agreement = self
            .key_pair
            .private_key
            .calculate_agreement(&master_ephemeral)
            .map_err(|e| anyhow!("calculate agreement: {}", e))?;

        let key = HKDF::new(3)
            .map_err(|e| anyhow!("create hkdf: {}", e))?
            .derive_secrets(&agreement, b"TextSecure Provisioning Message", 64)
            .map_err(|e| anyhow!("calculate hkdf: {}", e))?;
        let decryption_key = &key[..32];
        let verification_key = &key[32..64];

        let mut verification = Hmac::<Sha256>::new_varkey(&verification_key)
            .map_err(|e| anyhow!("create hmac: {}", e))?;
        verification.update(iv_and_ciphertext);
        verification
            .verify(mac)
            .map_err(|_| anyhow!("invalid mac"))?;

        let mut plaintext = vec![0u8; ciphertext.len()];
        plaintext.copy_from_slice(ciphertext);

        let plaintext = Cbc::<Aes256, Pkcs7>::new_var(decryption_key, iv)
            .context("init aes-cbc")?
            .decrypt(&mut plaintext)
            .context("decrypt provision message")?;

        let msg =
            proto::ProvisionMessage::decode(&*plaintext).context("decode provision message")?;

        let private_key = PrivateKey::deserialize(msg.identity_key_private())
            .map_err(|e| anyhow!("decode identity private key: {}", e))?;
        let identity_key_pair = IdentityKeyPair::try_from(private_key)
            .map_err(|e| anyhow!("convert private key to identity key pair: {}", e))?;

        Ok(DecryptedProvision {
            identity_key_pair,
            provisioning_code: msg.provisioning_code.unwrap_or_default(),
            user_agent: msg.user_agent.unwrap_or_default(),
            read_receipts: msg.read_receipts.unwrap_or_default(),
            profile_key: msg.profile_key,
            uuid: msg.uuid.unwrap_or_default(),
            number: msg.number.unwrap_or_default(),
        })
    }
}
