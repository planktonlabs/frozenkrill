use secrecy::{ExposeSecret, Secret, SecretVec};

use crate::wallet_description::{KEY_SIZE, NONCE_SIZE};

pub const MAC_LENGTH: usize = alkali::symmetric::aead::xchacha20poly1305_ietf::MAC_LENGTH;

pub(crate) fn default_encrypt(
    key: &Secret<[u8; KEY_SIZE]>,
    nonce: &[u8; NONCE_SIZE],
    message: &SecretVec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let ciphertext =
        libsodium_encrypt_xchacha20poly1305(key.expose_secret(), nonce, message.expose_secret())?;
    Ok(ciphertext)
}

pub(crate) fn default_decrypt(
    key: &Secret<[u8; KEY_SIZE]>,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> anyhow::Result<SecretVec<u8>> {
    let cleartext = SecretVec::new(libsodium_decrypt_xchacha20poly1305(
        key.expose_secret(),
        nonce,
        ciphertext,
    )?);
    Ok(cleartext)
}

fn libsodium_encrypt_xchacha20poly1305(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut k = alkali::symmetric::aead::xchacha20poly1305_ietf::Key::new_empty()?;
    k.copy_from_slice(key);
    let mut ciphertext =
        vec![0u8; message.len() + alkali::symmetric::aead::xchacha20poly1305_ietf::MAC_LENGTH];
    alkali::symmetric::aead::xchacha20poly1305_ietf::encrypt(
        message,
        None,
        &k,
        Some(nonce),
        &mut ciphertext,
    )?;
    Ok(ciphertext)
}

fn libsodium_decrypt_xchacha20poly1305(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut k = alkali::symmetric::aead::xchacha20poly1305_ietf::Key::new_empty()?;
    k.copy_from_slice(key);
    let mut plaintext =
        vec![0u8; ciphertext.len() - alkali::symmetric::aead::xchacha20poly1305_ietf::MAC_LENGTH];
    alkali::symmetric::aead::xchacha20poly1305_ietf::decrypt(
        ciphertext,
        None,
        &k,
        nonce,
        &mut plaintext,
    )?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{aead::Aead, KeyInit};
    use rand_core::RngCore;

    use crate::get_random_nonce;

    use super::*;
    fn rust_encrypt_xchacha20poly1305(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(key.into());
        let ciphertext = cipher
            .encrypt(nonce.into(), message)
            .map_err(|e| anyhow::anyhow!("Got on cipher.encrypt: {e:?}"))?;
        Ok(ciphertext)
    }

    fn rust_decrypt_xchacha20poly1305(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(key.into());
        let cleartext = cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|e| anyhow::anyhow!("Got on cipher.decrypt: {e:?}"))?;
        Ok(cleartext)
    }

    fn orion_encrypt_xchacha20poly1305(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let key = orion::hazardous::aead::xchacha20poly1305::SecretKey::from_slice(key)?;
        let nonce = orion::aead::streaming::Nonce::from_slice(nonce)?;
        let mut ciphertext =
            vec![0u8; message.len() + alkali::symmetric::aead::xchacha20poly1305_ietf::MAC_LENGTH];
        orion::hazardous::aead::xchacha20poly1305::seal(
            &key,
            &nonce,
            message,
            None,
            &mut ciphertext,
        )?;
        Ok(ciphertext)
    }

    fn orion_decrypt_xchacha20poly1305(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let key = orion::hazardous::aead::xchacha20poly1305::SecretKey::from_slice(key)?;
        let nonce = orion::aead::streaming::Nonce::from_slice(nonce)?;
        let mut cleartext = vec![
            0u8;
            ciphertext.len()
                - alkali::symmetric::aead::xchacha20poly1305_ietf::MAC_LENGTH
        ];
        orion::hazardous::aead::xchacha20poly1305::open(
            &key,
            &nonce,
            ciphertext,
            None,
            &mut cleartext,
        )?;
        Ok(cleartext)
    }

    #[test]
    fn test_encryption() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; KEY_SIZE];
        rng.try_fill_bytes(&mut key)?;
        let nonce = get_random_nonce(&mut rng)?;
        let mut message = [0u8; 1024];
        rng.try_fill_bytes(&mut message)?;

        let sodium_encrypted_xchacha20poly1305 =
            libsodium_encrypt_xchacha20poly1305(&key, &nonce, &message)?;
        let rust_encrypted_xchacha20poly1305 =
            rust_encrypt_xchacha20poly1305(&key, &nonce, &message)?;
        let orion_encrypted_xchacha20poly1305 =
            orion_encrypt_xchacha20poly1305(&key, &nonce, &message)?;
        let sodium_decrypted_xchacha20poly1305 =
            libsodium_decrypt_xchacha20poly1305(&key, &nonce, &sodium_encrypted_xchacha20poly1305)?;
        let rust_decrypted_xchacha20poly1305 =
            rust_decrypt_xchacha20poly1305(&key, &nonce, &rust_encrypted_xchacha20poly1305)?;
        let orion_decrypted_xchacha20poly1305 =
            orion_decrypt_xchacha20poly1305(&key, &nonce, &orion_encrypted_xchacha20poly1305)?;
        assert_eq!(message.to_vec(), sodium_decrypted_xchacha20poly1305);
        assert_eq!(message.to_vec(), rust_decrypted_xchacha20poly1305);
        assert_eq!(message.to_vec(), orion_decrypted_xchacha20poly1305);
        assert_eq!(
            orion_encrypted_xchacha20poly1305,
            rust_encrypted_xchacha20poly1305,
        );
        assert_eq!(
            rust_encrypted_xchacha20poly1305,
            sodium_encrypted_xchacha20poly1305,
        );
        Ok(())
    }
}
