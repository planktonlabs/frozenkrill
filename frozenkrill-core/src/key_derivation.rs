use std::{
    fmt::Display,
    fs::OpenOptions,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Context, bail};
use secrecy::{ExposeSecret, SecretBox, SecretString};
type Secret<T> = SecretBox<T>;

use crate::wallet_description::{KEY_SIZE, SALT_SIZE};

pub struct Argon2DifficultyParams {
    pub ops_limit: u32,
    pub mem_limit_kbytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyDerivationDifficulty {
    Easy,
    Normal,
    Hard,
    VeryHard,
}

pub const DEFAULT_DIFFICULTY_LEVEL: KeyDerivationDifficulty = KeyDerivationDifficulty::Normal;

pub const DIFFICULTY_LEVELS: [KeyDerivationDifficulty; 4] = [
    KeyDerivationDifficulty::Easy,
    KeyDerivationDifficulty::Normal,
    KeyDerivationDifficulty::Hard,
    KeyDerivationDifficulty::VeryHard,
];

impl FromStr for KeyDerivationDifficulty {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "easy" => Ok(Self::Easy),
            "normal" => Ok(Self::Normal),
            "hard" => Ok(Self::Hard),
            "veryhard" => Ok(Self::VeryHard),
            other => bail!(
                "Invalid difficulty: {other}, valid options are: easy, normal, hard, veryhard"
            ),
        }
    }
}

impl Display for KeyDerivationDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl KeyDerivationDifficulty {
    pub const fn as_str(&self) -> &str {
        match self {
            KeyDerivationDifficulty::Easy => "Easy",
            KeyDerivationDifficulty::Normal => "Normal",
            KeyDerivationDifficulty::Hard => "Hard",
            KeyDerivationDifficulty::VeryHard => "VeryHard",
        }
    }

    const fn argon2_difficulty_params(&self) -> Argon2DifficultyParams {
        match self {
            KeyDerivationDifficulty::Easy => Argon2DifficultyParams {
                ops_limit: 42,
                mem_limit_kbytes: 256 * 1024,
            },
            KeyDerivationDifficulty::Normal => Argon2DifficultyParams {
                ops_limit: 210,
                mem_limit_kbytes: 512 * 1024,
            },
            KeyDerivationDifficulty::Hard => Argon2DifficultyParams {
                ops_limit: 930,
                mem_limit_kbytes: 1024 * 1024,
            },
            KeyDerivationDifficulty::VeryHard => Argon2DifficultyParams {
                ops_limit: 5500,
                mem_limit_kbytes: 2 * 1024 * 1024,
            },
        }
    }

    pub const fn estimate_time(&self) -> &str {
        match self {
            KeyDerivationDifficulty::Easy => "min 2-4s",
            KeyDerivationDifficulty::Normal => "min 20-40s",
            KeyDerivationDifficulty::Hard => "min 3-6m",
            KeyDerivationDifficulty::VeryHard => "min 40-80m",
        }
    }
    pub const fn estimate_memory(&self) -> &str {
        match self {
            KeyDerivationDifficulty::Easy => "256MB of RAM",
            KeyDerivationDifficulty::Normal => "512MB of RAM",
            KeyDerivationDifficulty::Hard => "1GB of RAM",
            KeyDerivationDifficulty::VeryHard => "2GB of RAM",
        }
    }
}

const KEYFILES_CONTEXT: &str = "frozenkrill keyfiles derivation";

fn libsodium_argon2id_derive_key(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    ops_limit: usize,
    mem_limit_kbytes: usize,
) -> anyhow::Result<[u8; KEY_SIZE]> {
    let mut key = [0u8; KEY_SIZE];
    let mem_limit_bytes = mem_limit_kbytes * 1024;
    alkali::hash::pbkdf::argon2id::derive_key(
        password,
        salt,
        ops_limit,
        mem_limit_bytes,
        &mut key[..],
    )?;
    Ok(key)
}

fn _default_derive_key(
    password: &SecretString,
    keyfiles: &[PathBuf],
    salt: &[u8; SALT_SIZE],
    difficulty: &KeyDerivationDifficulty,
) -> anyhow::Result<SecretBox<[u8; KEY_SIZE]>> {
    // note that if keyfiles is empty the resulting password will be the original password
    let password = generate_password_with_keyfiles(password, salt, keyfiles)?;
    let argon2_difficulty_params = difficulty.argon2_difficulty_params();
    let key_array = libsodium_argon2id_derive_key(
        password.expose_secret(),
        salt,
        argon2_difficulty_params.ops_limit.try_into()?,
        argon2_difficulty_params.mem_limit_kbytes.try_into()?,
    )?;
    let key = Secret::from(Box::new(key_array));
    Ok(key)
}

#[must_use = "expensive to calculate"]
pub fn default_derive_key(
    password: &SecretString,
    keyfiles: &[PathBuf],
    salt: &[u8; SALT_SIZE],
    difficulty: &KeyDerivationDifficulty,
) -> anyhow::Result<SecretBox<[u8; KEY_SIZE]>> {
    _default_derive_key(password, keyfiles, salt, difficulty)
        .context("failure deriving key, check if you have enough memory, perhaps try with a easier difficulty param")
}

fn copy_wide(mut reader: impl Read, hasher: &mut blake3::Hasher) -> io::Result<u64> {
    let mut buffer = vec![0; 10 * 1024 * 1024];
    let mut total = 0;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                hasher.update_rayon(&buffer[..n]);
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn generate_password_with_keyfiles(
    password: &SecretString,
    salt: &[u8],
    keyfiles: &[PathBuf],
) -> anyhow::Result<SecretBox<Vec<u8>>> {
    let mut hashes = Vec::with_capacity(keyfiles.len());
    for keyfile in keyfiles {
        let mut hasher = blake3::Hasher::new_derive_key(KEYFILES_CONTEXT);
        let f = OpenOptions::new()
            .read(true)
            .open(keyfile)
            .with_context(|| format!("failure opening keyfile {}", keyfile.display()))?;
        copy_wide(f, &mut hasher)
            .with_context(|| format!("failure reading keyfile {}", keyfile.display()))?;
        hasher.update(password.expose_secret().as_bytes());
        hasher.update(salt);
        hashes.push(hasher.finalize().as_bytes().to_vec());
    }
    hashes.sort();
    let mut concatenated_hashes = hashes.concat();
    concatenated_hashes.extend(password.expose_secret().as_bytes());
    Ok(SecretBox::from(Box::new(concatenated_hashes)))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    fn rust_argon2id_derive_key(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        ops_limit: u32,
        mem_limit_kbytes: u32,
    ) -> anyhow::Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        let params = argon2::Params::new(
            mem_limit_kbytes,
            ops_limit,
            argon2::Params::DEFAULT_P_COST,
            None,
        )
        .map_err(|e| anyhow::anyhow!("Error creating argon2 params: {e:?}"))?;
        let algorithm =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        algorithm
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| anyhow::anyhow!("Error hashing password with argon2: {e:?}"))?;
        Ok(key)
    }

    fn rargon2_derive_key(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        ops_limit: u32,
        mem_limit_kbytes: u32,
    ) -> anyhow::Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        let config = rargon2::Config {
            mem_cost: mem_limit_kbytes,
            time_cost: ops_limit,
            variant: rargon2::Variant::Argon2id,
            ..Default::default()
        };
        let raw = rargon2::hash_raw(password, salt, &config)?;
        key.copy_from_slice(&raw);
        Ok(key)
    }

    use alkali::random;
    use rand_core::RngCore;

    use crate::{random_generation_utils::get_random_salt, utils::create_file};

    use super::*;

    #[test]
    fn test_key_derivation() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        let mut rng = rand::thread_rng();
        let mut password = [1u8; 1024 * 1024];
        rng.fill_bytes(&mut password);
        let salt = get_random_salt(&mut rng)?;
        let difficulty = KeyDerivationDifficulty::Easy.argon2_difficulty_params();
        let ops_limit = difficulty.ops_limit;
        let mem_limit = difficulty.mem_limit_kbytes;

        let libsodium_time = Instant::now();
        let sodium_argon2_key = libsodium_argon2id_derive_key(
            &password,
            &salt,
            ops_limit.try_into()?,
            mem_limit.try_into()?,
        )?;
        dbg!(libsodium_time.elapsed());
        let rust_argon2_time = Instant::now();
        let rust_argon2_key = rust_argon2id_derive_key(&password, &salt, ops_limit, mem_limit)?;
        dbg!(rust_argon2_time.elapsed());
        let rargon2_time = Instant::now();
        let rargon2_key = rargon2_derive_key(&password, &salt, ops_limit, mem_limit)?;
        dbg!(rargon2_time.elapsed());
        assert_eq!(sodium_argon2_key, rust_argon2_key);
        assert_eq!(rust_argon2_key, rargon2_key);

        Ok(())
    }

    #[test]
    fn generate_password_with_keyfiles_test() -> anyhow::Result<()> {
        // very simple test for quick regression discover. more tests are present as integration tests
        let tempdir = tempfile::tempdir()?;
        let password = "abc123";
        let keyfile = tempdir
            .path()
            .join(format!("whatever{i}", i = random::random_u32()?));
        create_file("somecontent".as_bytes(), keyfile.as_path())?;
        let salt = vec![123u8; 32];

        let secret = generate_password_with_keyfiles(
            &SecretString::new(password.into()),
            &salt,
            &[keyfile],
        )?;

        assert_eq!(
            hex::encode(secret.expose_secret().as_slice()),
            "a4cca66b4fa11239814965941b2d49f59543654cfd26ac547d8bf6de93d7546f616263313233"
        );

        Ok(())
    }

    #[test]
    fn generate_password_with_empty_keyfiles_test() -> anyhow::Result<()> {
        // if not keyfiles given, this function just returns the password
        let password = "abc123";
        let salt = vec![123u8; 32];
        let secret =
            generate_password_with_keyfiles(&SecretString::new(password.into()), &salt, &[])?;
        assert_eq!(secret.expose_secret().as_slice(), password.as_bytes());
        Ok(())
    }
}
