use std::{io::BufReader, sync::Arc};

use anyhow::Context;
use bip39::Language;
use bitcoin::Network;
use frozenkrill_core::{
    generate_encrypted_encoded_singlesig_wallet, get_padder, get_random_key, get_random_nonce,
    get_random_salt, get_secp,
    key_derivation::{default_derive_key, KeyDerivationDifficulty},
    parse_keyfiles_paths,
    utils::create_file,
    wallet_description::{
        generate_seeds, EncryptedWalletDescription, ScriptType, SinglesigJsonWalletDescriptionV0,
        WordCount,
    },
    PaddingParams,
};
use rand_core::RngCore;
use secrecy::{ExposeSecret, Secret, SecretString};
use tempdir::TempDir;

fn create_keyfiles_directory() -> anyhow::Result<TempDir> {
    let tempdir = tempdir::TempDir::new("integration-test")?;
    let i: u32 = rand::random();
    let keyfile1 = tempdir.path().join(format!("namedoesntmatter{i}"));
    let i: u32 = rand::random();
    let keyfile2 = tempdir.path().join(format!("whatever{i}"));
    create_file("We the Cypherpunks are dedicated to building anonymous systems. We are defending our privacy with cryptography, with anonymous mail forwarding systems, with digital signatures, and with electronic money.".as_bytes(), keyfile1.as_path())?;
    create_file("The network is robust in its unstructured simplicity. Nodes work all at once with little coordination. They do not need to be identified, since messages are not routed to any particular place and only need to be delivered on a best effort basis. Nodes can leave and rejoin the network at will, accepting the proof-of-work chain as proof of what happened while they were gone".as_bytes(), keyfile2.as_path())?;
    Ok(tempdir)
}

const TEST_DIFFICULTY: KeyDerivationDifficulty = KeyDerivationDifficulty::Easy;
const TEST_NETWORK: Network = Network::Bitcoin;
const TEST_SCRIPT_TYPE: ScriptType = ScriptType::SegwitNative;
const TEST_PASSWORD: &str = "correct horse battery staple";
const TEST_SEED_PASSWORD: &str = "correct seed battery staple";

#[test]
fn test_full_generation_process_random_wallet() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let mut password = [1u8; 1024 * 1024];
    rng.try_fill_bytes(&mut password)?;
    let header_key = get_random_key(&mut rng)?;
    let salt = get_random_salt(&mut rng)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let padder = get_padder(&mut rng, &PaddingParams::new(false, None, Some(5))?)?;
    let tempdir = create_keyfiles_directory()?;
    let secp = get_secp(&mut rng);
    let password = SecretString::new(TEST_PASSWORD.into());
    let seed_password = Some(Arc::new(SecretString::new(TEST_SEED_PASSWORD.into())));
    let mnemonic = generate_seeds(&mut rng, WordCount::W24, Language::English)?;
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let key = default_derive_key(&password, &keyfiles, &salt, &TEST_DIFFICULTY)?;
    let encoded_wallet = generate_encrypted_encoded_singlesig_wallet(
        &key,
        Secret::new(header_key),
        Arc::new(mnemonic),
        &seed_password,
        salt,
        nonce,
        header_nonce,
        padder,
        TEST_SCRIPT_TYPE,
        TEST_NETWORK,
        &secp,
    )?;
    println!(
        "encoded_wallet {} length {}",
        hex::encode(&encoded_wallet),
        encoded_wallet.len()
    );
    let decoded_wallet =
        EncryptedWalletDescription::deserialize(BufReader::new(encoded_wallet.as_slice()))?;
    let key = default_derive_key(&password, &keyfiles, &decoded_wallet.salt, &TEST_DIFFICULTY)?;
    let decrypted_wallet = decoded_wallet.decrypt_singlesig(&key)?;
    let wallet_description = decrypted_wallet.expose_secret().to(&seed_password, &secp)?;
    SinglesigJsonWalletDescriptionV0::validate_same(&decrypted_wallet, &wallet_description, &secp)?
        .context("failure checking generated wallet")?;
    Ok(())
}

#[test]
fn test_default_seed_password() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let mut password = [1u8; 1024 * 1024];
    rng.try_fill_bytes(&mut password)?;
    let header_key = get_random_key(&mut rng)?;
    let salt = get_random_salt(&mut rng)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let padder = get_padder(&mut rng, &PaddingParams::default())?;
    let tempdir = create_keyfiles_directory()?;
    let secp = get_secp(&mut rng);
    let password = SecretString::new(TEST_PASSWORD.into());
    let mnemonic = Arc::new(generate_seeds(&mut rng, WordCount::W24, Language::English)?);
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let key = default_derive_key(&password, &keyfiles, &salt, &TEST_DIFFICULTY)?;
    let encoded_wallet_no_seed_password = generate_encrypted_encoded_singlesig_wallet(
        &key,
        Secret::new(header_key),
        Arc::clone(&mnemonic),
        &None,
        salt,
        nonce,
        header_nonce,
        padder.clone(),
        TEST_SCRIPT_TYPE,
        TEST_NETWORK,
        &secp,
    )?;
    let encoded_wallet_empty_password = generate_encrypted_encoded_singlesig_wallet(
        &key,
        Secret::new(header_key),
        mnemonic,
        &Some(Arc::new(SecretString::new("".into()))), // empty password is the default
        salt,
        nonce,
        header_nonce,
        padder,
        TEST_SCRIPT_TYPE,
        TEST_NETWORK,
        &secp,
    )?;
    assert_eq!(
        encoded_wallet_no_seed_password,
        encoded_wallet_empty_password
    );
    Ok(())
}

#[test]
fn test_read_existing_wallet() -> anyhow::Result<()> {
    let encoded_wallet = "abf22187303ddaeaf3ddc734941793faa6e9e172d60609df9377df2f2f737de53a4aaa3b3da11102dd732da9179b5a4894e2fa07986b3694924a3943a67b7717ed1600b1bf2116b8ea0dcedb154c2976981dc1f0da29b43479584c0bbf26373ff34a203cd603942a73b09a53729ee16d2233c15ebd27940821a88b4a54305d49e38d7b1c40a290336d46186ab55b9f433e852db35eed2af1645ed42996a558a613282e126709b5fdc8281feae7762480ce0902f0a2be173e0e70a724ec09cac732c942e4afe759befb13a1776db451c1dc3797767f1b0374f589547e4cdbb2768c716ddabb44aff792e8a6aa4ee42748205167a7be1278ef90e66b6a6cae68f1fa45ebfa94205d62acdfad862bed984461b408e5475663da31526eb9be2fc1113f57170026012653520695a6dd302873546a7ac139438b64b4f3d61048f15da8f8ca345e045d140576ee4acd9b00fbf71a65e83ec6a6e367b8cd39d9dce93b7cea915fc47b93d12b5d1881449efa0170caaba2d2b7ea6cd604f628379c6b2492782f59d5019a5cb6cc84685a5c8b9ac86032daada18cd1d6128ddc6e38f950908e3abe8d6b171136035704d6babba1ef1d3ee24b6dda9c7bdb199c2e156e02c0eec806fb4705fb0b1e34c1c7cf8ed66fb659b25128ad3db335cadab85a9f831b7c21178cce438ab1f0ae9cf155c3cbf16d731f25898c2ae54e8d80c8a800f4dd6bfd3ac92c864737669cc77df035a67f41d20452aa1bc2e801690eb5d278ffbca4e0c4eb41038430d1d93cb6d5bcfa468d44c1b83c9d57ad179f3b3229a1f1e601c254ef5dcf05f6757cbc9992d24abdfafcbc1885bc9f16ae86837cdf56e1321b063df348d1c3b7b918639aab84708635b4d3164a18c3221964882ee9e1c366fc84ae8c672f5117e1794fa546d4f47f1f19488773f7c8215c5ef0b68fa263c5f9fc0ce527d345b2372b482ccb1e6ec48f707be5d2446a0841c0506371106f8eea115d4130630cc98b17ea2be141730599301530fa2da40cb502f93136d86e3d244179db4356683300bae37b37ff09355c21e133ea19905e6e345948ad31e84860f968b527bdd32ef63cc6bac39a43723c08dcd6c99c42232868df181499d388e514bc6b7f446df598f867f7a227d76ed3b2665d8f39ed602ca0d9f5c973da3475caae5ee5965d9867dff3fc4c030e7b50a4d70fd3d7e2eaf37913df07f689193e6578f23c485a173fc8c912e009448378cdb0c87360e30ab49e90237e513291244d0c230f50d59e9636cbc652ff5d95e5e2347ec99965519c439a660c9ae18ac7384d85a3d1fb4de5b624faf861e99b9e0bdc1d770d78eb3c08ce43f7218176b64fc155bfe1d0e3f60265a7b181716a2fa190849d4cd8dc3078f7cfd4368b2b3b9e90c01a5e93eb9658e1d944d86e956fb52bbf2ae6db3aad28052243d24e97dc57197fc5243f0b063aa8d17f88aedddf4976b50539cf01a318d88a22f97062648a9859a99ef8341d6eea1f4b75cd50a65ab5aea79d4cc0438c3e58873b87d3baae2a5062e27cae78be5dff5fa738a57619bfedfe82d0424cfd2dd20bea53796b6a7c0630f3b458f87148b6bdef37bb0e0ee92c0146d11c8b7268e56eb11f802344b59bbc936e8891dd1fad246e40a881664e39ccd5cadb72184f1e44a003a017ee5f416f547a8250dc56d5468613a6099253cefd94ea0ac3e3bfe3a7c86d060bd9992b135285f2dcbbb3988621b5e77cdfd9c0901c1a3a7ab2333b0676de5a86e04f373d67d30655e755df15a90b47052f0aeadc94a661cfe77b9e2c144d6c73ee12fcbd06f648af998f0c65f4c89b284e81034b90c9b2bd9e327881a155e95db40796d6721bc0";
    let encoded_wallet = hex::decode(encoded_wallet)?;
    let decoded_wallet =
        EncryptedWalletDescription::deserialize(BufReader::new(encoded_wallet.as_slice()))?;
    let password = SecretString::new(TEST_PASSWORD.into());
    let seed_password = Some(Arc::new(SecretString::new(TEST_SEED_PASSWORD.into())));
    let tempdir = create_keyfiles_directory()?;
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let key = default_derive_key(&password, &keyfiles, &decoded_wallet.salt, &TEST_DIFFICULTY)?;
    let decrypted_wallet = decoded_wallet.decrypt_singlesig(&key)?;
    let mut rng = rand::thread_rng();
    let secp = get_secp(&mut rng);
    let wallet_description = decrypted_wallet.expose_secret().to(&seed_password, &secp)?;
    SinglesigJsonWalletDescriptionV0::validate_same(&decrypted_wallet, &wallet_description, &secp)?
        .context("failure checking generated wallet")?;
    Ok(())
}
