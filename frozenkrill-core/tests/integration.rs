use std::{collections::HashSet, io::BufReader, str::FromStr, sync::Arc};

use anyhow::Context;
use bip39::Language;
use bitcoin::Network;
use frozenkrill_core::{
    MultisigInputs, PaddingParams, generate_encrypted_encoded_multisig_wallet,
    generate_encrypted_encoded_singlesig_wallet, get_padder,
    key_derivation::{KeyDerivationDifficulty, default_derive_key},
    parse_keyfiles_paths,
    random_generation_utils::{get_random_key, get_random_nonce, get_random_salt, get_secp},
    utils::create_file,
    wallet_description::{
        EncryptedWalletDescription, EncryptedWalletVersion, MultisigType, ScriptType,
        SinglesigJsonWalletDescriptionV0, WordCount, generate_seeds,
    },
};
use miniscript::DescriptorPublicKey;
use rand_core::RngCore;
use secrecy::{ExposeSecret, SecretBox, SecretString};

type Secret<T> = SecretBox<T>;
use tempfile::TempDir;

fn create_keyfiles_directory() -> anyhow::Result<TempDir> {
    let tempdir = tempfile::tempdir()?;
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
    rng.fill_bytes(&mut password);
    let header_key = get_random_key(&mut rng)?;
    let salt = get_random_salt(&mut rng)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let padder = get_padder(&mut rng, &PaddingParams::new(false, None, Some(5))?)?;
    let tempdir = create_keyfiles_directory()?;
    let secp = get_secp(&mut rng);
    let password = SecretString::new(TEST_PASSWORD.into());
    let seed_password = Some(Arc::new(SecretString::new(TEST_SEED_PASSWORD.into())));
    let mnemonic = Arc::new(generate_seeds(&mut rng, WordCount::W24, Language::English)?);
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let key = default_derive_key(&password, &keyfiles, &salt, &TEST_DIFFICULTY)?;

    for encrypted_wallet_version in [
        EncryptedWalletVersion::V0Standard,
        EncryptedWalletVersion::V0CompactTestnet,
    ] {
        let encoded_wallet = generate_encrypted_encoded_singlesig_wallet(
            &key,
            Secret::from(Box::new(header_key)),
            Arc::clone(&mnemonic),
            &seed_password,
            salt,
            nonce,
            header_nonce,
            padder.clone(),
            TEST_SCRIPT_TYPE,
            TEST_NETWORK,
            encrypted_wallet_version,
            &secp,
        )?;
        println!(
            "encoded_wallet singlesig {encrypted_wallet_version:?}: {} length {}",
            hex::encode(&encoded_wallet),
            encoded_wallet.len()
        );
        let decoded_wallet =
            EncryptedWalletDescription::deserialize(BufReader::new(encoded_wallet.as_slice()))?;
        let key = default_derive_key(&password, &keyfiles, &decoded_wallet.salt, &TEST_DIFFICULTY)?;
        let decrypted_wallet = decoded_wallet.decrypt_singlesig(&key, &seed_password, &secp)?;
        let wallet_description = decrypted_wallet.expose_secret().to(&seed_password, &secp)?;
        SinglesigJsonWalletDescriptionV0::validate_same(
            &decrypted_wallet,
            &wallet_description,
            &secp,
        )?
        .context("failure checking generated wallet")?;
    }
    Ok(())
}

#[test]
fn test_default_seed_password() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let mut password = [1u8; 1024 * 1024];
    rng.fill_bytes(&mut password);
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
    for encrypted_wallet_version in [
        EncryptedWalletVersion::V0Standard,
        EncryptedWalletVersion::V0CompactTestnet,
    ] {
        let encoded_wallet_no_seed_password = generate_encrypted_encoded_singlesig_wallet(
            &key,
            Secret::from(Box::new(header_key)),
            Arc::clone(&mnemonic),
            &None,
            salt,
            nonce,
            header_nonce,
            padder.clone(),
            TEST_SCRIPT_TYPE,
            TEST_NETWORK,
            encrypted_wallet_version,
            &secp,
        )?;
        let encoded_wallet_empty_password = generate_encrypted_encoded_singlesig_wallet(
            &key,
            Secret::from(Box::new(header_key)),
            Arc::clone(&mnemonic),
            &Some(Arc::new(SecretString::new("".into()))), // empty password is the default
            salt,
            nonce,
            header_nonce,
            padder.clone(),
            TEST_SCRIPT_TYPE,
            TEST_NETWORK,
            encrypted_wallet_version,
            &secp,
        )?;
        assert_eq!(
            encoded_wallet_no_seed_password,
            encoded_wallet_empty_password
        );
    }
    Ok(())
}

#[test]
fn test_read_existing_singlesig_wallet() -> anyhow::Result<()> {
    let encoded_wallet_standard = "abf22187303ddaeaf3ddc734941793faa6e9e172d60609df9377df2f2f737de53a4aaa3b3da11102dd732da9179b5a4894e2fa07986b3694924a3943a67b7717ed1600b1bf2116b8ea0dcedb154c2976981dc1f0da29b43479584c0bbf26373ff34a203cd603942a73b09a53729ee16d2233c15ebd27940821a88b4a54305d49e38d7b1c40a290336d46186ab55b9f433e852db35eed2af1645ed42996a558a613282e126709b5fdc8281feae7762480ce0902f0a2be173e0e70a724ec09cac732c942e4afe759befb13a1776db451c1dc3797767f1b0374f589547e4cdbb2768c716ddabb44aff792e8a6aa4ee42748205167a7be1278ef90e66b6a6cae68f1fa45ebfa94205d62acdfad862bed984461b408e5475663da31526eb9be2fc1113f57170026012653520695a6dd302873546a7ac139438b64b4f3d61048f15da8f8ca345e045d140576ee4acd9b00fbf71a65e83ec6a6e367b8cd39d9dce93b7cea915fc47b93d12b5d1881449efa0170caaba2d2b7ea6cd604f628379c6b2492782f59d5019a5cb6cc84685a5c8b9ac86032daada18cd1d6128ddc6e38f950908e3abe8d6b171136035704d6babba1ef1d3ee24b6dda9c7bdb199c2e156e02c0eec806fb4705fb0b1e34c1c7cf8ed66fb659b25128ad3db335cadab85a9f831b7c21178cce438ab1f0ae9cf155c3cbf16d731f25898c2ae54e8d80c8a800f4dd6bfd3ac92c864737669cc77df035a67f41d20452aa1bc2e801690eb5d278ffbca4e0c4eb41038430d1d93cb6d5bcfa468d44c1b83c9d57ad179f3b3229a1f1e601c254ef5dcf05f6757cbc9992d24abdfafcbc1885bc9f16ae86837cdf56e1321b063df348d1c3b7b918639aab84708635b4d3164a18c3221964882ee9e1c366fc84ae8c672f5117e1794fa546d4f47f1f19488773f7c8215c5ef0b68fa263c5f9fc0ce527d345b2372b482ccb1e6ec48f707be5d2446a0841c0506371106f8eea115d4130630cc98b17ea2be141730599301530fa2da40cb502f93136d86e3d244179db4356683300bae37b37ff09355c21e133ea19905e6e345948ad31e84860f968b527bdd32ef63cc6bac39a43723c08dcd6c99c42232868df181499d388e514bc6b7f446df598f867f7a227d76ed3b2665d8f39ed602ca0d9f5c973da3475caae5ee5965d9867dff3fc4c030e7b50a4d70fd3d7e2eaf37913df07f689193e6578f23c485a173fc8c912e009448378cdb0c87360e30ab49e90237e513291244d0c230f50d59e9636cbc652ff5d95e5e2347ec99965519c439a660c9ae18ac7384d85a3d1fb4de5b624faf861e99b9e0bdc1d770d78eb3c08ce43f7218176b64fc155bfe1d0e3f60265a7b181716a2fa190849d4cd8dc3078f7cfd4368b2b3b9e90c01a5e93eb9658e1d944d86e956fb52bbf2ae6db3aad28052243d24e97dc57197fc5243f0b063aa8d17f88aedddf4976b50539cf01a318d88a22f97062648a9859a99ef8341d6eea1f4b75cd50a65ab5aea79d4cc0438c3e58873b87d3baae2a5062e27cae78be5dff5fa738a57619bfedfe82d0424cfd2dd20bea53796b6a7c0630f3b458f87148b6bdef37bb0e0ee92c0146d11c8b7268e56eb11f802344b59bbc936e8891dd1fad246e40a881664e39ccd5cadb72184f1e44a003a017ee5f416f547a8250dc56d5468613a6099253cefd94ea0ac3e3bfe3a7c86d060bd9992b135285f2dcbbb3988621b5e77cdfd9c0901c1a3a7ab2333b0676de5a86e04f373d67d30655e755df15a90b47052f0aeadc94a661cfe77b9e2c144d6c73ee12fcbd06f648af998f0c65f4c89b284e81034b90c9b2bd9e327881a155e95db40796d6721bc0";

    let encoded_wallet_compact = "330e3ea18e5f2d46a3eb1b4ac7e91851f6f8ad50016ab41fc66a8f0bb7e30fa510de4989c4a41dad6af954dd7d02520794d70944b16908b8e4d5d1f1721e95bf4cb9569ea97ab73ec54c37ac3fa717c9cc60cf1ebb5e2690c5c8a37b45d6cb9404c26d39bf96cb39869a5ce6a6c33c1fb7d06468d83bf71a41ec65b2dfda0df7e253e6f04ba89b0c70828353fdf2274831c2cdf2828b3da995ea8a4c0127ed7bafc1f67f0fb353cc";

    let tempdir = create_keyfiles_directory()?;
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let mut rng = rand::thread_rng();
    let secp = get_secp(&mut rng);
    let password = SecretString::new(TEST_PASSWORD.into());

    for encoded_wallet in [encoded_wallet_standard, encoded_wallet_compact] {
        let encoded_wallet = hex::decode(encoded_wallet)?;
        let decoded_wallet =
            EncryptedWalletDescription::deserialize(BufReader::new(encoded_wallet.as_slice()))?;
        let seed_password = Some(Arc::new(SecretString::new(TEST_SEED_PASSWORD.into())));
        let key = default_derive_key(&password, &keyfiles, &decoded_wallet.salt, &TEST_DIFFICULTY)?;
        let decrypted_wallet = decoded_wallet.decrypt_singlesig(&key, &seed_password, &secp)?;
        let wallet_description = decrypted_wallet.expose_secret().to(&seed_password, &secp)?;
        SinglesigJsonWalletDescriptionV0::validate_same(
            &decrypted_wallet,
            &wallet_description,
            &secp,
        )?
        .context("failure checking generated wallet")?;
    }
    Ok(())
}

#[test]
fn test_generation_multisig_wallet() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let mut password = [1u8; 1024 * 1024];
    rng.fill_bytes(&mut password);
    let salt = get_random_salt(&mut rng)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let tempdir = create_keyfiles_directory()?;
    let secp = get_secp(&mut rng);
    let password = SecretString::new(TEST_PASSWORD.into());
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let key = default_derive_key(&password, &keyfiles, &salt, &TEST_DIFFICULTY)?;

    let script_type = ScriptType::SegwitNative;

    let required = 2;
    let total = 3;
    let configuration = MultisigType::new(required, total)?;
    let receiving_descriptors = [
        "[620fc36a/48'/0'/0'/2']xpub6EjtYhwFJ6eqAZrt9QmhhtKGofpeorUVnmjZ68V5zVSRZ1SsqcEgCpM7KcziKSychLb28kBmcBwJ4LgtsaWjYHLiE2jFXPVayd952ZL4jk5/0/*" ,
        "[99f25136/48'/0'/0'/2']xpub6F8EegNUubkpWFkbJHYyD1aQC62yG3yDKJVHL6V3CCxGBDfrvrZmeB2yvM4jWFSuBkvGpGU6HonJqFZSprJMsQiytgeBxuhbmkgTASuPvgM/0/*","[efe66085/48'/0'/0'/2']xpub6ENstZhSr4L1cEqzpRBBs5SQcjHbXAGuoHeiUSBo3DfP2R5irgZAFgf7buZjhBi4fWMZAy3yFQ5Lh9fGqbbRAs2GoMHBD7upUmyNVj55r28/0/*"
    ].into_iter().map(|s| Ok(DescriptorPublicKey::from_str(s)?)).collect::<anyhow::Result<HashSet<_>>>()?;
    let change_descriptors = [
        "[620fc36a/48'/0'/0'/2']xpub6EjtYhwFJ6eqAZrt9QmhhtKGofpeorUVnmjZ68V5zVSRZ1SsqcEgCpM7KcziKSychLb28kBmcBwJ4LgtsaWjYHLiE2jFXPVayd952ZL4jk5/1/*" ,
        "[99f25136/48'/0'/0'/2']xpub6F8EegNUubkpWFkbJHYyD1aQC62yG3yDKJVHL6V3CCxGBDfrvrZmeB2yvM4jWFSuBkvGpGU6HonJqFZSprJMsQiytgeBxuhbmkgTASuPvgM/1/*","[efe66085/48'/0'/0'/2']xpub6ENstZhSr4L1cEqzpRBBs5SQcjHbXAGuoHeiUSBo3DfP2R5irgZAFgf7buZjhBi4fWMZAy3yFQ5Lh9fGqbbRAs2GoMHBD7upUmyNVj55r28/1/*"
    ].into_iter().map(|s| Ok(DescriptorPublicKey::from_str(s)?)).collect::<anyhow::Result<HashSet<_>>>()?;

    let inputs = MultisigInputs {
        receiving_descriptors,
        change_descriptors,
        signers: vec![],
    };

    for encrypted_wallet_version in [
        EncryptedWalletVersion::V0Standard,
        EncryptedWalletVersion::V0CompactTestnet,
    ] {
        let padder = get_padder(&mut rng, &PaddingParams::new(false, None, Some(5))?)?;

        let header_key = Secret::from(Box::new(get_random_key(&mut rng)?));
        let encoded_wallet = generate_encrypted_encoded_multisig_wallet(
            configuration,
            inputs.clone(),
            &key,
            header_key,
            salt,
            nonce,
            header_nonce,
            padder,
            script_type,
            TEST_NETWORK,
            encrypted_wallet_version,
            &secp,
        )?;
        println!(
            "encoded_wallet multisig {encrypted_wallet_version:?}: {} length {}",
            hex::encode(&encoded_wallet),
            encoded_wallet.len()
        );
    }

    Ok(())
}

#[test]
fn test_read_existing_multisig_wallet() -> anyhow::Result<()> {
    let encoded_wallet_standard = "653117627897eca8532abb09de7fc502b8e9a16c40ee103621c874d4895c566cb11be28cbe45823a25ba9b769efbdcbf6bdfe0a210f1916e0687fdb01f4ed8123b48d9593df2749dd142afe3bc6774ad1fb630a4a1aa061d936424b72e2061259282304a03de46aec6b22cc3548bf901f64b8a527acf6f7809fa1500b40010fe7a266822e5dcf7bd4b16de4255779a6978226b4292358a9e1a1b547221b313517878b9649ae690d11f7ebac4cf7777ff04f9084a69b688b5c4f4ea2ca2f96827ddd9c1fd6deedeb24fd02bac0ae4fdd0d5580d5c50508018f8ac7d5c81ac5b7a8debf9cf6467e7def10c136676b3a26073b59385c7d77e1caa106a8d3f727c9bee34623260a35a5baa40c287d488467fec625dc118b8c45da49018b9a8842175c77a129e51f5bb06fa41558847200cd66783d1b7812bb4cd6f7a44ed98b307d102bbcb9b327b0ae59ea991665661b934244678f23c15fd267e5b81ba7b1fc0ea5fe7fe9cde555a509cddb201158f8b4c336276bdf16fb69f3d9afdeb812cbc4ca1ddcde312065b7fd7335fdaf2cd2c8f2774be522665db4b718a57c6372bdd1d1ddc5a3bf68b1ee8d99a3d3f75cc67568c2b644f5aeb97e950e80990a173f41a2eb4a04a867ebc02016fb18475a1440a6901c6c4a90aed14c8a4d9955f9908d7a98e454dcc616dbeabb9681edc7ff248d995872d11d9937c8dbcb41af5cad8cfe70af2a90cc07321ab4711d17d4a31c5f6c36874b8a1265d720a107a2b1654ebd1e834f30a6c7cc9cf0130068cdac7395e12fb69c072999a3b7fa7b044a636bafd8ad9b49e540e994ed0270609ae9de9b4043610d61feab6f8c775fa48c60ac881eac02ff2670370e7e9787fb0f0a9493c4c6055e415dbb0145ff90be0581ba075d5590387b02a201c71ee300c1931aed3131c5fd5dac39f9f7abac0bd72d5ff662cbdc90568cbb10f375c1141801e92864b4b234030c1c6d9e071788f136501db4f0aedab9785ee97702815d82195a3f5fb68ed908348fd9d21ec66c503a3632fb9d4a8b7e948e4bd40e79a519762f3817466ae52048779d6e6f17ef8fb6d73b844dd5861bbbdb750991fc235c9ede8c5d029242f5c10ea3f1ed1176badf7d877e777a135bb62b136dc48827c5b3eb316cf6e9c1ba56a9ac342182b73d645b4570e5661b9a190e1610ba715fd601761e9e3279454263c9390ab8e996b775ce17c5c77f75d9bb9959c1bc5da01a9d8fd81e5ceb29f5d76d758c3684307e8c78e0baaf608fcf69f3ed6e26e55a4f36d1f4fac0688cd49d4d7239e9d4d3f8527ffefa010fc109ba786ce5c81f4372709bc559d28cb2b52977a024ac83f0cac0470debed3cda67d88fecd0cfba2bb5d5d191cdfea0122af4c9ad227d5f856a16b16f20e1b5aa78e4bc1c94d5e00161083d6fd924e05748cb2e955edb6494cac7f471a1486710b801fe946601169431583bca5cb33f6b57541e49b4ab6724427ad221cbb57e5be9bd59fcbd5814bedf0a9a06498072af9a242bf698471a4ae4ed2e9582fce612df793f2817acc8ecd3ce131948d9aeee082faa21fc959fc0a3ef51b4061f33842e41c1630ce1b4a9d49322cd9ee2ed82127773d5c54c02035a7dab5731ee46d0cb12fe07b7a70fbcac547c774a54fb956581dff84605efd05522f8beba409bf5bcf9cfd859dd453248094b055f95d921086dadb3b23ec9c91dbcbac85beab2604de621a5f53bd80ba9b3e40a8f7a706075c9466bce57a4fef607528181da7d2dd32252979bd490eb427ca8168e08388bda501ad8d8511af7bb7d999e2af1cd3a2303ce80d942345f92515beebf2fb6c2025c33f864070c030556585903a09a19d80177db538099f";

    let encoded_wallet_compact = "653117627897eca8532abb09de7fc502b8e9a16c40ee103621c874d4895c566cb11be28cbe45823a9b441018d467ab50a4979692b6f394cd47f92a074798bfd12ebb10e98ec09795d142afe3bc6774ad1fb630a4a1aa061d936424b72e2061259082304a7add46ae812693a40765542155d0a0079d2f174d7c715a18dbf506232d4033780e120898e84bf1703b88c2d3ee1d6571d88ab8baa12566041c6944fd6836c45e8eff0c9517f34ab8c6e4496712984dae98d1c9cb329bbbe4f5eb2564755fe7c912e24d6b23d9530eeaf86f297740f548d2318047bf16540719979e87b379df193e7e2454dfaafb918efca4405c893b327d93546093fa5b9bbdfa3da680c81d6b50841b97412a56a0411899e075ab3f76bb11445a32cae35a2a574d40a636e5fbe419ef281ae9b8a86768ac64dd33419ad339c64344641cacd95beaa92771d8a0cc9281573c913c63daad14d57cc4216e0ef2787648b1f3962d35561f26bc682d189fe20ec8acb278c4c66aacd90d2e1037464b1850b7b0fbdf2a9c346fc003492868cac728f7c4d88812b95556e4addb39fb929b97f944281901a572505256101fa0f9f6df58e6b68a3b1207af886c0514dd0981ffc4230cc942848240512af6846db6c0ca4363157fadc1dab99ca79eb8";

    let tempdir = create_keyfiles_directory()?;
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let mut rng = rand::thread_rng();
    let secp = get_secp(&mut rng);
    let password = SecretString::new(TEST_PASSWORD.into());

    for encoded_wallet in [encoded_wallet_standard, encoded_wallet_compact] {
        let encoded_wallet = hex::decode(encoded_wallet)?;
        let decoded_wallet =
            EncryptedWalletDescription::deserialize(BufReader::new(encoded_wallet.as_slice()))?;
        let key = default_derive_key(&password, &keyfiles, &decoded_wallet.salt, &TEST_DIFFICULTY)?;
        let _decrypted_wallet = decoded_wallet.decrypt_multisig(&key, &secp)?;
    }
    Ok(())
}
