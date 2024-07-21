use std::{collections::HashSet, io::BufReader, str::FromStr, sync::Arc};

use anyhow::Context;
use bip39::Language;
use bitcoin::Network;
use frozenkrill_core::{
    generate_encrypted_encoded_multisig_wallet, generate_encrypted_encoded_singlesig_wallet,
    get_padder,
    key_derivation::{default_derive_key, KeyDerivationDifficulty},
    parse_keyfiles_paths,
    random_generation_utils::{get_random_key, get_random_nonce, get_random_salt, get_secp},
    utils::create_file,
    wallet_description::{
        generate_seeds, EncryptedWalletDescription, EncryptedWalletVersion, MultisigType,
        ScriptType, SinglesigJsonWalletDescriptionV0, WordCount,
    },
    MultisigInputs, PaddingParams,
};
use miniscript::DescriptorPublicKey;
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
    let mnemonic = Arc::new(generate_seeds(&mut rng, WordCount::W24, Language::English)?);
    let keyfiles = parse_keyfiles_paths(&[tempdir.into_path().to_str().unwrap().to_owned()])?;
    let key = default_derive_key(&password, &keyfiles, &salt, &TEST_DIFFICULTY)?;

    for encrypted_wallet_version in [
        EncryptedWalletVersion::V0Standard,
        EncryptedWalletVersion::V0CompactTestnet,
    ] {
        let encoded_wallet = generate_encrypted_encoded_singlesig_wallet(
            &key,
            Secret::new(header_key),
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
    for encrypted_wallet_version in [
        EncryptedWalletVersion::V0Standard,
        EncryptedWalletVersion::V0CompactTestnet,
    ] {
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
            encrypted_wallet_version,
            &secp,
        )?;
        let encoded_wallet_empty_password = generate_encrypted_encoded_singlesig_wallet(
            &key,
            Secret::new(header_key),
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
    rng.try_fill_bytes(&mut password)?;
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

        let header_key = Secret::new(get_random_key(&mut rng)?);
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
    let encoded_wallet_standard = "7572bfe45ccc0888f2e062c914fb1105dc1efc59803894451f0199a3aea3fc30ae873fb014beb44d5ec3e26609611782fd255d3077da6dd8fbc4234a155fb39c2fbc64799e6602dfbd964be52df745e1696b5574aa1da2e7b60ddf9338bdd166aa0f5a40dc384479835352276090f1d36e032f64fac792a0fa53a78f056d35f3cc8bcbf879b2152b8b99ecca5001722b8cf6cbc655bb11a3e673318b8d3769f632721cd3d1d4c072de0a7e72e8978ca8843c6f3b72415db943d3fbbfceb52f0dee26c44964898f9fc9c6087b8ace9c3fa89c21ce58da4800e107ded4a4949ae7ad74083902ad229464784369218785fe35e1a94fdaf3ea016819957a24d0f693c857ebb140a233cb948e4e83f78f65df8066e37b97f4e0c4c5b17511a2e39b462fe52c29a74cbccb82c7231f15adf6844b1f5d9c0a7c7dd2016e208d98e7d8aff87eaac9a689d03a58e99214da215e83061647ff5f0fd8fa0661e3764df4f9e89035c62136595b239bf7e3b17d07c1f8187c475fbadafba0f52c098454e4d37bc747bf6808586a4a0c895105e64791a96725e896bb357bd9c3bbeb98fe2cd086456ac124f5178e8b896b03497caadf9cddbe8ee01debbf4651e399877079c1c7aa49df60bb1db8b27c0b2cda59526195ca64050cc23c33dc53d4d96140d42cf88e5758b5c923c171199e1d428ce0e8ba1c27011ca1e78a431cea735c22c75e630dec7eef8783e2c2274d3c406452d9de35f1d933047f1c4fa7749633f5eab16d01a7f753a4296a89d531500aad154e0cc9c3f51a66fbd476fac0d9c38ae545604e61987e0f4ee69a46474855bcee28278e3e7fcd1ba02f4382c3665b66707d786980d6c8b2a0a6aff57e185582a0f903f85eb5ca5e596242fde50f9db652e7b97133604ff68afa40d44fedc3556d52652f50d4e17183325a5de8a319150125b941fbdd2c06fa2374064201975d0cdb13c1581148c6c5cfb8cd96c3e10a0ff0dd9ce91e0307b3f95ec0687e888c5cccf9c1bccb8f952656b5347be302a47a9fd53213a2ed436d49fce78c6c007a13ef64daa4befd85d78a7945626dd964a858c993668a765039cbea5c0dc4c19acdbd18c03d48a40c7372ac089dbeb40e5f23762d33edc3df4d1056aa5363b969ae07f5687f5da424cd991e256e652b3185854343ae26da4b8d3bbecce557de90a6854dc4a8f67d405f4d1b7e0e5481ec004cc5de89690c45c104d8c25f92f8afe7052e2bba3519badea9fdf5a58db35fe6f5fb857c7c3862ddfbedbafe6dafde61ff3f6e07899d1f0cd07d94e962b995341d27fe73d1fe42ed45eff3bd9d37606ef90fe6e8b829b4de613d9bbba55755a20b22b6d0439151c90670f462d3c0b134c52b4b3db753dcc88f8ef7bfca7e9ad8ba1633e4d3ea0ec261e4307dc39f3d7cccb7a49bf979e4c02617620d4cf3e733b472a73d62c7b57a037db8b6d03d301e66de7e15a6eca7dcb6271243e68ee722e953b660faedf02f54bdb0c342d18fa6d2a650dfeed5a405e3c30179d6f6d268b65c6ddf12b2dd023633d0b0ee9b7451974bedabf6119bc586df87771ba72d7f56efcc09140fad8166ddad526c4f7cf2c475b0988a3a19447cdc271172e095976b1594aac4ba5ff9a0248cda66a513c6b1035d4b679df0ff7fb155007e69a42144604811030f531f974dec50393c8a3dd7c069114152e67bf2e7723691fe7b175bd502b67fe9670490b2a891de7d0535e2ed2b7e0cf35990149b8dd77c4409f8fe079aed300fee9d58c86f5c73b32ea42e75346490bdee64cb17bedf6bbe99f47a9ce72fb5967c40d52df37b50b34dabafb791a560f91e4c956e3fe628223e68be4fcee48e85a70426196ddbc7";

    let encoded_wallet_compact = "7572bfe45ccc0888f2e062c914fb1105dc1efc59803894451f0199a3aea3fc30ae873fb014beb44d27756ca5b2dbb35e37b6845eebecc9caedb740bca3b6cf392ecfd996a2ffea42bd964be52df745e1696b5574aa1da2e7b60ddf9338bdd166a80f5a40983b44794a980debf1edd464de0b3a4611f45bd4e387725d673af9deedda8536c504d3c0e9d5ce42ff55863d443bdd29f20c5d77441a019615dd601812541154255f27a7d76d099dd22c3d28f4d0e086a72abc3a415e425ac0cfa75dfefabd869b7f1734c5f07d6d6f335a1c5187c50b1c28d7fb58f5c5ae8893f892bb677eb633114e625c0a4d59f887125a4cb0285fd8939540a3b98f792ac481138f5af05597c01644db3bffbb541bd5c32097212fe9c4591bc00d0299c68d575aa85b4d859c11504e5ab44af567ea9c35e33f17269adb93792cd3f416f97ff5449e520eb428b94b612e7c8e35385ba793c494568ad6df844e07f200b62c802f60200ace8002ceb49de7f2eb09583ce0c8e95c46cf4b70208cda0872c5926d50b73b4cb9230fd674368acba90ff5796a84edbcbe9cec480950f87342d605d617e3597c590c7713cb33e0272f53afc07976fc660a67e5bc3f6668f064efa7e8c1d6abb303f5265912792ff84931b369415e81432d56fee67a71";

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
