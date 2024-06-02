use std::{
    io::{stdout, Write},
    time::Instant,
};

use frozenkrill_core::{
    anyhow::{self},
    key_derivation::{self, default_derive_key},
    wallet_description::SALT_SIZE,
};

use frozenkrill_core::secrecy::SecretString;

pub(crate) mod batch_generate_export;
pub(crate) mod common;
pub(crate) mod export_public_info;
pub(crate) mod generate;
pub(crate) mod interactive;
pub(crate) mod psbt;
pub(crate) mod reencode;
pub(crate) mod show_receiving_qr_code;
pub(crate) mod show_secrets;

pub(crate) fn benchmark() -> anyhow::Result<()> {
    let password = SecretString::new("top secret".into());
    let salt = [2u8; SALT_SIZE];
    println!("Benchmarking key derivation times:");
    for difficulty in &key_derivation::DIFFICULTY_LEVELS {
        print!("difficulty = {difficulty} ...");
        stdout().lock().flush()?;
        let time = Instant::now();
        let _ = default_derive_key(&password, &[], &salt, difficulty)?;
        println!(" finished in {:#.1}s", time.elapsed().as_secs_f32());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr, sync::Arc};

    use frozenkrill_core::{
        bip39,
        bitcoin::Network,
        custom_logger, get_secp, hex,
        key_derivation::KeyDerivationDifficulty,
        psbt::open_psbt_file,
        rand,
        secrecy::{ExposeSecret, Secret},
        utils::create_file,
        wallet_description::{
            self, read_decode_wallet, MultisigJsonWalletDescriptionV0, MultisigType, PsbtWallet,
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        },
        wallet_export::{MultisigJsonWalletPublicExportV0, SinglesigJsonWalletPublicExportV0},
        MultisigInputs, PaddingParams,
    };

    use super::{
        generate::core::{singlesig_core_generate, SinglesigCoreGenerateArgs},
        *,
    };
    use crate::{
        commands::{
            common::multisig::MultisigCoreOpenWalletParam,
            generate::core::{multisig_core_generate, DuressInputArgs, MultisigCoreGenerateArgs},
        },
        get_term_theme,
    };

    #[test]
    fn test_generate_read_singlesig() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        let mut rng = rand::thread_rng();
        let mut secp = get_secp(&mut rng);
        let network = Network::Bitcoin;
        let difficulty = KeyDerivationDifficulty::Easy;
        let tempdir = tempdir::TempDir::new("test-singlesig")?;
        let output_file_path = tempdir.path().join("output_file_path");
        let public_info_json_output = tempdir.path().join("public_info_json_output");
        let keyfile1 = tempdir.path().join("keyfile1");
        create_file("stuff".as_bytes(), keyfile1.as_path())?;
        let keyfiles = &[keyfile1];
        let password = Arc::new(SecretString::new("9asFSD$#".into()));
        let mnemonic = bip39::Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")?;
        let word_count = wallet_description::WordCount::W24;
        let duress_input_args = DuressInputArgs {
            enable_duress_wallet: false,
            non_duress_output_file_json: None,
            public_json_file_path: None,
        };
        let script_type = ScriptType::SegwitNative;
        let args = SinglesigCoreGenerateArgs {
            password: Some(Arc::clone(&password)),
            output_file_path: output_file_path.clone(),
            public_info_json_output: Some(public_info_json_output.clone()),
            duress_input_args,
            keyfiles,
            user_mnemonic: Some(Arc::new(Secret::new(mnemonic))),
            word_count,
            script_type,
            network,
            difficulty: &difficulty,
            addresses_quantity: 2,
            padding_params: PaddingParams::default(),
            encrypted_wallet_version: wallet_description::EncryptedWalletVersion::V0Standard,
        };
        let mut ic = crate::MockInternetChecker::new();
        ic.expect_check().never();
        let (term, theme) = get_term_theme(true);
        singlesig_core_generate(theme.as_ref(), &term, &mut secp, &mut rng, ic, args)?;
        let mut ic = crate::MockInternetChecker::new();
        ic.expect_check().once().return_once(|| Ok(()));
        let encrypted_wallet = read_decode_wallet(&output_file_path)?;
        let (w, _) = common::singlesig::singlesig_core_open(
            theme.as_ref(),
            &term,
            &secp,
            Some(ic),
            &encrypted_wallet,
            keyfiles,
            &difficulty,
            false,
            Some(password),
        )?;
        let _j = SinglesigJsonWalletDescriptionV0::from_wallet_description(&w, &secp)?;
        let j = _j.expose_secret();
        assert_eq!(
            j.singlesig_first_address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(j.singlesig_receiving_output_descriptor, "wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#wc3n3van");
        assert_eq!(j.singlesig_change_output_descriptor, "wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#lv5jvedt");
        assert_eq!(j.singlesig_xpub, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
        assert_eq!(j.multisig_xpub, "Zpub74Jru6aftwwHxCUCWEvP6DgrfFsdA4U6ZRtQ5i8qJpMcC39yZGv3egBhQfV3MS9pZtH5z8iV5qWkJsK6ESs6mSzt4qvGhzJxPeeVS2e1zUG");
        let public_info = SinglesigJsonWalletPublicExportV0::from_path(&public_info_json_output)?;
        assert_eq!(
            public_info.to_string_pretty()?,
            r#"{
  "wallet": "frozenkrill",
  "version": 0,
  "sigtype": "singlesig",
  "master_fingerprint": "73c5da0a",
  "singlesig_xpub": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
  "singlesig_derivation_path": "m/84'/0'/0'",
  "multisig_xpub": "Zpub74Jru6aftwwHxCUCWEvP6DgrfFsdA4U6ZRtQ5i8qJpMcC39yZGv3egBhQfV3MS9pZtH5z8iV5qWkJsK6ESs6mSzt4qvGhzJxPeeVS2e1zUG",
  "multisig_derivation_path": "m/48'/0'/0'/2'",
  "singlesig_receiving_output_descriptor": "wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#wc3n3van",
  "singlesig_change_output_descriptor": "wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#lv5jvedt",
  "multisig_receiving_output_descriptor_key": "[73c5da0a/48'/0'/0'/2']xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/0/*",
  "multisig_change_output_descriptor_key": "[73c5da0a/48'/0'/0'/2']xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/1/*",
  "script_type": "segwit-native",
  "network": "bitcoin",
  "receiving_addresses": [
    {
      "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
      "derivation_path": "m/84'/0'/0'/0/0"
    },
    {
      "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
      "derivation_path": "m/84'/0'/0'/0/1"
    }
  ],
  "change_addresses": [
    {
      "address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
      "derivation_path": "m/84'/0'/0'/1/0"
    },
    {
      "address": "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf",
      "derivation_path": "m/84'/0'/0'/1/1"
    }
  ]
}"#
        );
        Ok(())
    }

    #[test]
    fn test_generate_read_multisig() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        custom_logger::init();
        let mut rng = rand::thread_rng();
        let mut secp = get_secp(&mut rng);
        let network = Network::Testnet;
        let script_type = ScriptType::SegwitNative;
        let difficulty = KeyDerivationDifficulty::Easy;
        let tempdir = tempdir::TempDir::new("test-multisig")?;
        let output_file_path_encrypted = tempdir.path().join("output_file_path_encrypted");
        let output_file_path_json = tempdir.path().join("output_file_path_json");
        let keyfile1 = tempdir.path().join("keyfile1");
        create_file("stuff".as_bytes(), keyfile1.as_path())?;
        let keyfiles = vec![keyfile1];
        let psbt = "70736274ff01005e020000000188757b1ed06cc6101dfa1de184f3af936f905c14997ed5249243b5d9694368de0100000000fdffffff01d21600000000000022002005b53149c0a926e1c534de78c706ab0140259c2634a2054ff76d808c74f67a6ce9e524004f01043587cf0000000000000000001d4fbebdd967e1af714c0997d38fcf670b5ce9d301c0440bbcc3b6a20eb7721c03568ea1f36051916ed1b690c39e12a8e70603b280bd30ce5f281f2918a55363aa043fef83ee4f01043587cf0000000000000000005f7cbbebc3eb196badd173c8416c4687a4ef7cc0cd4e0b0bdf40e7b49870f9ac02de6c4bdad6f37ea931886d213339437b478b90c9f7007636f55f36ebbd0e166c041c9cea5f4f01043587cf0000000000000000004505908a5ab63987695d789e43130dce9fc1c03bebf8a0fb1d4f243743071cf703ebc9993f99feb14b59ef12e9cabbd38529cef1cfe451bc7e970657d849648d08047a22a4fb0001012b701700000000000022002005dce3b4fa82f0c36ac4d8a8c76a74be630c2119b31eb4b2e68361516eeeb9190100ea0200000000010116d5e555d8fba55707c0fe5760844c2049bbcc057ad42910ba4825ba122b66370100000000feffffff029aac250000000000160014834bef9c2733a2983d3b9bb25e4af01ff6040a96701700000000000022002005dce3b4fa82f0c36ac4d8a8c76a74be630c2119b31eb4b2e68361516eeeb9190247304402207ae93b9a19ff553d0e206afb13ef7e02914bfac2ff05ce4465d28108b17429b00220465d2418488c50724e51540d3ce6ed64a15528b3906e5b33e4da347bff47c54a012102d4318c88211a7335dfd14c415e2c07006ea8caf746407589241a7ee15c0b39b5e9e524000105695221025df3211bcff0b1f18c83695c9d7ac7df7fb6f96df17fe1d84a5286ab7791ff6121030b90ed2e86bad7f2a4fe9769bb417d7ba9caa1124807dbfb362dfbeeb65e7e0121039daf0e68deea41a5cbd517f2637bad9bbea8327786470237f448bbca2ff57f3553ae2206025df3211bcff0b1f18c83695c9d7ac7df7fb6f96df17fe1d84a5286ab7791ff610c7a22a4fb00000000000000002206030b90ed2e86bad7f2a4fe9769bb417d7ba9caa1124807dbfb362dfbeeb65e7e010c3fef83ee00000000000000002206039daf0e68deea41a5cbd517f2637bad9bbea8327786470237f448bbca2ff57f350c1c9cea5f00000000000000000001016952210366dab8a136865a497b81ca7dc4e23cf35331d28f4459526fea1d76ca25e407fe2103689572e28b0feda9d6981c0237d9e5dedbfec16de7143f680a02ed5d159f7587210386696e229e1a346fe03965e1e4150c79a9c9ceabc25e10f91d6c031f55b5c95f53ae22020366dab8a136865a497b81ca7dc4e23cf35331d28f4459526fea1d76ca25e407fe0c1c9cea5f0000000001000000220203689572e28b0feda9d6981c0237d9e5dedbfec16de7143f680a02ed5d159f75870c3fef83ee000000000100000022020386696e229e1a346fe03965e1e4150c79a9c9ceabc25e10f91d6c031f55b5c95f0c7a22a4fb000000000100000000";
        let psbt2 = "70736274ff01005e020000000188757b1ed06cc6101dfa1de184f3af936f905c14997ed5249243b5d9694368de0100000000fdffffff01d21600000000000022002005b53149c0a926e1c534de78c706ab0140259c2634a2054ff76d808c74f67a6cd8ec24004f01043587cf04bac14839800000021d4fbebdd967e1af714c0997d38fcf670b5ce9d301c0440bbcc3b6a20eb7721c03568ea1f36051916ed1b690c39e12a8e70603b280bd30ce5f281f2918a55363aa1473c5da0a300000800100008000000080020000804f01043587cf04bb0b78ee800000025f7cbbebc3eb196badd173c8416c4687a4ef7cc0cd4e0b0bdf40e7b49870f9ac02de6c4bdad6f37ea931886d213339437b478b90c9f7007636f55f36ebbd0e166c147f4d5c70300000800100008000000080020000804f01043587cf04a563ead1800000024505908a5ab63987695d789e43130dce9fc1c03bebf8a0fb1d4f243743071cf703ebc9993f99feb14b59ef12e9cabbd38529cef1cfe451bc7e970657d849648d081498d0d15a300000800100008000000080020000800001007d020000000116d5e555d8fba55707c0fe5760844c2049bbcc057ad42910ba4825ba122b66370100000000feffffff029aac250000000000160014834bef9c2733a2983d3b9bb25e4af01ff6040a96701700000000000022002005dce3b4fa82f0c36ac4d8a8c76a74be630c2119b31eb4b2e68361516eeeb919e9e5240001012b701700000000000022002005dce3b4fa82f0c36ac4d8a8c76a74be630c2119b31eb4b2e68361516eeeb919010304010000000105695221025df3211bcff0b1f18c83695c9d7ac7df7fb6f96df17fe1d84a5286ab7791ff6121030b90ed2e86bad7f2a4fe9769bb417d7ba9caa1124807dbfb362dfbeeb65e7e0121039daf0e68deea41a5cbd517f2637bad9bbea8327786470237f448bbca2ff57f3553ae2206030b90ed2e86bad7f2a4fe9769bb417d7ba9caa1124807dbfb362dfbeeb65e7e011c73c5da0a3000008001000080000000800200008000000000000000002206039daf0e68deea41a5cbd517f2637bad9bbea8327786470237f448bbca2ff57f351c7f4d5c703000008001000080000000800200008000000000000000002206025df3211bcff0b1f18c83695c9d7ac7df7fb6f96df17fe1d84a5286ab7791ff611c98d0d15a3000008001000080000000800200008000000000000000000001016952210366dab8a136865a497b81ca7dc4e23cf35331d28f4459526fea1d76ca25e407fe2103689572e28b0feda9d6981c0237d9e5dedbfec16de7143f680a02ed5d159f7587210386696e229e1a346fe03965e1e4150c79a9c9ceabc25e10f91d6c031f55b5c95f53ae220203689572e28b0feda9d6981c0237d9e5dedbfec16de7143f680a02ed5d159f75871c73c5da0a30000080010000800000008002000080000000000100000022020366dab8a136865a497b81ca7dc4e23cf35331d28f4459526fea1d76ca25e407fe1c7f4d5c7030000080010000800000008002000080000000000100000022020386696e229e1a346fe03965e1e4150c79a9c9ceabc25e10f91d6c031f55b5c95f1c98d0d15a30000080010000800000008002000080000000000100000000";
        let psbt_path = tempdir.path().join("psbt.psbt");
        let psbt2_path = tempdir.path().join("psbt2.psbt");
        create_file(&hex::decode(psbt)?, &psbt_path)?;
        create_file(&hex::decode(psbt2)?, &psbt2_path)?;
        let seeds = [bip39::Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")?,
            bip39::Mnemonic::from_str("fly often rather version bulk text affair super iron bunker whip shrug")?,
            bip39::Mnemonic::from_str("father engine pizza shrimp suffer add outside inspire two visa neglect quote")?];
        let signers = seeds
            .iter()
            .cloned()
            .map(|seed| {
                SingleSigWalletDescriptionV0::generate(
                    Arc::new(Secret::new(seed)),
                    &None,
                    network,
                    script_type,
                    &secp,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        assert_eq!(
            "Vpub5n95dMZrDHj6SeBgJ1oz4Fae2N2eJNuWK3VTKDb2dzGpMFLUHLmtyDfen7AaQxwQ5mZnMyXdVrkEaoMLVTH8FmVBRVWPGFYWhmtDUGehGmq",
            signers[0].encoded_multisig_xpub());
        assert_eq!(
            "Vpub5myyN3hupCfSaGExukQxaGiWTjmRSUNUBDdrLXetXUCwwhm43i7tSU93TumrVLTC5VsD9oJ4tAYHA8doPJBYtRwXmTJqidoNEX8PrJHtrhJ",
            signers[1].encoded_multisig_xpub());
        assert_eq!(
            "Vpub5n9Cny7T8XGH2QofyDniyNyawwZEy4r4n1KCacMx9Wz45Hw6TfPjhEj8QRraqdJhaaYujwhqRc2amUdRa67zDyF4csqJXJ1LsXnzAKC3Hmj",
            signers[2].encoded_multisig_xpub());

        assert_eq!(
            "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/*)#2ag6nxcd",
            signers[0]
                .receiving_singlesig_output_descriptor()?
                .to_string()
        );
        assert_eq!(
            "wpkh([98d0d15a/84'/1'/0']tpubDD944mr5LAG9roWx4BiFiepQa14md36G1RhrRZ8q9LAstuzTzBuGTs81aQfskaA88gJxqk2bDUXTJjcBhQwMqCZxGa1BACAwsei6vKP4vsU/0/*)#h9dvq9qs",
            signers[1]
                .receiving_singlesig_output_descriptor()?
                .to_string()
        );
        assert_eq!(
            "wpkh([7f4d5c70/84'/1'/0']tpubDCJzBahFj9ZuXSnvZwemfzLpXJPKeiPVpqhrj5ZvSe8Kpu6rHJ7o7BJ7LfbaY3twqzkyrkijJq9wYPyyBhkckzY2JnENJsTt1wSL3b4xTmx/0/*)#3eq3976z",
            signers[2]
                .receiving_singlesig_output_descriptor()?
                .to_string()
        );
        let receiving_descriptors = signers
            .iter()
            .map(|s| s.receiving_multisig_public_descriptor())
            .collect();
        let change_descriptors = signers
            .iter()
            .map(|s| s.change_multisig_public_descriptor())
            .collect();
        let total = 3;
        let password = Arc::new(SecretString::new("9asFSD$#".into()));
        let args = MultisigCoreGenerateArgs {
            password: Some(Arc::clone(&password)),
            configuration: MultisigType { required: 2, total },
            inputs: MultisigInputs {
                receiving_descriptors,
                change_descriptors,
                signers,
            },
            output_file_path_encrypted: output_file_path_encrypted.clone(),
            output_file_path_json: Some(output_file_path_json.clone()),
            keyfiles: &keyfiles,
            network,
            difficulty: &difficulty,
            addresses_quantity: 2,
            padding_params: PaddingParams::default(),
        };
        let (term, theme) = get_term_theme(true);
        multisig_core_generate(theme.as_ref(), &term, &mut secp, &mut rng, args)?;
        let signers = seeds
            .iter()
            .cloned()
            .map(|seed| {
                SingleSigWalletDescriptionV0::generate(
                    Arc::new(Secret::new(seed)),
                    &None,
                    network,
                    script_type,
                    &secp,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        // Try to sign PSBTs using the singlesig wallet
        let mut psbt = open_psbt_file(&psbt_path)?;
        for signer in &signers {
            let n: usize = signer.sign_psbt(&mut psbt, &secp)?;
            assert_eq!(n, 1);
        }

        let input_wallets = vec![
            MultisigCoreOpenWalletParam::Encrypted {
                input_wallet: read_decode_wallet(&output_file_path_encrypted)?,
                password: Some(Arc::clone(&password)),
                keyfiles: keyfiles.to_owned(),
                difficulty,
            },
            MultisigCoreOpenWalletParam::Json(Secret::new(
                MultisigJsonWalletPublicExportV0::from_path(&output_file_path_json)?,
            )),
        ];
        for input_wallet in input_wallets {
            let wallet = common::multisig::multisig_core_open(
                theme.as_ref(),
                &term,
                &secp,
                input_wallet,
                Some(signers.clone()),
            )?;
            let json_wallet =
                MultisigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)?;
            assert_eq!(
                "tb1qqhww8d86stcvx6kymz5vw6n5he3scggekv0tfvhxsds4zmhwhyvsp346h3",
                json_wallet.expose_secret().first_address
            );
            assert_eq!(
                "wsh(sortedmulti(2,[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*,[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/0/*,[98d0d15a/48'/1'/0'/2']tpubDF83NP8zFt9V85eg5zWKNHu5R17i6kAwEocvLcEGFctCB1VJrqupjvGDwepLTDVNTDZkPjzwTNgvVijmvKhsDreMjGLbAadaUCaDoXDoMeB/0/*))#tfc0mal5",
                json_wallet.expose_secret().receiving_output_descriptor
            );
            // Try to sign PSBTs using the multisig wallet
            let mut psbt = open_psbt_file(&psbt_path)?;
            let mut psbt2 = open_psbt_file(&psbt2_path)?;
            let n: u32 = wallet.sign_psbt(&mut psbt, &secp)?.try_into()?;
            assert_eq!(n, total);
            let n: u32 = wallet.sign_psbt(&mut psbt2, &secp)?.try_into()?;
            assert_eq!(n, total);
            let public_info = MultisigJsonWalletPublicExportV0::from_path(&output_file_path_json)?;
            assert_eq!(
                public_info.to_string_pretty()?,
                r#"{
  "wallet": "frozenkrill",
  "version": 0,
  "sigtype": "2-of-3",
  "script_type": "segwit-native",
  "network": "testnet",
  "receiving_output_descriptor": "wsh(sortedmulti(2,[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*,[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/0/*,[98d0d15a/48'/1'/0'/2']tpubDF83NP8zFt9V85eg5zWKNHu5R17i6kAwEocvLcEGFctCB1VJrqupjvGDwepLTDVNTDZkPjzwTNgvVijmvKhsDreMjGLbAadaUCaDoXDoMeB/0/*))#tfc0mal5",
  "change_output_descriptor": "wsh(sortedmulti(2,[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/1/*,[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/1/*,[98d0d15a/48'/1'/0'/2']tpubDF83NP8zFt9V85eg5zWKNHu5R17i6kAwEocvLcEGFctCB1VJrqupjvGDwepLTDVNTDZkPjzwTNgvVijmvKhsDreMjGLbAadaUCaDoXDoMeB/1/*))#wun49m0u",
  "receiving_addresses": [
    {
      "address": "tb1qqhww8d86stcvx6kymz5vw6n5he3scggekv0tfvhxsds4zmhwhyvsp346h3",
      "index": 0
    },
    {
      "address": "tb1qqk6nzjwq4ynwr3f5meuvwp4tq9qzt8pxxj3q2nlhdkqgca8k0fkqtsnl29",
      "index": 1
    }
  ],
  "change_addresses": [
    {
      "address": "tb1qdemlrvnajrk32a7en773e4hv6dhr3v5c52zkqn7j9khvn6v2q8mqlqmmv4",
      "index": 0
    },
    {
      "address": "tb1qwsmhdlg0y8fggx0uxfq27mn4hfd5k3lk8r9ejqlvazq0hktz9nrsfam5qx",
      "index": 1
    }
  ]
}"#
            );
        }
        Ok(())
    }

    #[test]
    fn test_generate_read_descriptors_multisig() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        let mut rng = rand::thread_rng();
        let mut secp = get_secp(&mut rng);
        let network = Network::Testnet;
        let difficulty = KeyDerivationDifficulty::Easy;
        let tempdir = tempdir::TempDir::new("test-public-keys-multisig")?;
        let output_file_path_encrypted = tempdir.path().join("output_file_path_encrypted");
        let output_file_path_json = tempdir.path().join("output_file_path_json");
        let keyfile1 = tempdir.path().join("keyfile1");
        create_file("stuff".as_bytes(), keyfile1.as_path())?;
        let keyfiles = vec![keyfile1];
        let input_files_descriptors = vec![
            create_file(
                r#"[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/<0;1>/*"#.as_bytes(),
                &tempdir.path().join("descriptor1.txt"),
            )?.to_path_buf(),
            create_file(
                r#"[98d0d15a/48'/1'/0'/2']tpubDF83NP8zFt9V85eg5zWKNHu5R17i6kAwEocvLcEGFctCB1VJrqupjvGDwepLTDVNTDZkPjzwTNgvVijmvKhsDreMjGLbAadaUCaDoXDoMeB/0/*"#.as_bytes(),
                &tempdir.path().join("descriptor2.txt"),
            )?.to_path_buf(),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources/tests/73C5DA0A_coldcard-generic-export.json"),
        ];
        let (term, theme) = get_term_theme(true);
        let mut multisig_inputs = MultisigInputs::default();
        for input_file in input_files_descriptors {
            let input =
                common::multisig::parse_multisig_input(theme.as_ref(), &term, &secp, &input_file)?;
            assert_eq!(multisig_inputs.merge(input)?, 1);
        }
        let total = 3;
        let password = Arc::new(SecretString::new("9asFSD$#".into()));
        let args = MultisigCoreGenerateArgs {
            password: Some(Arc::clone(&password)),
            configuration: MultisigType { required: 2, total },
            inputs: multisig_inputs,
            output_file_path_encrypted: output_file_path_encrypted.clone(),
            output_file_path_json: Some(output_file_path_json.clone()),
            keyfiles: &keyfiles,
            network,
            difficulty: &difficulty,
            addresses_quantity: 2,
            padding_params: PaddingParams::default(),
        };
        multisig_core_generate(theme.as_ref(), &term, &mut secp, &mut rng, args)?;
        let input_wallets = vec![
            MultisigCoreOpenWalletParam::Encrypted {
                input_wallet: read_decode_wallet(&output_file_path_encrypted)?,
                password: Some(Arc::clone(&password)),
                keyfiles: keyfiles.to_owned(),
                difficulty,
            },
            MultisigCoreOpenWalletParam::Json(Secret::new(
                MultisigJsonWalletPublicExportV0::from_path(&output_file_path_json)?,
            )),
        ];
        for input_wallet in input_wallets {
            let wallet = common::multisig::multisig_core_open(
                theme.as_ref(),
                &term,
                &secp,
                input_wallet,
                Some(vec![]),
            )?;
            let json_wallet =
                MultisigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp)?;
            assert_eq!(
                "tb1qqhww8d86stcvx6kymz5vw6n5he3scggekv0tfvhxsds4zmhwhyvsp346h3",
                json_wallet.expose_secret().first_address
            );
            assert_eq!(
            "wsh(sortedmulti(2,[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*,[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/0/*,[98d0d15a/48'/1'/0'/2']tpubDF83NP8zFt9V85eg5zWKNHu5R17i6kAwEocvLcEGFctCB1VJrqupjvGDwepLTDVNTDZkPjzwTNgvVijmvKhsDreMjGLbAadaUCaDoXDoMeB/0/*))#tfc0mal5",
            json_wallet.expose_secret().receiving_output_descriptor
        );
        }
        Ok(())
    }
}
