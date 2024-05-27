#[cfg(feature = "cli_tests")]
use std::{fs, io::Write, process::Command};

#[cfg(feature = "cli_tests")]
use frozenkrill_core::{
    anyhow, log,
    utils::create_file,
    wallet_export::{MultisigJsonWalletPublicExportV0, SinglesigJsonWalletPublicExportV0},
};

#[cfg(feature = "cli_tests")]
use rexpect::session::{spawn_command, PtySession};

#[cfg(feature = "cli_tests")]
fn run_cli(args: &[&str]) -> anyhow::Result<PtySession> {
    let cmd = {
        let mut c = Command::new("cargo");
        c.args([
            "run",
            "--release",
            "--target",
            current_platform::CURRENT_PLATFORM,
            "--",
        ]);
        c.args(args);
        c
    };
    log::info!("Running with args: {args:?}");
    Ok(spawn_command(cmd, Some(600_000))?)
}

#[cfg(feature = "cli_tests")]
fn dialoguer_up_enter(p: &mut PtySession) -> anyhow::Result<()> {
    send_line(p, "k")?;
    Ok(())
}

#[cfg(feature = "cli_tests")]
fn send(p: &mut PtySession, s: &str) -> anyhow::Result<()> {
    p.writer.write_all(s.as_bytes())?;
    p.flush()?;
    Ok(())
}

#[cfg(feature = "cli_tests")]
fn send_line(p: &mut PtySession, s: &str) -> anyhow::Result<()> {
    send(p, &format!("{s}\n"))?;
    Ok(())
}

#[test]
#[cfg(feature = "cli_tests")]
fn test_generate_open_singlesig() -> anyhow::Result<()> {
    use pretty_assertions::{assert_eq, assert_ne};

    for wallet_type in ["standard", "compact"] {
        let temp = tempdir::TempDir::new(&format!("cli-generate-singlesig-{wallet_type}"))?;
        let keyfile1 = temp.path().join("keyfile1");
        create_file("keyfile1".as_bytes(), &keyfile1)?;
        let wallet_path = temp.path().join("mywallet");
        let public_info_path = temp.path().join("public_info.json");
        let nonduress_public_info_path = temp.path().join("public_info_non_duress.json");
        let mypassword = "Super11Ultra&SAASD*()";
        let mynonduresspassword = "seedpass";

        let mut s = run_cli(&[
            "--disable-internet-check",
            "--use-simple-theme",
            "singlesig-generate",
            "--difficulty",
            "easy",
            "--enable-duress-wallet",
            "--wallet-file-type",
            wallet_type,
            "--keyfile",
            keyfile1.display().to_string().as_str(),
            wallet_path.display().to_string().as_str(),
            public_info_path.display().to_string().as_str(),
        ])?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Enter a non duress seed password")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Wallet saved to")?;
        s.exp_string("Enter the non duress seed password again")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Exported public info to")?;
        s.exp_string("Exported non duress public info to")?;
        s.exp_string("Finished successfully!")?;
        s.exp_eof()?;
        assert!(wallet_path.exists());
        assert!(public_info_path.exists());
        assert!(nonduress_public_info_path.exists());
        let info = SinglesigJsonWalletPublicExportV0::from_path(&public_info_path)?;
        let non_duress_info =
            SinglesigJsonWalletPublicExportV0::from_path(&nonduress_public_info_path)?;
        assert_ne!(
            info.to_string_pretty()?,
            non_duress_info.to_string_pretty()?
        );
        let public_info_path2 = temp.path().join("public_info2.json");
        let nonduress_public_info_path2 = temp.path().join("public_info_non_duress2.json");
        let mut s = run_cli(&[
            "--disable-internet-check",
            "--use-simple-theme",
            "singlesig-open",
            "--difficulty",
            "easy",
            "--keyfile",
            keyfile1.display().to_string().as_str(),
            "--enable-duress-wallet",
            wallet_path.display().to_string().as_str(),
            "export-public-info",
            public_info_path2.display().to_string().as_str(),
            nonduress_public_info_path2.display().to_string().as_str(),
        ])?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Enter a non duress seed password")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Enter the non duress seed password again")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_eof()?;
        assert!(public_info_path2.exists());
        assert!(nonduress_public_info_path2.exists());
        let info2 = SinglesigJsonWalletPublicExportV0::from_path(&public_info_path2)?;
        let non_duress_info2 =
            SinglesigJsonWalletPublicExportV0::from_path(&nonduress_public_info_path2)?;
        assert_eq!(info.to_string_pretty()?, info2.to_string_pretty()?);
        assert_eq!(
            non_duress_info.to_string_pretty()?,
            non_duress_info2.to_string_pretty()?
        );
        eprintln!("generated {wallet_type} wallet");
    }
    Ok(())
}

#[test]
#[cfg(feature = "cli_tests")]
fn test_batch_generate_open_multisig() -> anyhow::Result<()> {
    use pretty_assertions::assert_eq;

    let temp = tempdir::TempDir::new("cli-batch-generate-open-multisig")?;
    let wallet_path_prefix = temp.path().join("mywallet");
    let mypassword = "Super11Ultra&SAASD*()";
    let mynonduresspassword = "seedpass";

    println!("---> Will generate a batch of singlesig wallets");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "singlesig-batch-generate-export",
        "--difficulty",
        "easy",
        "--enable-duress-wallet",
        "--wallets-quantity",
        "3",
        wallet_path_prefix.display().to_string().as_str(),
    ])?;
    s.exp_string("Do you want to pick one or more keyfiles?")?;
    send(&mut s, "n")?;
    s.exp_string("Continue without a keyfile?")?;
    send(&mut s, "y")?;
    s.exp_string("Password:")?;
    send_line(&mut s, mypassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, mypassword)?;
    s.exp_string("Enter a non duress seed password")?;
    send_line(&mut s, mynonduresspassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, mynonduresspassword)?;
    s.exp_string("Enter the non duress seed password again")?;
    send_line(&mut s, mynonduresspassword)?;
    s.exp_eof()?;
    let wallets = fs::read_dir(temp.path())?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|i| {
            i.file_name().to_string_lossy().starts_with("mywallet")
                && !i.file_name().to_string_lossy().ends_with(".json")
        })
        .map(|i| i.path())
        .collect::<Vec<_>>();
    assert_eq!(wallets.len(), 3);
    let multisig_path = temp.path().join("multisigwallet");
    let multisig_pub_path = temp.path().join("multisigwalletpub.json");
    let keyfile1 = temp.path().join("keyfile1");
    create_file("keyfile1".as_bytes(), &keyfile1)?;
    println!("---> Will generate a multisig wallet");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "multisig-generate",
        "--difficulty",
        "easy",
        "--keyfile",
        keyfile1.display().to_string().as_str(),
        "--encrypted-wallet-output-file",
        multisig_path.display().to_string().as_str(),
        "2-of-3",
        wallets[0].display().to_string().as_str(),
        wallets[1].display().to_string().as_str(),
        wallets[2].display().to_string().as_str(),
        "--json-output-file",
        multisig_pub_path.display().to_string().as_str(),
    ])?;
    // try once with wrong password
    println!("---> Trying with wrong password on first wallet");
    s.exp_string("Have you used a keyfile when generating this wallet?")?;
    send(&mut s, "n")?;
    s.exp_string("Select one (leave the default if unsure)")?;
    dialoguer_up_enter(&mut s)?;
    s.exp_string("Password:")?;
    let wrongpassword = "wrongpassword";
    send_line(&mut s, wrongpassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, wrongpassword)?;
    s.exp_string("Enable duress feature for this wallet?")?;
    send(&mut s, "n")?;
    s.exp_string("Got an error, try to open another file?")?;
    send(&mut s, "y")?;
    for i in 0..3 {
        println!("---> Opening singlesig wallet {i} for multisig generation");
        s.exp_string("Have you used a keyfile when generating this wallet?")?;
        send(&mut s, "n")?;
        s.exp_string("Select one (leave the default if unsure)")?;
        dialoguer_up_enter(&mut s)?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Enable duress feature for this wallet?")?;
        send(&mut s, "y")?;
        s.exp_string("Enter a non duress seed password")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mynonduresspassword)?;
    }
    let multisigpassword = "Super11Ultra!!!X";
    s.exp_string("Password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_eof()?;
    assert!(multisig_path.exists());
    assert!(multisig_pub_path.exists());
    let info = MultisigJsonWalletPublicExportV0::from_path(&multisig_pub_path)?;
    let multisig_pub_path2 = temp.path().join("multisigwalletpub2.json");
    println!("---> Opening encrypted multisig wallet");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "multisig-open",
        "--difficulty",
        "easy",
        "--keyfile",
        keyfile1.display().to_string().as_str(),
        multisig_path.display().to_string().as_str(),
        "-i",
        wallets[0].display().to_string().as_str(),
        "-i",
        wallets[1].display().to_string().as_str(),
        "-i",
        wallets[2].display().to_string().as_str(),
        "export-public-info",
        multisig_pub_path2.display().to_string().as_str(),
    ])?;
    for i in 0..3 {
        println!("---> Opening signer wallet {i} for multisig operation");
        s.exp_string("Have you used a keyfile when generating this wallet?")?;
        send(&mut s, "n")?;
        s.exp_string("Select one (leave the default if unsure)")?;
        dialoguer_up_enter(&mut s)?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Enable duress feature for this wallet?")?;
        send(&mut s, "y")?;
        s.exp_string("Enter a non duress seed password")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mynonduresspassword)?;
    }
    s.exp_string("Password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_eof()?;
    assert!(multisig_pub_path2.exists());
    let multisig_pub_path3 = temp.path().join("multisigwalletpub3.json");
    println!("---> Opening pub json multisig wallet");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "multisig-open",
        multisig_pub_path.display().to_string().as_str(),
        "-i",
        wallets[0].display().to_string().as_str(),
        "-i",
        wallets[1].display().to_string().as_str(),
        "-i",
        wallets[2].display().to_string().as_str(),
        "export-public-info",
        multisig_pub_path3.display().to_string().as_str(),
    ])?;
    for i in 0..3 {
        println!("---> Opening signer wallet {i} for multisig operation");
        s.exp_string("Have you used a keyfile when generating this wallet?")?;
        send(&mut s, "n")?;
        s.exp_string("Select one (leave the default if unsure)")?;
        dialoguer_up_enter(&mut s)?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Enable duress feature for this wallet?")?;
        send(&mut s, "y")?;
        s.exp_string("Enter a non duress seed password")?;
        send_line(&mut s, mynonduresspassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mynonduresspassword)?;
    }
    s.exp_eof()?;
    assert!(multisig_pub_path3.exists());
    let info3 = MultisigJsonWalletPublicExportV0::from_path(&multisig_pub_path3)?;
    assert_eq!(info.to_string_pretty()?, info3.to_string_pretty()?);
    Ok(())
}

#[test]
#[cfg(feature = "cli_tests")]
fn test_batch_generate_open_multisig_pub_json_descriptors() -> anyhow::Result<()> {
    use pretty_assertions::assert_eq;

    let temp = tempdir::TempDir::new("cli-batch-generate-open-multisig-pub-json-descriptors")?;
    let wallet_path_prefix = temp.path().join("mywallet");
    let mypassword = "Super11Ultra&SAASD*()";
    let mynonduresspassword = "seedpass";

    println!("---> Will generate a batch of singlesig wallets");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "singlesig-batch-generate-export",
        "--difficulty",
        "easy",
        "--enable-duress-wallet",
        "--wallets-quantity",
        "3",
        wallet_path_prefix.display().to_string().as_str(),
    ])?;
    s.exp_string("Do you want to pick one or more keyfiles?")?;
    send(&mut s, "n")?;
    s.exp_string("Continue without a keyfile?")?;
    send(&mut s, "y")?;
    s.exp_string("Password:")?;
    send_line(&mut s, mypassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, mypassword)?;
    s.exp_string("Enter a non duress seed password")?;
    send_line(&mut s, mynonduresspassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, mynonduresspassword)?;
    s.exp_string("Enter the non duress seed password again")?;
    send_line(&mut s, mynonduresspassword)?;
    s.exp_eof()?;
    // In this test we use the singlesig public json as input for the multisig creation
    let pub_json_wallets = fs::read_dir(temp.path())?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|i| {
            i.file_name().to_string_lossy().starts_with("mywallet")
                && i.file_name().to_string_lossy().ends_with("pub.json")
        })
        .map(|i| i.path())
        .collect::<Vec<_>>();
    assert_eq!(pub_json_wallets.len(), 3);
    let multisig_path = temp.path().join("multisigwallet");
    let multisig_pub_path = temp.path().join("multisigwalletpub.json");
    let keyfile1 = temp.path().join("keyfile1");
    create_file("keyfile1".as_bytes(), &keyfile1)?;
    println!("---> Will generate a multisig wallet");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "multisig-generate",
        "--difficulty",
        "easy",
        "--keyfile",
        keyfile1.display().to_string().as_str(),
        "--encrypted-wallet-output-file",
        multisig_path.display().to_string().as_str(),
        "2-of-3",
        pub_json_wallets[0].display().to_string().as_str(),
        pub_json_wallets[1].display().to_string().as_str(),
        pub_json_wallets[2].display().to_string().as_str(),
        "--json-output-file",
        multisig_pub_path.display().to_string().as_str(),
    ])?;
    let multisigpassword = "Super11Ultra!!!X";
    s.exp_string("Password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_eof()?;
    assert!(multisig_path.exists());
    assert!(multisig_pub_path.exists());
    let info = MultisigJsonWalletPublicExportV0::from_path(&multisig_pub_path)?;

    let wallets = fs::read_dir(temp.path())?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|i| {
            i.file_name().to_string_lossy().starts_with("mywallet")
                && !i.file_name().to_string_lossy().ends_with(".json")
        })
        .map(|i| i.path())
        .collect::<Vec<_>>();
    assert_eq!(wallets.len(), 3);

    let multisig_pub_path2 = temp.path().join("multisigwalletpub2.json");
    println!("---> Opening encrypted multisig wallet");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "multisig-open",
        "--difficulty",
        "easy",
        "--keyfile",
        keyfile1.display().to_string().as_str(),
        multisig_path.display().to_string().as_str(),
        "-i",
        wallets[0].display().to_string().as_str(),
        "-i",
        wallets[1].display().to_string().as_str(),
        "-i",
        wallets[2].display().to_string().as_str(),
        "export-public-info",
        multisig_pub_path2.display().to_string().as_str(),
    ])?;
    for i in 0..3 {
        println!("---> Opening signer wallet {i} for multisig operation");
        s.exp_string("Have you used a keyfile when generating this wallet?")?;
        send(&mut s, "n")?;
        s.exp_string("Select one (leave the default if unsure)")?;
        dialoguer_up_enter(&mut s)?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        // As we are using the public json, they are for the non-duress wallet (the one with an empty password)
        s.exp_string("Enable duress feature for this wallet?")?;
        send(&mut s, "n")?;
    }
    s.exp_string("Password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_string("Confirm password:")?;
    send_line(&mut s, multisigpassword)?;
    s.exp_eof()?;
    assert!(multisig_pub_path2.exists());
    let info2 = MultisigJsonWalletPublicExportV0::from_path(&multisig_pub_path2)?;
    assert_eq!(info.to_string_pretty()?, info2.to_string_pretty()?);

    let multisig_pub_path3 = temp.path().join("multisigwalletpub3.json");
    println!("---> Opening pub json multisig wallet");
    let mut s = run_cli(&[
        "--disable-internet-check",
        "--use-simple-theme",
        "multisig-open",
        multisig_pub_path.display().to_string().as_str(),
        "-i",
        wallets[0].display().to_string().as_str(),
        "-i",
        wallets[1].display().to_string().as_str(),
        "-i",
        wallets[2].display().to_string().as_str(),
        "export-public-info",
        multisig_pub_path3.display().to_string().as_str(),
    ])?;
    for i in 0..3 {
        println!("---> Opening signer wallet {i} for multisig operation");
        s.exp_string("Have you used a keyfile when generating this wallet?")?;
        send(&mut s, "n")?;
        s.exp_string("Select one (leave the default if unsure)")?;
        dialoguer_up_enter(&mut s)?;
        s.exp_string("Password:")?;
        send_line(&mut s, mypassword)?;
        s.exp_string("Confirm password:")?;
        send_line(&mut s, mypassword)?;
        // As we are using the public json, they are for the non-duress wallet (the one with an empty password)
        s.exp_string("Enable duress feature for this wallet?")?;
        send(&mut s, "n")?;
    }
    s.exp_eof()?;
    assert!(multisig_pub_path3.exists());
    let info3 = MultisigJsonWalletPublicExportV0::from_path(&multisig_pub_path3)?;
    assert_eq!(info.to_string_pretty()?, info3.to_string_pretty()?);
    Ok(())
}
