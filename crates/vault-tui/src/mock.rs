//! Sample decrypted vault data for the TUI `--mock` demo.

use vault_session::DecryptedUri;

use crate::models::{DecryptedItem, FolderView, ItemType};

/// Recount folder item totals for the mock vault.
pub fn with_folder_counts(mut folders: Vec<FolderView>, items: &[DecryptedItem]) -> Vec<FolderView> {
    for folder in folders.iter_mut() {
        let Some(id) = folder.id.as_ref() else {
            folder.count = 0;
            continue;
        };
        folder.count = items
            .iter()
            .filter(|i| !i.deleted && i.folder_id.as_ref() == Some(id))
            .count();
    }
    folders
}

/// Deterministic sample folders.
pub fn sample_folders() -> Vec<FolderView> {
    vec![
        FolderView {
            id: Some("11111111-1111-1111-1111-111111111111".into()),
            name: "Personal".into(),
            count: 0,
        },
        FolderView {
            id: Some("22222222-2222-2222-2222-222222222222".into()),
            name: "Work".into(),
            count: 0,
        },
        FolderView {
            id: Some("33333333-3333-3333-3333-333333333333".into()),
            name: "Finance".into(),
            count: 0,
        },
    ]
}

fn shell(
    id: &str,
    name: &str,
    item_type: ItemType,
    folder_id: Option<String>,
) -> DecryptedItem {
    DecryptedItem {
        id: id.into(),
        name: name.into(),
        item_type,
        folder_id,
        ..Default::default()
    }
}

/// Deterministic sample decrypted items.
pub fn sample_items() -> Vec<DecryptedItem> {
    let personal = "11111111-1111-1111-1111-111111111111".to_string();
    let work = "22222222-2222-2222-2222-222222222222".to_string();
    let finance = "33333333-3333-3333-3333-333333333333".to_string();

    let mut github = shell(
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "GitHub",
        ItemType::Login,
        Some(work.clone()),
    );
    github.favorite = true;
    github.username = Some("octocat".into());
    github.password = Some("gh-demo-password-9x!".into());
    github.totp = Some("JBSWY3DPEHPK3PXP".into());
    github.uris = vec![DecryptedUri {
        uri: "https://github.com/login".into(),
        match_type: None,
    }];
    github.notes = Some("Work GitHub account".into());
    github.reprompt = true;

    let mut gmail = shell(
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "Gmail",
        ItemType::Login,
        Some(personal.clone()),
    );
    gmail.favorite = true;
    gmail.username = Some("demo@example.com".into());
    gmail.password = Some("mail-s3cret!".into());
    gmail.uris = vec![DecryptedUri {
        uri: "https://mail.google.com".into(),
        match_type: None,
    }];

    let mut vw = shell(
        "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "Vaultwarden Admin",
        ItemType::Login,
        Some(work.clone()),
    );
    vw.username = Some("admin".into());
    vw.password = Some("vw-admin-local".into());
    vw.totp = Some("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".into());
    vw.uris = vec![DecryptedUri {
        uri: "https://vault.example.com".into(),
        match_type: None,
    }];
    vw.notes = Some("Self-hosted instance".into());

    let mut wifi = shell(
        "dddddddd-dddd-dddd-dddd-dddddddddddd",
        "Wi-Fi Home",
        ItemType::Login,
        Some(personal.clone()),
    );
    wifi.username = Some("HomeNet".into());
    wifi.password = Some("router-passphrase".into());
    wifi.notes = Some("Living room AP".into());

    let mut aws = shell(
        "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        "AWS Root",
        ItemType::Login,
        Some(work.clone()),
    );
    aws.username = Some("root@aws.example".into());
    aws.password = Some("aws-root-never-use".into());
    aws.totp = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    aws.uris = vec![DecryptedUri {
        uri: "https://console.aws.amazon.com".into(),
        match_type: None,
    }];
    aws.notes = Some("Break-glass only".into());
    aws.reprompt = true;

    let mut bank = shell(
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "Bank Login",
        ItemType::Login,
        Some(finance.clone()),
    );
    bank.favorite = true;
    bank.username = Some("cust-10042".into());
    bank.password = Some("bank-demo-pw".into());
    bank.uris = vec![DecryptedUri {
        uri: "https://online.bank.example".into(),
        match_type: None,
    }];

    let mut visa = shell(
        "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1",
        "Visa ••4242",
        ItemType::Card,
        Some(finance),
    );
    visa.card_number = Some("4111111111114242".into());
    visa.card_brand = Some("Visa".into());
    visa.cardholder_name = Some("Alex Example".into());
    visa.card_exp_month = Some("12".into());
    visa.card_exp_year = Some("2030".into());
    visa.card_code = Some("123".into());
    visa.notes = Some("Personal debit".into());

    let mut passport = shell(
        "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2",
        "Passport details",
        ItemType::Identity,
        Some(personal.clone()),
    );
    passport.identity_name = Some("Alex Example".into());
    passport.identity_first_name = Some("Alex".into());
    passport.identity_last_name = Some("Example".into());
    passport.identity_passport_number = Some("X1234567".into());
    passport.identity_address1 = Some("1 Demo Street".into());
    passport.identity_city = Some("Berlin".into());
    passport.identity_country = Some("DE".into());
    passport.notes = Some("Travel docs".into());

    let mut note = shell(
        "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3",
        "Server recovery codes",
        ItemType::SecureNote,
        Some(work),
    );
    note.notes = Some("aaaa-bbbb\ncccc-dddd\neeee-ffff".into());

    let mut ssh = shell(
        "d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4",
        "deploy@prod",
        ItemType::SshKey,
        Some(personal.clone()),
    );
    ssh.ssh_public_key = Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoKey demo@host".into());
    ssh.ssh_fingerprint = Some("SHA256:demoFingerprint=======".into());
    ssh.ssh_private_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----\ndemo\n-----END OPENSSH PRIVATE KEY-----".into());

    let mut trash = shell(
        "e5e5e5e5-e5e5-e5e5-e5e5-e5e5e5e5e5e5",
        "Old forum",
        ItemType::Login,
        Some(personal),
    );
    trash.deleted = true;
    trash.username = Some("olduser".into());
    trash.password = Some("old-pass".into());

    vec![
        github, gmail, vw, wifi, aws, bank, visa, passport, note, ssh, trash,
    ]
}
