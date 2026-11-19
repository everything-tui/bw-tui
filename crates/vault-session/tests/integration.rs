//! Integration tests against a local Vaultwarden instance.
//!
//! Requires: `docker compose -f docker/compose.yml up -d`
//! Server: http://127.0.0.1:8080

use vault_session::{LoginDraft, LoginResult, NoteDraft, Session, SessionStatus};

const SERVER: &str = "http://127.0.0.1:8080";
const PASSWORD: &str = "TestPassword123!";

async fn server_up() -> bool {
    reqwest::get(format!("{SERVER}/alive"))
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

#[tokio::test]
async fn e2e_register_login_crud() {
    if !server_up().await {
        eprintln!("SKIP: Vaultwarden not running at {SERVER}");
        return;
    }

    let email = format!(
        "test{}@example.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let mut session = Session::new(SERVER).expect("session");

    // Register (idempotent if already exists)
    session
        .register(&email, PASSWORD, Some("Test User"))
        .await
        .expect("register");

    match session.login(&email, PASSWORD, None).await.expect("login") {
        LoginResult::Success => {}
        LoginResult::TwoFactorRequired { .. } => panic!("unexpected 2FA"),
    }
    assert_eq!(session.status(), SessionStatus::Unlocked);

    // Create folder
    let folder_id = session
        .create_folder("Personal")
        .await
        .expect("create folder");
    assert!(!folder_id.is_empty());

    // Create login
    let draft = LoginDraft {
        name: "Example Site".into(),
        username: Some("alice".into()),
        password: Some("s3cret-pass".into()),
        totp: None,
        uris: vec![vault_session::DecryptedUri {
            uri: "https://example.com".into(),
            match_type: Some(0),
        }],
        notes: Some("integration test".into()),
        folder_id: Some(folder_id.clone()),
        favorite: true,
        reprompt: false,
    };
    let item_id = session.create_login(&draft).await.expect("create login");
    assert!(!item_id.is_empty());

    // Verify decrypt
    let item = session.get_item(&item_id).expect("item present");
    assert_eq!(item.name, "Example Site");
    assert_eq!(item.username.as_deref(), Some("alice"));
    assert_eq!(item.password.as_deref(), Some("s3cret-pass"));
    assert!(item.favorite);

    // Create note
    let note_id = session
        .create_note(&NoteDraft {
            name: "Secret Note".into(),
            notes: Some("hello world".into()),
            folder_id: None,
            favorite: false,
        })
        .await
        .expect("create note");
    let note = session.get_item(&note_id).expect("note");
    assert_eq!(note.name, "Secret Note");
    assert_eq!(note.notes.as_deref(), Some("hello world"));

    // Update note
    session
        .update_note(
            &note_id,
            &NoteDraft {
                name: "Secret Note".into(),
                notes: Some("updated body".into()),
                folder_id: None,
                favorite: true,
            },
        )
        .await
        .expect("update note");
    let note = session.get_item(&note_id).expect("note");
    assert_eq!(note.notes.as_deref(), Some("updated body"));
    assert!(note.favorite);

    // Update login
    let mut updated = draft.clone();
    updated.password = Some("new-password".into());
    session
        .update_login(&item_id, &updated)
        .await
        .expect("update");
    assert_eq!(
        session.get_item(&item_id).unwrap().password.as_deref(),
        Some("new-password")
    );

    // Soft delete + restore
    session.soft_delete(&item_id).await.expect("soft delete");
    assert!(session.get_item(&item_id).unwrap().deleted);
    session.restore(&item_id).await.expect("restore");
    assert!(!session.get_item(&item_id).unwrap().deleted);

    // Lock / unlock
    session.lock();
    assert_eq!(session.status(), SessionStatus::Locked);
    session.unlock(PASSWORD).await.expect("unlock");
    assert_eq!(session.status(), SessionStatus::Unlocked);
    assert!(session.get_item(&item_id).is_some());

    // Cleanup
    session.hard_delete(&item_id).await.expect("hard delete");
    session
        .hard_delete(&note_id)
        .await
        .expect("hard delete note");
    session
        .delete_folder(&folder_id)
        .await
        .expect("delete folder");
}
