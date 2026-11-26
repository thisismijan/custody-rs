use gateway::{InMemoryNonceStore, NonceStore};

const CREATED: u64 = 1_700_000_000;

#[tokio::test]
async fn nonce_is_pruned_66_seconds_after_its_created_time() {
    let store = InMemoryNonceStore::new();
    assert!(store.record_if_new("key", "n1", CREATED, CREATED).await);
    assert!(store.contains("key", "n1"));

    store.prune(CREATED + 66);

    assert!(!store.contains("key", "n1"));
}

#[tokio::test]
async fn nonce_is_kept_30_seconds_after_its_created_time() {
    let store = InMemoryNonceStore::new();
    assert!(store.record_if_new("key", "n1", CREATED, CREATED).await);

    store.prune(CREATED + 30);

    assert!(store.contains("key", "n1"));
    assert!(
        !store
            .record_if_new("key", "n1", CREATED, CREATED + 30)
            .await
    );
}
