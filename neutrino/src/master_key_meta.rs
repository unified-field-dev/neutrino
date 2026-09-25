//! Best-effort write of [`NeutrinoMasterKeyMeta`] provenance (no key material).

use chrono::Utc;
use valence::Model;
use valence::Valence;

use crate::generated::{NeutrinoMasterKeyMeta, NeutrinoMasterKeyMetaSource};
use crate::key_source::MasterKeyProvenance;

const META_ID: &str = "current";

/// Upsert master-key provenance when the resolved source is KMS (SYSTEM_ONLY table).
///
/// Failures are logged and ignored so seal/reveal is not blocked by meta storage.
pub async fn ensure_master_key_meta(valence: &Valence, provenance: &MasterKeyProvenance) {
    let MasterKeyProvenance::Kms { key_id } = provenance else {
        return;
    };
    let row = match NeutrinoMasterKeyMeta::new(
        key_id.clone(),
        NeutrinoMasterKeyMetaSource::Kms,
        serde_json::json!({}),
        Utc::now(),
    ) {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                target: "neutrino.master_key.resolve",
                "master key meta build failed: {e}"
            );
            return;
        }
    };
    if let Err(e) = NeutrinoMasterKeyMeta::upsert_used(
        META_ID,
        row,
        valence,
        valence::use_!(r"When the vault **records how the process master key was obtained**, we store only **non-secret provenance** (env vs KMS and an opaque key id) so operators can audit key source without exposing key material."),
    )
    .await
    {
        log::warn!(
            target: "neutrino.master_key.resolve",
            "master key meta upsert failed: {e}"
        );
    }
}
