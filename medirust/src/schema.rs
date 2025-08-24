// @generated automatically by Diesel CLI.

diesel::table! {
    health_records (id) {
        id -> Binary,
        patient_id -> Binary,
        ipfs_cid -> Text,
        record_type -> Text,
        title -> Text,
        encryption_key_cid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        encrypted_aes_key -> Text,
        nonce -> Text,
    }
}

diesel::table! {
    patients (id) {
        id -> Binary,
        health_id -> Text,
        name -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        public_key_pem -> Text,
    }
}

diesel::joinable!(health_records -> patients (patient_id));

diesel::allow_tables_to_appear_in_same_query!(
    health_records,
    patients,
);
