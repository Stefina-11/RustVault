use actix_web::{web, HttpResponse, Responder};
use diesel::prelude::*;
use uuid::Uuid;
use anyhow::Result;
use futures::{StreamExt, TryStreamExt}; // Import TryStreamExt
use serde_json::json;
use ipfs_api_backend_hyper::IpfsApi;

use crate::models::{Patient, NewPatient, HealthRecord, NewHealthRecord};
use crate::schema::{patients, health_records};
use crate::{DbPool, IpfsClientType};
use crate::crypto::CryptoUtils;

// Handler to create a new patient
pub async fn create_patient(
    pool: web::Data<DbPool>,
    new_patient_data: web::Json<NewPatient>,
) -> impl Responder {
    let mut conn = pool.get().expect("couldn't get db connection from pool");

    let patient_data = new_patient_data.into_inner();

    // Generate RSA key pair for the patient
    let (_private_key, public_key) = match CryptoUtils::generate_rsa_key_pair() {
        Ok(keys) => keys,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error generating RSA key pair: {:?}", e)),
    };

    // Export public key to PEM format
    let public_key_pem = match CryptoUtils::export_public_key_to_pem(&public_key) {
        Ok(pem) => pem,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error exporting public key: {:?}", e)),
    };

    let new_patient = patient_data.to_patient(public_key_pem);
    let patient_to_return = new_patient.clone(); // Clone for the response

    match web::block(move || {
        diesel::insert_into(patients::table)
            .values(&new_patient)
            .execute(&mut conn)
    })
    .await
    {
        Ok(Ok(_)) => HttpResponse::Created().json(patient_to_return),
        Ok(Err(e)) => HttpResponse::InternalServerError().body(format!("Error creating patient: {:?}", e)),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    }
}

// Handler to get a patient by ID
pub async fn get_patient(
    pool: web::Data<DbPool>,
    patient_id: web::Path<String>,
) -> impl Responder {
    let _conn = pool.get().expect("couldn't get db connection from pool");
    let patient_uuid = Uuid::parse_str(&patient_id).expect("Invalid UUID format");
    let patient_id_bytes = patient_uuid.as_bytes().to_vec();

    match web::block(move || {
        let mut conn_for_query = pool.get().expect("couldn't get db connection from pool");
        patients::table
            .filter(patients::id.eq(patient_id_bytes.clone()))
            .select(Patient::as_select())
            .first(&mut conn_for_query)
    })
    .await
    {
        Ok(Ok(patient)) => HttpResponse::Ok().json(patient),
        Ok(Err(diesel::NotFound)) => HttpResponse::NotFound().body("Patient not found"),
        Ok(Err(e)) => HttpResponse::InternalServerError().body(format!("Error getting patient: {:?}", e)),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    }
}

// Handler to create a new health record for a patient
pub async fn create_health_record(
    pool: web::Data<DbPool>,
    ipfs_client: web::Data<IpfsClientType>,
    new_health_record_data: web::Json<NewHealthRecord>,
) -> impl Responder {
    let mut conn = pool.get().expect("couldn't get db connection from pool");
    let record_data = new_health_record_data.into_inner();

    // 1. Retrieve patient's public key
    let patient_id_bytes = record_data.patient_id.clone();
    let patient = match web::block(move || {
        let mut conn_for_query = pool.get().expect("couldn't get db connection from pool");
        patients::table
            .filter(patients::id.eq(patient_id_bytes))
            .select(Patient::as_select())
            .first(&mut conn_for_query)
    })
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(diesel::NotFound)) => return HttpResponse::NotFound().body("Patient not found"),
        Ok(Err(e)) => return HttpResponse::InternalServerError().body(format!("Error getting patient: {:?}", e)),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    };

    let public_key = match CryptoUtils::import_public_key_from_pem(&patient.public_key_pem) {
        Ok(key) => key,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error importing public key: {:?}", e)),
    };

    // 2. Encrypt health record content using AES-GCM
    let aes_key = CryptoUtils::generate_aes_key();
    let (encrypted_content, nonce) = match CryptoUtils::encrypt_data(record_data.content.as_bytes(), &aes_key) {
        Ok(data) => data,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error encrypting data: {:?}", e)),
    };

    // 3. Upload encrypted content to IPFS
    let ipfs_cid = match ipfs_client.add(std::io::Cursor::new(encrypted_content)).await {
        Ok(res) => res.hash,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error uploading to IPFS: {:?}", e)),
    };

    // 4. Encrypt the AES key using the patient's RSA public key
    let encrypted_aes_key = match CryptoUtils::encrypt_aes_key_with_rsa(&aes_key, &public_key) {
        Ok(key) => CryptoUtils::encode_base64(&key),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error encrypting AES key: {:?}", e)),
    };

    // 5. Store IPFS CID, encrypted AES key, and nonce in the database
    let new_health_record = record_data.to_health_record(
        ipfs_cid,
        encrypted_aes_key,
        CryptoUtils::encode_base64(&nonce),
    );
    let health_record_to_return = new_health_record.clone(); // Clone for the response

    match web::block(move || {
        diesel::insert_into(health_records::table)
            .values(&new_health_record)
            .execute(&mut conn)
    })
    .await
    {
        Ok(Ok(_)) => HttpResponse::Created().json(health_record_to_return),
        Ok(Err(e)) => HttpResponse::InternalServerError().body(format!("Error creating health record: {:?}", e)),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    }
}

// Handler to get all health records for a specific patient
pub async fn get_health_records_for_patient(
    pool: web::Data<DbPool>,
    ipfs_client: web::Data<IpfsClientType>,
    patient_id: web::Path<String>,
) -> impl Responder {
    let _conn = pool.get().expect("couldn't get db connection from pool");
    let patient_uuid = Uuid::parse_str(&patient_id).expect("Invalid UUID format");
    let patient_id_bytes = patient_uuid.as_bytes().to_vec();
    let patient_id_bytes_clone_for_patient_query = patient_id_bytes.clone();
    let patient_id_bytes_clone_for_records_query = patient_id_bytes.clone();
    let pool_clone_for_patient_query = pool.clone(); // Clone pool for the first block

    // Retrieve patient to get their public key
    let _patient = match web::block(move || {
        let mut conn_for_query = pool_clone_for_patient_query.get().expect("couldn't get db connection from pool");
        patients::table
            .filter(patients::id.eq(patient_id_bytes_clone_for_patient_query))
            .select(Patient::as_select())
            .first(&mut conn_for_query)
    })
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(diesel::NotFound)) => return HttpResponse::NotFound().body("Patient not found"),
        Ok(Err(e)) => return HttpResponse::InternalServerError().body(format!("Error getting patient: {:?}", e)),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    };

    // For demonstration, we'll assume the private key is available.
    // In a real decentralized system, the patient's client would hold and use the private key.
    let (private_key, _) = match CryptoUtils::generate_rsa_key_pair() { // This is a placeholder!
        Ok(keys) => keys,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error generating dummy RSA key pair: {:?}", e)),
    };

    let records = match web::block(move || {
        let mut conn_for_query = pool.get().expect("couldn't get db connection from pool");
        health_records::table
            .filter(health_records::patient_id.eq(patient_id_bytes_clone_for_records_query))
            .select(HealthRecord::as_select())
            .load(&mut conn_for_query)
    })
    .await
    {
        Ok(Ok(recs)) => recs,
        Ok(Err(e)) => return HttpResponse::InternalServerError().body(format!("Error getting health records: {:?}", e)),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    };

    let mut decrypted_records = Vec::new();
    for record in records {
        // Retrieve encrypted content from IPFS
        let encrypted_content_bytes = match ipfs_client.cat(&record.ipfs_cid).map_ok(|chunk| chunk.to_vec()).collect::<Vec<Result<Vec<u8>, _>>>().await {
            chunks if chunks.iter().all(Result::is_ok) => chunks.into_iter().filter_map(Result::ok).flatten().collect::<Vec<u8>>(),
            _ => return HttpResponse::InternalServerError().body(format!("Error retrieving encrypted content from IPFS for CID: {}", record.ipfs_cid)),
        };

        // Decode encrypted AES key and nonce from base64
        let decoded_encrypted_aes_key = match CryptoUtils::decode_base64(&record.encrypted_aes_key) {
            Ok(key) => key,
            Err(e) => return HttpResponse::InternalServerError().body(format!("Error decoding encrypted AES key: {:?}", e)),
        };
        let decoded_nonce = match CryptoUtils::decode_base64(&record.nonce) {
            Ok(nonce) => nonce,
            Err(e) => return HttpResponse::InternalServerError().body(format!("Error decoding nonce: {:?}", e)),
        };

        // Decrypt AES key with RSA private key
        let decrypted_aes_key = match CryptoUtils::decrypt_aes_key_with_rsa(&decoded_encrypted_aes_key, &private_key) {
            Ok(key) => key,
            Err(e) => return HttpResponse::InternalServerError().body(format!("Error decrypting AES key: {:?}", e)),
        };

        // Decrypt health record content with AES key and nonce
        let decrypted_content_bytes = match CryptoUtils::decrypt_data(&encrypted_content_bytes, &decrypted_aes_key, &decoded_nonce) {
            Ok(content) => content,
            Err(e) => return HttpResponse::InternalServerError().body(format!("Error decrypting health record content: {:?}", e)),
        };

        let decrypted_content = String::from_utf8(decrypted_content_bytes)
            .unwrap_or_else(|_| "Could not decode UTF-8".to_string());

        // For now, we'll just return the decrypted content as part of the record.
        // In a real app, you might want a dedicated DTO for this.
        decrypted_records.push(json!({
            "id": Uuid::from_slice(&record.id).unwrap().to_string(),
            "patient_id": Uuid::from_slice(&record.patient_id).unwrap().to_string(),
            "ipfs_cid": record.ipfs_cid,
            "record_type": record.record_type,
            "title": record.title,
            "content": decrypted_content, // Decrypted content
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }));
    }

    HttpResponse::Ok().json(decrypted_records)
}

// Handler to get a single health record by ID and decrypt its content
pub async fn get_health_record_by_id(
    pool: web::Data<DbPool>,
    ipfs_client: web::Data<IpfsClientType>,
    record_id: web::Path<String>,
) -> impl Responder {
    let _conn = pool.get().expect("couldn't get db connection from pool");
    let record_uuid = Uuid::parse_str(&record_id).expect("Invalid UUID format");
    let record_id_bytes = record_uuid.as_bytes().to_vec();
    let pool_clone_for_record_query = pool.clone(); // Clone pool for the first block

    let record = match web::block(move || {
        let mut conn_for_query = pool_clone_for_record_query.get().expect("couldn't get db connection from pool");
        health_records::table
            .filter(health_records::id.eq(record_id_bytes.clone()))
            .select(HealthRecord::as_select())
            .first(&mut conn_for_query)
    })
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(diesel::NotFound)) => return HttpResponse::NotFound().body("Health record not found"),
        Ok(Err(e)) => return HttpResponse::InternalServerError().body(format!("Error getting health record: {:?}", e)),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    };

    // Retrieve patient to get their public key (for private key assumption)
    let patient_id_bytes = record.patient_id.clone();
    let pool_clone_for_patient_query = pool.clone(); // Clone pool for this block
    let _patient = match web::block(move || {
        let mut conn_for_query = pool_clone_for_patient_query.get().expect("couldn't get db connection from pool");
        patients::table
            .filter(patients::id.eq(patient_id_bytes))
            .select(Patient::as_select())
            .first(&mut conn_for_query)
    })
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(diesel::NotFound)) => return HttpResponse::NotFound().body("Patient not found for record"),
        Ok(Err(e)) => return HttpResponse::InternalServerError().body(format!("Error getting patient for record: {:?}", e)),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error blocking thread: {:?}", e)),
    };

    // For demonstration, we'll assume the private key is available.
    let (private_key, _) = match CryptoUtils::generate_rsa_key_pair() { // This is a placeholder!
        Ok(keys) => keys,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error generating dummy RSA key pair: {:?}", e)),
    };

    // Retrieve encrypted content from IPFS
    let encrypted_content_bytes = match ipfs_client.cat(&record.ipfs_cid).map_ok(|chunk| chunk.to_vec()).collect::<Vec<Result<Vec<u8>, _>>>().await {
        chunks if chunks.iter().all(Result::is_ok) => chunks.into_iter().filter_map(Result::ok).flatten().collect::<Vec<u8>>(),
        _ => return HttpResponse::InternalServerError().body(format!("Error retrieving encrypted content from IPFS for CID: {}", record.ipfs_cid)),
    };

    // Decode encrypted AES key and nonce from base64
    let decoded_encrypted_aes_key = match CryptoUtils::decode_base64(&record.encrypted_aes_key) {
        Ok(key) => key,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error decoding encrypted AES key: {:?}", e)),
    };
    let decoded_nonce = match CryptoUtils::decode_base64(&record.nonce) {
        Ok(nonce) => nonce,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error decoding nonce: {:?}", e)),
    };

    // Decrypt AES key with RSA private key
    let decrypted_aes_key = match CryptoUtils::decrypt_aes_key_with_rsa(&decoded_encrypted_aes_key, &private_key) {
        Ok(key) => key,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error decrypting AES key: {:?}", e)),
    };

    // Decrypt health record content with AES key and nonce
    let decrypted_content_bytes = match CryptoUtils::decrypt_data(&encrypted_content_bytes, &decrypted_aes_key, &decoded_nonce) {
        Ok(content) => content,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error decrypting health record content: {:?}", e)),
    };

    let decrypted_content = String::from_utf8(decrypted_content_bytes)
        .unwrap_or_else(|_| "Could not decode UTF-8".to_string());

    HttpResponse::Ok().json(json!({
        "id": Uuid::from_slice(&record.id).unwrap().to_string(),
        "patient_id": Uuid::from_slice(&record.patient_id).unwrap().to_string(),

        "ipfs_cid": record.ipfs_cid,
        "record_type": record.record_type,
        "title": record.title,
        "content": decrypted_content, // Decrypted content
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }))
}
