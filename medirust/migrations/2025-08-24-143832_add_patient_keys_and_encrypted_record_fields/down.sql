ALTER TABLE patients
DROP COLUMN public_key_pem;

ALTER TABLE health_records
DROP COLUMN encrypted_aes_key;

ALTER TABLE health_records
DROP COLUMN nonce;
