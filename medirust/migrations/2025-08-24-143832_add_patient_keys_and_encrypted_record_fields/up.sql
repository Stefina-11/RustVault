ALTER TABLE patients
ADD COLUMN public_key_pem TEXT NOT NULL DEFAULT '';

ALTER TABLE health_records
ADD COLUMN encrypted_aes_key TEXT NOT NULL DEFAULT '';

ALTER TABLE health_records
ADD COLUMN nonce TEXT NOT NULL DEFAULT '';
