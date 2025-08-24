extern crate dotenvy;

use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection; // Use PgConnection
use dotenvy::dotenv;
use std::env;
use ipfs_api_backend_hyper::{IpfsClient}; // Corrected import for IpfsClient

pub mod schema;
pub mod models;
pub mod handlers;
pub mod crypto;

// Database connection pool type
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>; // Use PgConnection

// IPFS client type
pub type IpfsClientType = IpfsClient;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // create db connection pool
    let manager = ConnectionManager::<PgConnection>::new(database_url); // Use PgConnection
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    // Initialize IPFS client
    let ipfs_client = IpfsClient::default();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(ipfs_client.clone())) // Add IPFS client to app data
            .service(
                web::scope("/patients")
                    .route("", web::post().to(handlers::create_patient))
                    .route("/{patient_id}", web::get().to(handlers::get_patient))
                    .route("/{patient_id}/records", web::post().to(handlers::create_health_record))
                    .route("/{patient_id}/records", web::get().to(handlers::get_health_records_for_patient))
            )
            .route("/", web::get().to(hello)) // Keep the hello route for basic testing
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello, MediRust!")
}
