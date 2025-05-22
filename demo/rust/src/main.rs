use tonic::{transport::Server, Request, Response, Status};

// Include the generated proto code
pub mod pvss {
    tonic::include_proto!("pvss");
}

use pvss::{
    pvss_service_server::{PvssService, PvssServiceServer},
    PvssRequest, PvssResponse,
};

// Implement the PVSS service
#[derive(Debug, Default)]
pub struct PVSSServiceImpl {}

#[tonic::async_trait]
impl PvssService for PVSSServiceImpl {
    async fn generate_pvss(
        &self,
        request: Request<PvssRequest>,
    ) -> Result<Response<PvssResponse>, Status> {
        println!("Received PVSS request from C++ client!");
        
        // Extract the request data
        let req = request.into_inner();
        
        // Log the received data sizes
        println!("Received shares of size: {} bytes", req.shares.len());
        println!("Received committed shares of size: {} bytes", req.committed_shares.len());
        println!("Received signatures of size: {} bytes", req.signatures.len());
        
        // Here we would process the cryptographic data
        // This is just a mock implementation
        let mock_pvss_data = process_pvss_data(&req.shares, &req.committed_shares, &req.signatures);
        
        // Create and return the response
        let response = PvssResponse {
            success: true,
            error_message: "".to_string(),
            pvss_data: mock_pvss_data,
        };
        
        Ok(Response::new(response))
    }
}

// Mock function for PVSS data processing
fn process_pvss_data(shares: &[u8], committed_shares: &[u8], signatures: &[u8]) -> Vec<u8> {
    println!("Processing PVSS data...");
    // In a real implementation, this would generate actual PVSS data
    // For demo purposes, we just combine the inputs in some way
    let mut result = Vec::new();
    result.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Magic header
    result.extend_from_slice(&(shares.len() as u32).to_be_bytes());
    result.extend_from_slice(&shares[0..std::cmp::min(10, shares.len())]);
    // Combine with some data from committed shares and signatures as well
    result
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = PVSSServiceImpl::default();
    
    println!("PVSS Server listening on {}", addr);
    
    Server::builder()
        .add_service(PvssServiceServer::new(service))
        .serve(addr)
        .await?;
    
    Ok(())
} 