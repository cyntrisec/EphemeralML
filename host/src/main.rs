use ephemeral_ml_host::{mock::MockVSockProxy, VSockProxy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralNet Host Proxy (Mock Mode)");
    
    // Create mock proxy
    let mut proxy = MockVSockProxy::new(8081);
    
    // Test weight storage
    // weights are now treated as encrypted blobs (Vec<u8>) in the proxy
    let test_weights: Vec<f32> = (0..100).map(|i| i as f32 * 0.01).collect();
    // In a real scenario these would be encrypted bytes. For the mock we just cast to bytes.
    let test_weights_bytes: Vec<u8> = test_weights.iter().flat_map(|x| x.to_be_bytes().to_vec()).collect();
    
    proxy.store_weights("test_model", &test_weights_bytes)?;
    println!("Stored {} bytes of weights for test_model", test_weights_bytes.len());
    
    // Test weight retrieval
    let retrieved_weights_bytes = proxy.retrieve_weights("test_model")?;
    println!("Retrieved {} bytes of weights for test_model", retrieved_weights_bytes.len());
    
    // Test payload forwarding (this would normally connect to enclave)
    println!("Mock proxy demo completed");
    println!("To test full communication, start the enclave server first");
    
    Ok(())
}