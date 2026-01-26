use ephemeral_ml_host::spy::SpyProxy;
use ephemeral_ml_host::mock::MockVSockProxy;
use ephemeral_ml_host::HostProxy;
use std::fs;
use std::io::Read;

// Wrapper to satisfy orphan rules for implementing HostProxy in an integration test
struct MockProxyWrapper(MockVSockProxy);

impl HostProxy for MockProxyWrapper {
    fn forward_to_enclave(&self, _payload: &[u8]) -> ephemeral_ml_host::Result<Vec<u8>> {
        // For the test, we just return Ok
        Ok(vec![])
    }
}

#[test]
fn test_spy_proxy_intercepts_and_logs() {
    // Ensure clean state
    let log_path = "spy_intercept.log";
    if fs::metadata(log_path).is_ok() {
        fs::remove_file(log_path).ok();
    }

    // 1. Instantiate a MockVSockProxy and wrap it
    let mock_proxy = MockVSockProxy::new(1234);
    let wrapper = MockProxyWrapper(mock_proxy);
    
    // 2. Wrap it in a SpyProxy
    let spy_proxy = SpyProxy::new(wrapper);
    
    // 3. Send a "secret" payload (using non-printable bytes to prove host blindness)
    // We use a payload that is NOT printable ASCII to see the "dots" logic in action
    let secret_payload = vec![0x01, 0x02, 0x03, 0x04];
    let _ = spy_proxy.forward_to_enclave(&secret_payload).expect("Forward failed");
    
    // 4. Verify that a file spy_intercept.log is created
    assert!(fs::metadata(log_path).is_ok(), "Log file should be created");
    
    // 5. Read the log file and assert
    let mut log_content = String::new();
    let mut file = fs::File::open(log_path).expect("Failed to open log file");
    file.read_to_string(&mut log_content).expect("Failed to read log file");
    
    // Assert it contains the HEX representation
    let hex_payload: String = secret_payload.iter().map(|b| format!("{:02x}", b)).collect();
    assert!(log_content.contains(&hex_payload), "Log should contain hex payload");
    
    // Assert it DOES NOT contain the plaintext "secret" string
    assert!(!log_content.contains("secret"), "Log should not contain 'secret'");
    
    // Assert it contains dots for non-graphics
    // Check for the dots in the "Potential clear-text" line
    assert!(log_content.contains("...."), "Log should contain dots for non-printable characters");
    
    println!("Test passed! Log content:\n{}", log_content);
    
    // Cleanup
    fs::remove_file(log_path).ok();
}
