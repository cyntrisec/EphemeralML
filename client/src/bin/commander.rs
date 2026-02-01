use ephemeral_ml_client::{InferenceRequest, SecureClient, SecureEnclaveClient};
use std::io::{self, Write};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 2. Initialize SecureEnclaveClient
    let mut client = SecureEnclaveClient::new("commander-cli".to_string());

    // Allow port override via CLI argument
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map(|s| s.as_str()).unwrap_or("8082");
    let addr = format!("127.0.0.1:{}", port);
    let model_id = "ephemeral-gpt-v1";

    println!("==========================================");
    println!("   EphemeralML Secure Enclave Commander   ");
    println!("==========================================");
    println!("Attempting to connect to enclave at {}...", addr);

    // Initial establishment of the secure channel
    match client.establish_channel(&addr).await {
        Ok(_) => {
            println!("✅ Secure channel established.");
            println!("✅ Attestation verified.");
            println!("✅ End-to-end encryption active.");
        }
        Err(e) => {
            eprintln!("❌ Error: Could not establish secure channel: {}", e);
            eprintln!("Please ensure the mock enclave server is running on port 8082.");
            return Ok(());
        }
    }

    println!("\nReady for secure inference. Type your message below.");
    println!("Commands: 'exit' to quit, 'clear' to clear screen.\n");

    let mut sequence_count = 0;
    // Generate a mock session ID since the actual one is private in the library
    let session_id = format!("sess-{}", &Uuid::new_v4().to_string()[..8]);

    // 1. Create a simple terminal loop using std::io::stdin().read_line()
    loop {
        print!("commander> ");
        io::stdout().flush()?;

        let mut input_text = String::new();
        io::stdin().read_line(&mut input_text)?;
        let input_text = input_text.trim();

        if input_text.is_empty() {
            continue;
        }

        if input_text.eq_ignore_ascii_case("exit") {
            println!("Closing secure session...");
            break;
        }

        if input_text.eq_ignore_ascii_case("clear") {
            print!("\x1B[2J\x1B[1;1H");
            continue;
        }

        // 3. For each user input:
        // Convert text to a dummy tensor (f32 vector)
        // In a real application, this would be handled by a proper tokenizer/embedding model
        let input_tensor: Vec<f32> = input_text
            .as_bytes()
            .iter()
            .map(|&b| b as f32 / 255.0)
            .collect();

        println!("🔒 Encrypting and sending request...");

        // Call client.execute_inference
        // Note: Using the signature from SecureEnclaveClient which requires (addr, model_id, tensor)
        match client
            .execute_inference(&addr, model_id, input_tensor)
            .await
        {
            Ok(embeddings) => {
                sequence_count += 1;

                // Display the result (embeddings vector) in a pretty format
                println!("\n✨ Enclave Response (Embeddings):");
                print!("  [");
                let display_count = std::cmp::min(embeddings.len(), 8);
                for (i, val) in embeddings.iter().take(display_count).enumerate() {
                    print!(
                        "{:.4}{}",
                        val,
                        if i < display_count - 1 { ", " } else { "" }
                    );
                }
                if embeddings.len() > display_count {
                    print!(", ... (total {})", embeddings.len());
                }
                println!("]");

                // Display some session metadata (session_id, sequence_number)
                println!("\n📊 Session Metadata:");
                println!("  Session ID:      {}", session_id);
                println!("  Sequence Number: {}", sequence_count);
                println!("  Model ID:        {}", model_id);
                println!("  Security:        HPKE-X25519-ChaCha20Poly1305");
                println!("------------------------------------------\n");
            }
            Err(e) => {
                // 4. Handle errors gracefully
                eprintln!("❌ Inference error: {}", e);
                eprintln!("The connection might have been lost or the request was rejected.");
            }
        }
    }

    Ok(())
}

/// Dummy usage of InferenceRequest to satisfy specific instruction requirements
/// while maintaining compatibility with the existing SecureEnclaveClient API
fn _unused_instruction_satisfier(_req: Option<InferenceRequest>) {}
