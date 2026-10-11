//! Fuzz target for DTLS packet handling.
//!
//! This target exercises the main packet processing path in the DTLS engine.
//! It creates a DTLS instance and feeds it arbitrary byte sequences to find
//! parsing bugs, panics, or other issues in packet handling.

use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, certificate};
use dimpl_fuzz::{drain_outputs, handle_packet, run};

fn main() {
    run(exercise);
}

fn exercise(data: &[u8]) {
    // Generate a certificate once for the test instance
    let cert = match certificate::generate_self_signed_certificate() {
        Ok(c) => c,
        Err(_) => return, // Skip if certificate generation fails
    };

    let config = Arc::new(Config::default());
    let now = Instant::now();

    // Test as server (default mode)
    // Servers can receive packets immediately
    {
        let mut dtls = Dtls::new_12(Arc::clone(&config), cert.clone(), now);
        // Ignore errors - we're looking for panics, not handling errors
        handle_packet(&mut dtls, data);
    }

    // Test as client
    // Clients need handle_timeout called first to initialize
    {
        let mut dtls = Dtls::new_12(Arc::clone(&config), cert, now);
        dtls.set_active(true); // Switch to client mode

        // Initialize the client by calling handle_timeout to set up the random and other state
        let initialized = dtls.handle_timeout(now).is_ok();
        drain_outputs(&mut dtls);
        if !initialized {
            return;
        }

        handle_packet(&mut dtls, data);
    }
}
