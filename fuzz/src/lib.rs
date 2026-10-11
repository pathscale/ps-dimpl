//! Deterministic, pure Rust mutation runner for the packet harnesses.
//!
//! Usage: `<target> [seed] [iterations] [corpus-file]`.
//! Re-run the same arguments to reproduce the input stream for a reported iteration.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dimpl::{Dtls, Output};

const MAX_INPUT_LEN: usize = 65536;

/// Mutate a corpus input, or generate inputs when no corpus file is supplied.
pub fn run(mut exercise: impl FnMut(&[u8])) {
    let mut args = std::env::args().skip(1);
    let seed = args
        .next()
        .map(|arg| arg.parse::<u64>().expect("seed must be a u64"))
        .unwrap_or(1);
    let iterations = args
        .next()
        .map(|arg| arg.parse::<usize>().expect("iterations must be a usize"))
        .unwrap_or(1000);
    let corpus = args
        .next()
        .map(|path| std::fs::read(path).expect("read corpus input"))
        .unwrap_or_default();
    assert!(
        args.next().is_none(),
        "usage: <target> [seed] [iterations] [corpus-file]"
    );
    assert!(
        corpus.len() <= MAX_INPUT_LEN,
        "corpus input exceeds 65536 bytes"
    );

    let iteration = Arc::new(AtomicUsize::new(0));
    let current_iteration = Arc::clone(&iteration);
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!(
            "fuzz seed={seed}, iteration={}; re-run with the same seed and corpus",
            current_iteration.load(Ordering::Relaxed)
        );
        previous_hook(info);
    }));

    let mut state = seed;
    let mut data = Vec::with_capacity(MAX_INPUT_LEN);
    for index in 0..iterations {
        iteration.store(index, Ordering::Relaxed);
        data.clear();
        data.extend_from_slice(&corpus);
        if index > 0 {
            let len = if index % 2 == 0 {
                next_random(&mut state) as usize % (MAX_INPUT_LEN + 1)
            } else {
                corpus.len()
            };
            data.truncate(len);
            while data.len() < len {
                data.push(next_random(&mut state) as u8);
            }
            if !data.is_empty() {
                let changes = 1 + next_random(&mut state) as usize % 8;
                for _ in 0..changes {
                    let offset = next_random(&mut state) as usize % data.len();
                    data[offset] ^= next_random(&mut state) as u8;
                }
            }
        }
        exercise(&data);
    }
}

/// Feed a packet and drain the mutation through Timeout.
pub fn handle_packet(dtls: &mut Dtls, packet: &[u8]) -> bool {
    let accepted = dtls.handle_packet(packet).is_ok();
    drain_outputs(dtls);
    accepted
}

/// Drain every output until the Sans-IO state machine reaches Timeout.
pub fn drain_outputs(dtls: &mut Dtls) {
    let mut buf = vec![0u8; 2048];
    loop {
        match dtls.poll_output(&mut buf) {
            Output::Timeout(_) => break,
            Output::BufferTooSmall { needed } => buf.resize(needed, 0),
            _ => {}
        }
    }
}

// This generator is only for reproducible fuzz mutations, never cryptography.
fn next_random(state: &mut u64) -> u32 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*state >> 32) as u32
}
