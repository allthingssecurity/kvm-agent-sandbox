//! The "agent": an ordinary Rust program using the standard library. Nothing here knows about the
//! supervisor. It is compiled as a normal static Linux arm64 binary and would run unchanged on Linux.

use std::collections::HashMap;
use std::time::Instant;

fn main() {
    // Test modes, to trip each limit on purpose: `vmm -- spin`, `vmm -- hog`, `vmm -- spam`.
    match std::env::args().nth(1).as_deref() {
        Some("spin") => {
            println!("agent: spinning forever (only a time limit can stop me)");
            loop { std::hint::spin_loop() }
        }
        Some("hog") => {
            println!("agent: allocating 1 MB blocks until something stops me");
            let mut blocks: Vec<Vec<u8>> = Vec::new();
            loop {
                blocks.push(vec![1u8; 1 << 20]);
                if blocks.len() % 8 == 0 { println!("agent: holding {} MB", blocks.len()); }
            }
        }
        Some("spam") => loop { println!("agent: spam spam spam spam spam spam spam spam spam spam spam spam") },
        Some("hello") => println!("agent: hello"), // the smallest useful job: start, print, exit
        Some("idle") => {
            // Sit idle for N seconds (for density tests): sleeping costs no CPU.
            let secs = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(10);
            println!("agent: idle for {secs} s");
            std::thread::sleep(std::time::Duration::from_secs(secs));
            println!("agent: done idling");
        }
        _ => normal(),
    }
}

fn normal() {
    let start = Instant::now();
    println!("agent: hello! I'm an ordinary Rust program: std, heap, files, hash maps.");

    // Heap memory (Vec): the supervisor answers brk/mmap itself.
    let numbers: Vec<u64> = (1..=200_000).collect();
    let sum: u64 = numbers.iter().sum();
    println!("agent: summed 200,000 numbers on the heap = {sum}");

    // HashMap: Rust seeds it with real randomness (getrandom), which only the host can provide.
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for word in "the quick brown fox jumps over the lazy dog and the end".split(' ') {
        *counts.entry(word).or_insert(0) += 1;
    }
    println!("agent: word counts: the={} fox={}", counts["the"], counts["fox"]);

    // A file the policy allows.
    match std::fs::read_to_string("/workspace/notes.txt") {
        Ok(text) => println!("agent: read /workspace/notes.txt ({} bytes): {}", text.len(), text.lines().next().unwrap_or("")),
        Err(e) => println!("agent: could not read notes: {e}"),
    }

    // Things the policy forbids.
    attempt("read ~/.ssh/id_rsa", std::fs::read_to_string("/home/user/.ssh/id_rsa").map(drop));
    attempt("escape with /workspace/../etc/passwd", std::fs::read_to_string("/workspace/../etc/passwd").map(drop));
    attempt("write a file into /workspace", std::fs::write("/workspace/out.txt", "hi"));
    attempt("connect to 1.1.1.1:443", std::net::TcpStream::connect("1.1.1.1:443").map(drop));
    attempt("start /bin/sh", std::process::Command::new("/bin/sh").status().map(drop));

    println!("agent: done in {:?}", start.elapsed());
}

fn attempt(what: &str, result: std::io::Result<()>) {
    match result {
        Ok(()) => println!("agent: {what}: it worked?!"),
        Err(e) => println!("agent: {what}: {e}"),
    }
}
