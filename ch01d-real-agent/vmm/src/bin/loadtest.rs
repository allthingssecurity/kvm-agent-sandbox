//! Load test. Run it inside the Linux VM that has /dev/kvm, from the chapter folder:
//!     ./vmm/target/aarch64-unknown-linux-musl/release/loadtest
//!
//! A. cold start: start a sandbox, the agent prints one line, the sandbox exits; one at a time
//! B. throughput: the same, with 1..32 sandboxes in flight
//! C. density: idle sandboxes kept alive until only KEEP_FREE_MB of memory is left, then all killed
//!
//! It never pushes the machine to the edge: it stops adding sandboxes while memory is still free.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VMM: &str = "./vmm/target/aarch64-unknown-linux-musl/release/vmm";
const POLICY: &str = "policies/loadtest.policy";
const KEEP_FREE_MB: u64 = 200;
const MAX_SANDBOXES: usize = 2000;

fn sandbox(args: &[&str]) -> Command {
    let mut c = Command::new(VMM);
    c.args(["--policy", POLICY, "--"]).args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

fn meminfo_mb(key: &str) -> u64 {
    std::fs::read_to_string("/proc/meminfo").unwrap().lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0) / 1024
}

fn rss_kb(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status")).ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// (busy, total) CPU ticks of the whole machine.
fn cpu_ticks() -> (u64, u64) {
    let stat = std::fs::read_to_string("/proc/stat").unwrap();
    let v: Vec<u64> = stat.lines().next().unwrap().split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    let total: u64 = v.iter().sum();
    (total - v[3] - v.get(4).copied().unwrap_or(0), total) // minus idle and iowait
}

fn pct(v: &[f64], p: f64) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[((s.len() - 1) as f64 * p).round() as usize]
}

fn main() {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("machine: {cpus} CPUs, {} MB RAM, {} MB available\n", meminfo_mb("MemTotal:"), meminfo_mb("MemAvailable:"));

    // ---------------- A. cold start, one at a time ----------------
    for _ in 0..5 { sandbox(&["hello"]).status().unwrap(); } // warm the page cache
    let mut lat = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        let status = sandbox(&["hello"]).status().unwrap();
        assert!(status.success(), "sandbox failed: {status}");
        lat.push(t.elapsed().as_secs_f64() * 1e3);
    }
    println!("A. cold start (new process + VM + load ELF + supervisor + agent prints + exit), 100 runs, one at a time");
    println!("   p50 {:.2} ms   p90 {:.2} ms   p99 {:.2} ms   max {:.2} ms\n", pct(&lat, 0.5), pct(&lat, 0.9), pct(&lat, 0.99), pct(&lat, 1.0));

    // ---------------- B. throughput ----------------
    println!("B. throughput: 256 sandboxes per row (each: start, print, exit)");
    println!("   in flight   sandboxes/s   p50 ms   p99 ms   failures");
    for in_flight in [1, 2, 4, 8, 16, 32] {
        let total = 256;
        let start = Instant::now();
        let (mut running, mut launched, mut lat, mut failures): (Vec<(Child, Instant)>, usize, Vec<f64>, usize) = (Vec::new(), 0, Vec::new(), 0);
        while lat.len() + failures < total {
            while running.len() < in_flight && launched < total {
                running.push((sandbox(&["hello"]).spawn().unwrap(), Instant::now()));
                launched += 1;
            }
            let mut i = 0;
            while i < running.len() {
                if let Some(status) = running[i].0.try_wait().unwrap() {
                    let (_, t) = running.swap_remove(i);
                    if status.success() { lat.push(t.elapsed().as_secs_f64() * 1e3) } else { failures += 1 }
                } else {
                    i += 1;
                }
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        let rate = total as f64 / start.elapsed().as_secs_f64();
        println!("   {in_flight:>9}   {rate:>11.0}   {:>6.2}   {:>6.2}   {failures:>8}", pct(&lat, 0.5), pct(&lat, 0.99));
    }

    // ---------------- C. density: idle sandboxes ----------------
    println!("\nC. density: idle sandboxes (each agent sleeps 150 s); adding 10 at a time, stopping while {KEEP_FREE_MB} MB is still free");
    println!("   alive   memory used   per sandbox   avg VMM RSS");
    let base = meminfo_mb("MemAvailable:");
    let mut kids: Vec<Child> = Vec::new();
    let started = Instant::now();
    loop {
        for _ in 0..10 { kids.push(sandbox(&["idle", "150"]).spawn().unwrap()); }
        std::thread::sleep(Duration::from_millis(300));
        let avail = meminfo_mb("MemAvailable:");
        let alive = kids.iter_mut().map(|k| k.try_wait()).filter(|r| matches!(r, Ok(None))).count();
        let n = kids.len();
        let done = avail < KEEP_FREE_MB || n >= MAX_SANDBOXES || alive < n;
        if n % 50 == 0 || done {
            let sample: Vec<u64> = kids.iter().rev().take(20).map(|k| rss_kb(k.id())).collect();
            let used = base.saturating_sub(avail);
            println!("   {alive:>5}   {used:>8} MB   {:>8.2} MB   {:>8.2} MB",
                     used as f64 / n as f64, sample.iter().sum::<u64>() as f64 / sample.len() as f64 / 1024.0);
        }
        if alive < n { println!("   (some sandboxes exited early: stopping)"); }
        if done { break; }
    }
    let n = kids.len();
    println!("   reached {n} idle sandboxes in {:.1} s", started.elapsed().as_secs_f64());
    let (b0, t0) = cpu_ticks();
    std::thread::sleep(Duration::from_secs(3));
    let (b1, t1) = cpu_ticks();
    println!("   CPU use with {n} idle sandboxes: {:.1}% of the machine (measured over 3 s)", 100.0 * (b1 - b0) as f64 / (t1 - t0).max(1) as f64);

    for k in &mut kids { let _ = k.kill(); }
    for k in &mut kids { let _ = k.wait(); }
    std::thread::sleep(Duration::from_secs(1));
    println!("   after killing them all: {} MB available again (started with {base} MB)", meminfo_mb("MemAvailable:"));
}
