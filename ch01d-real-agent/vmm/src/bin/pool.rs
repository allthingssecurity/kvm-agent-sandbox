//! A warm pool. Keep N sandboxes made ahead of time (VM created, program loaded, pages mapped, jail
//! on), hand one out per call, and make a replacement in the background. Every call still gets a
//! fresh VM that nobody used before; only the waiting has moved off the call's path.
//!
//! Run inside the Linux VM, from the chapter folder:
//!     ./vmm/target/aarch64-unknown-linux-musl/release/pool [--size N] [--calls M] PROGRAM -- ARGS...
//! It measures the same call four ways: a plain process, a fresh namespace sandbox (bwrap), a cold
//! VM (`vmm`, everything at call time) and a warm VM from the pool.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VMM: &str = "./vmm/target/aarch64-unknown-linux-musl/release/vmm";
const POLICY: &str = "policies/default.policy";

/// Start a warm sandbox and wait until it says it's ready (one byte).
fn warm_sandbox(program: &str) -> Child {
    let mut child = Command::new(VMM)
        .args(["--warm", "--policy", POLICY, program])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().expect("start vmm");
    let mut ready = [0u8; 1];
    child.stdout.as_mut().unwrap().read_exact(&mut ready).expect("warm sandbox died before it was ready");
    assert_eq!(ready[0], 0x06, "unexpected first byte from a warm sandbox");
    child
}

/// One call: send the arguments, read the output to the end, collect the exit code.
fn call_warm(mut child: Child, args: &[String]) -> (Vec<u8>, i32) {
    let body = args.join("\0");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
        stdin.write_all(body.as_bytes()).unwrap();
    }
    let mut out = Vec::new();
    child.stdout.as_mut().unwrap().read_to_end(&mut out).unwrap();
    let code = child.wait().unwrap().code().unwrap_or(-1);
    (out, code)
}

fn call_process(cmd: &[String]) -> (Vec<u8>, i32) {
    let o = Command::new(&cmd[0]).args(&cmd[1..]).stderr(Stdio::null()).output().unwrap();
    (o.stdout, o.status.code().unwrap_or(-1))
}

/// Keep `size` warm sandboxes ready, made by `makers` background threads. A maker builds a new
/// sandbox only when it gets a token: one per free slot at the start, then one after each call has
/// finished, so building replacements never competes with a running call for the CPUs.
fn start_pool(size: usize, makers: usize, program: &str) -> (Receiver<Child>, Sender<()>) {
    let (tx, rx) = sync_channel::<Child>(size);
    let (token_tx, token_rx) = channel::<()>();
    let token_rx = Arc::new(Mutex::new(token_rx));
    for _ in 0..size { token_tx.send(()).unwrap(); }
    for _ in 0..makers {
        let (tx, program, tokens) = (tx.clone(), program.to_string(), token_rx.clone());
        std::thread::spawn(move || loop {
            if tokens.lock().unwrap().recv().is_err() { return; }
            if tx.send(warm_sandbox(&program)).is_err() { return; }
        });
    }
    (rx, token_tx)
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (mut size, mut calls, mut i) = (4usize, 200usize, 0);
    while i < argv.len() && argv[i].starts_with("--") {
        match argv[i].as_str() {
            "--size" => { size = argv[i + 1].parse().unwrap(); i += 2; }
            "--calls" => { calls = argv[i + 1].parse().unwrap(); i += 2; }
            other => panic!("unknown option {other}"),
        }
    }
    let program = argv[i].clone();
    let args: Vec<String> = argv[i + 2..].to_vec(); // after "--"
    let name = std::path::Path::new(&program).file_name().unwrap().to_string_lossy().into_owned();
    println!("call: {name} {}   ({calls} calls per row; median / p99 in ms, measured by the caller)\n", args.join(" "));

    let mut native = vec![program.clone()];
    native.extend(args.iter().cloned());
    let workspace = std::fs::canonicalize("workspace").unwrap().to_string_lossy().into_owned();
    let mut bwrap: Vec<String> = ["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc",
        "/proc", "--tmpfs", "/tmp", "--bind", &workspace, "/workspace"].iter().map(|s| s.to_string()).collect();
    bwrap.extend(native.iter().cloned());
    let mut cold = vec![VMM.to_string(), "--policy".into(), POLICY.into(), program.clone(), "--".into()];
    cold.extend(args.iter().cloned());

    let measure = |label: &str, f: &mut dyn FnMut() -> (Vec<u8>, i32), gap: Duration| {
        for _ in 0..5 { f(); }
        let mut lat = Vec::new();
        let mut failures = 0;
        let t = Instant::now();
        for _ in 0..calls {
            std::thread::sleep(gap);
            let start = Instant::now();
            let (_, code) = f();
            lat.push(start.elapsed().as_secs_f64() * 1e3);
            if code != 0 { failures += 1; }
        }
        let wall = t.elapsed().as_secs_f64() - gap.as_secs_f64() * calls as f64;
        println!("  {label:<44} {:>6.2} / {:>6.2}   {:>5.0} calls/s{}", pct(&mut lat, 0.5), pct(&mut lat, 0.99),
                 calls as f64 / wall, if failures > 0 { format!("   {failures} FAILED") } else { String::new() });
    };

    println!("  {:<44} {:>15}   {:>11}", "", "median / p99", "throughput");
    measure("plain process (no isolation)", &mut || call_process(&native), Duration::ZERO);
    measure("fresh namespace sandbox (bwrap)", &mut || call_process(&bwrap), Duration::ZERO);
    measure("cold VM (vmm: all set-up at call time)", &mut || call_process(&cold), Duration::ZERO);

    let (pool, refill) = start_pool(size, 2, &program);
    let mut warm_call = || { let r = call_warm(pool.recv().unwrap(), &args); refill.send(()).unwrap(); r };
    std::thread::sleep(Duration::from_millis(500)); // let the pool fill
    measure(&format!("warm VM, pool of {size}, calls 20 ms apart"), &mut warm_call, Duration::from_millis(20));
    measure(&format!("warm VM, pool of {size}, back to back"), &mut warm_call, Duration::ZERO);

    // The pool must not change what the program sees: compare with bwrap, which mounts the same workspace.
    let (warm_out, _) = warm_call();
    let (bwrap_out, _) = call_process(&bwrap);
    println!("\n  warm output identical to the bwrap run (same workspace): {}", if warm_out == bwrap_out { "yes" } else { "NO" });
    std::process::exit(0); // the makers are still holding warm sandboxes; they die with us
}
