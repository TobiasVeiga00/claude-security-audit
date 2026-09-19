use std::process::Command;

// Spawns a shell with attacker-influenced input — command injection.
fn run(user_input: &str) {
    let _ = Command::new("sh").arg("-c").arg(user_input).output().unwrap();
}

// SQL built by string formatting instead of bound parameters.
fn lookup(id: &str) {
    let _ = query(&format!("SELECT * FROM users WHERE id = {}", id));
}
