const COMMANDS: &[&str] = &["sign_in", "get_token", "status", "sign_out"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
