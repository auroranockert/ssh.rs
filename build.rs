use std::process::Command;

fn main() {
  Command::new("sh").args(&["build.sh"]).status().unwrap();
}