use chrono::{prelude::{DateTime, Local}, Duration};
fn main() {
    let local: DateTime<Local> = Local::now();
    local.checked_add_signed(Duration::seconds(60));
    println!("{}", local.timestamp());
}
