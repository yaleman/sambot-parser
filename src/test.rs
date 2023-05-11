use crate::process_str;

const EXAMPLE_SMS: &str = include_str!("../tests/sms.txt");

#[test]
fn test_sms() {

    println!("input: {}", EXAMPLE_SMS);
    println!("output:");
    process_str(EXAMPLE_SMS, "green", "phish");
}
