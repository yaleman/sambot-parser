use crate::process_str;

const EXAMPLE_SMS: &str = include_str!("../tests/sms.txt");
const EXAMPLE_EMAIL: &str = include_str!("../tests/email.txt");

#[test]
fn test_sms() {
    println!("input: {}", EXAMPLE_SMS);
    println!("output:");
    process_str(EXAMPLE_SMS, "green", "phish");
}

#[test]
fn test_email() {
    eprintln!("input: {}", EXAMPLE_EMAIL);
    println!("output:");
    process_str(EXAMPLE_EMAIL, "green", "phish");
}

#[test]
fn test_subject_regex() {
    use crate::REGEX_SUBJECT;
    for line in [
        "subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;",
        "Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck",
    ] {
        println!("Testing negative '{}'", line);
        assert!(REGEX_SUBJECT.find(line).is_none())
    }

    for line in [
        "Subject: Find Your Perfect Match in Ukraine: Start Dating Today!",
        "subject: Find Your Perfect Match in Ukraine: Start Dating Today!",
    ] {
        println!("Testing positive '{}'", line);
        assert!(REGEX_SUBJECT.find(line).is_some());
    }
}
