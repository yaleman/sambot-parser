use crate::process_str;

const EXAMPLE_SMS: &str = include_str!("../tests/sms.txt");
const EXAMPLE_EMAIL: &str = include_str!("../tests/email.txt");

#[test]
fn test_sms() {
    println!("input: {}", EXAMPLE_SMS);
    println!("output:");
    assert!(process_str(EXAMPLE_SMS, "green", "phish").is_ok());
}

#[test]
fn test_email() {
    eprintln!("input: {}", EXAMPLE_EMAIL);
    let res = process_str(EXAMPLE_EMAIL, "green", "phish").expect("failed to get result");
    println!("output:");
    println!("{}", res);
    assert!(res.contains("ip-dst: 2001[:][:]1"));
    assert!(res.contains("domain: mx1[.]messagingengine[.]com"));
}

#[test]
fn test_links() {
    let test_text = "are closing soon:https://example.com/foobar ";
    let expected = "https://example.com/foobar";

    let artifacts = crate::get_artifacts(test_text).unwrap();
    let urls = artifacts.urls.unwrap();

    assert!(urls.len() == 1);

    assert_eq!(urls.first().unwrap(), expected);
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

#[test]
fn test_with_single_quote() {
    let test_text = "are closing soon: https://example.com/foobar'";
    let expected = "https://example.com/foobar'";

    let artifacts = crate::get_artifacts(test_text).unwrap();
    let urls = artifacts.urls.unwrap();

    assert!(urls.len() == 1);
    assert!(urls.first().unwrap() == expected);

    let test_text = "'Urgent Notification: Your medical insurance refund was not processed correctly. Please take immediate steps: hxxps://fooba.space'";
    let expected = "hxxps://fooba.space";
    assert!(ioc_extract::validators::internet::URL
        .is_match(expected)
        .expect("Failed to regex URL"));

    let artifacts = crate::get_artifacts(test_text).expect("Failed on fooba.space domain");
    let urls = artifacts.urls.unwrap();
    assert!(urls.len() == 1);
    assert_eq!(urls.first().unwrap(), expected);
}
