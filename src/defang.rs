use std::sync::LazyLock;

use regex::Regex;

// Replacers
static DOTS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.").expect("Failed to compile regex!"));

static COLONS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r":").expect("Failed to compile regex!"));
static AT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@").expect("Failed to compile regex!"));
static HTTP_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)http").expect("Failed to compile regex!"));
// static SLASHES_REGEX: LazyLock<Regex> =
//     LazyLock::new(|| Regex::new(r"://").expect("Failed to compile regex!"));

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)([A-Za-z0-9!#$%&'*+/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)").expect("Failed to compile regex!")
});
static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)").expect("Failed to compile regex!")
});
// Matchers

static IPV6_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:))|(?:(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){5}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){4}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,3})|(?:(?::[0-9A-Fa-f]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){3}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,4})|(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){2}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,5})|(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){1}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?::(?:(?:(?::[0-9A-Fa-f]{1,4}){1,7})|(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(?:%.+)?\s*").expect("Failed to compile regex!")
});

pub fn defang(input: &str) -> String {
    if IPV4_REGEX.is_match(input) {
        defang_ipv4(input)
    } else if IPV6_REGEX.is_match(input) {
        return defang_ipv6(input);
    } else if EMAIL_REGEX.is_match(input) {
        return defang_email(input);
    } else {
        return defang_url(input);
    }
}

pub fn defang_url(input: &str) -> String {
    let mut result = input.to_string();

    result = DOTS_REGEX.replace_all(&result, "[.]").to_string();
    result = HTTP_REGEX.replace_all(&result, "hxxp").to_string();
    // result = SLASHES_REGEX.replace_all(&result, "[://]").to_string();

    result
}

pub fn defang_ipv4(input: &str) -> String {
    DOTS_REGEX.replace_all(input, "[.]").to_string()
}

pub fn defang_ipv6(input: &str) -> String {
    COLONS_REGEX.replace_all(input, "[:]").to_string()
}

pub fn defang_email(input: &str) -> String {
    let mut result = input.to_string();

    result = DOTS_REGEX.replace_all(&result, "[.]").to_string();
    result = AT_REGEX.replace_all(&result, "[@]").to_string();

    result
}

#[test]
fn test_ipv6_regex() {
    assert!(IPV6_REGEX.is_match("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3:0:0:8a2e:370:7334"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3::8a2e:370:7334"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3:0:0:8a2e:370:7334"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3::8a2e:370:7334"));
    assert!(IPV6_REGEX.is_match("2001:db8::1"));
    assert!(IPV6_REGEX.is_match("2001:db8::"));
    assert!(IPV6_REGEX.is_match("2001::1%asdf"));
    assert!(IPV6_REGEX.is_match("2001::1<asdf"));
    assert!(IPV6_REGEX.is_match("::1"));
    assert!(IPV6_REGEX.is_match("::"));
    assert!(IPV6_REGEX.is_match("2001:0db8:85a3:0000:0000:8a2e:0370:7334%eth0"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3:0:0:8a2e:370:7334%eth0"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3::8a2e:370:7334%eth0"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3:0:0:8a2e:370:7334%eth0"));
    assert!(IPV6_REGEX.is_match("2001:db8:85a3::8a2e:370:7334%eth0"));
    assert!(IPV6_REGEX.is_match("2001:db8::1%eth0"));
    assert!(IPV6_REGEX.is_match("2001:db8::%eth0"));
    assert!(IPV6_REGEX.is_match("::1%eth0"));
    assert!(IPV6_REGEX.is_match("::%eth0"));
}

#[test]
fn test_defang_ips() {
    assert_eq!(defang("1.2.3.4"), "1[.]2[.]3[.]4");
    assert_eq!(defang_ipv4("1.2.3.4"), "1[.]2[.]3[.]4");

    assert_eq!(defang("2001::1"), "2001[:][:]1");
    assert_eq!(defang_ipv6("2001::1"), "2001[:][:]1");
    assert_eq!(defang("foo@example.com"), "foo[@]example[.]com");
    assert_eq!(defang_email("foo@example.com"), "foo[@]example[.]com");
}
