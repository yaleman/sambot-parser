use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Replacers
    static ref DOTS_REGEX: Regex = Regex::new(r"\.").expect("Failed to compile regex!");
    static ref COLONS_REGEX: Regex = Regex::new(r":").expect("Failed to compile regex!");
    static ref AT_REGEX: Regex = Regex::new(r"@").expect("Failed to compile regex!");
    static ref HTTP_REGEX: Regex = Regex::new(r"(?i)http").expect("Failed to compile regex!");
    static ref SLASHES_REGEX: Regex = Regex::new(r"://").expect("Failed to compile regex!");

    // Matchers
    static ref EMAIL_REGEX: Regex = Regex::new(r"(?i)([A-Za-z0-9!#$%&'*+/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)").expect("Failed to compile regex!");
    static ref IPV4_REGEX: Regex = Regex::new(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)").expect("Failed to compile regex!");
    static ref IPV6_REGEX: Regex = Regex::new(r"(?:(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:))|(?:(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){5}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){4}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,3})|(?:(?::[0-9A-Fa-f]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){3}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,4})|(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){2}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,5})|(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){1}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?::(?:(?:(?::[0-9A-Fa-f]{1,4}){1,7})|(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(?:%.+)?\s*").expect("Failed to compile regex!");
}

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
