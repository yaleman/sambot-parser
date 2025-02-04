use anyhow::Context;
use ioc_extract::Artifacts;

use once_cell::sync::Lazy;
use regex::Regex;

mod defang;
#[cfg(test)]
mod test;

use crate::defang::*;

// TODO:
// hash|filename:

static REGEX_MD5: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"([a-fA-F0-9]{32})"#).expect("Failed to compile regex!"));
static REGEX_SHA256: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"([a-fA-F0-9]{64})"#).expect("Failed to compile regex!"));
static REGEX_SHA512: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"([a-fA-F0-9]{128})"#).expect("Failed to compile regex!"));
// thanks to https://nbviewer.org/github/rasbt/python_reference/blob/master/tutorials/useful_regex.ipynb#Checking-for-IP-addresses
static REGEX_IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$'
    ").expect("Failed to compile regex!")
});
static REGEX_SUBJECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)Subject:\s+([^\n]+)").expect("Failed to compile regex!"));

/// Use the regexes to find hashes in the source strings.
macro_rules! find_hash {
    ($x:expr, $target:expr) => {
        $x.captures_iter($target)
            .map(|x| x[1].to_string())
            .collect()
    };
}

/// strip ansi escape codes on the input
fn strip_to_string(data: &str) -> String {
    let ansi_stripped = strip_ansi_escapes::strip(data);
    std::str::from_utf8(&ansi_stripped)
        .expect("Failed to get string from stripped ansi")
        .to_string()
}

pub(crate) fn get_artifacts(data: &str) -> Result<Artifacts, anyhow::Error> {
    Artifacts::from_str(data).with_context(|| "Failed to find any artifacts")
}

pub fn process_str(data: &str, tlp: &str, report_type: &str) {
    // TODO: make this a test
    // echo -e "https://\033[31;1;4mgoogle.com Hello\033[0m https://example.com" | cargo run --
    let data = strip_to_string(data);

    let result = match get_artifacts(&data) {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Error: {:?}", err);
            return;
        }
    };

    println!("tag: TLP:{}", tlp);
    println!("type: {}", report_type);

    if let Some(url_vec) = result.urls {
        url_vec
            .into_iter()
            .for_each(|url| println!("url: {}", defang(&url)));
    }
    if let Some(domain_vec) = result.domains {
        domain_vec
            .into_iter()
            .for_each(|domain| println!("domain: {}", defang(&domain)));
    }

    // from: or source-email: or email-source
    if let Some(email_vec) = result.emails {
        email_vec
            .into_iter()
            .for_each(|email| println!("from: {}", defang(&email)));
    }

    // ip-dst:
    // ip-src:
    if let Some(ip_address_vec) = result.ip_address {
        ip_address_vec
            .into_iter()
            .for_each(|ip_address| println!("ip-dst: {}", defang(&ip_address)));
    }

    // use REGEX_IPV6 to match IP Addresses
    REGEX_IPV6.captures_iter(&data).for_each(|x| {
        println!("ip-dst: {}", defang(&x[1]));
    });

    if let Some(crypto_vec) = result.crypto {
        crypto_vec
            .into_iter()
            .for_each(|crypto| println!("crypto: {}", defang(&crypto)));
    }
    REGEX_SUBJECT.captures_iter(&data).for_each(|x| {
        println!("subject: {}", defang(&x[0]));
    });

    let md5s: Vec<String> = find_hash!(REGEX_MD5, &data);
    let sha256s: Vec<String> = find_hash!(REGEX_SHA256, &data);
    let sha512s: Vec<String> = find_hash!(REGEX_SHA512, &data);

    md5s.into_iter().for_each(|md5| println!("md5: {}", md5));
    sha256s
        .into_iter()
        .for_each(|sha256| println!("sha256: {}", sha256));
    sha512s
        .into_iter()
        .for_each(|sha512| println!("sha512: {}", sha512));

    println!("-------------------------");
    println!("{}", data);
}
