use anyhow::Context;
use ioc_extract::Artifacts;

mod defang;
#[cfg(test)]
mod test;

use crate::defang::*;

pub fn process_str(data: &str, tlp: &str, report_type: &str) {
    let result = Artifacts::from_str(data)
        .with_context(|| "Failed to find any artifacts")
        .unwrap();

    println!("tag: TLP:{}", tlp);
    println!("type: {}", report_type);

    result.urls.map(|url_vec| {
        url_vec.into_iter().for_each(|url| println!("url: {}", defang(&url)));
    });
    result.domains.map(|domain_vec| {
        domain_vec.into_iter().for_each(|domain| println!("domain: {}", defang(&domain)));
    });
    result.emails.map(|email_vec| {
        email_vec.into_iter().for_each(|email| println!("email: {}", defang(&email)));
    });
    result.ip_address.map(|ip_address_vec| {
        ip_address_vec.into_iter().for_each(|ip_address| println!("ip: {}", defang(&ip_address)));
    });
    result.crypto.map(|crypto_vec| {
        crypto_vec.into_iter().for_each(|crypto| println!("crypto: {}", defang(&crypto)));
    });
}