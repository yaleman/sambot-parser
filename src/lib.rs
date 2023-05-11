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

    if let Some(url_vec) = result.urls { url_vec.into_iter().for_each(|url| println!("url: {}", defang(&url))); }
    if let Some(domain_vec) = result.domains { domain_vec.into_iter().for_each(|domain| println!("domain: {}", defang(&domain))); }
    if let Some(email_vec) = result.emails { email_vec.into_iter().for_each(|email| println!("email: {}", defang(&email))); }
    if let Some(ip_address_vec) = result.ip_address { ip_address_vec.into_iter().for_each(|ip_address| println!("ip: {}", defang(&ip_address))); }
    if let Some(crypto_vec) = result.crypto { crypto_vec.into_iter().for_each(|crypto| println!("crypto: {}", defang(&crypto))); }
}