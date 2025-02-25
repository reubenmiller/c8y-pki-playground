use base64::prelude::*;

use cryptographic_message_syntax;

// Note: Since the server is not available openssl was used to convert from x509 PEM to a p7b (pkcs7) format.
//
// Convert pem to p7b format (for testing)
// openssl crl2pkcs7 -nocrl -certfile /opt/homebrew/etc/tedge/device-certs/tedge-certificate.pem -out certificatename.p7b -outform PEM


fn main() {
    println!("Converting .p7b to x509 PEM");
    let response = "MIIBewYJKoZIhvcNAQcCoIIBbDCCAWgCAQExADALBgkqhkiG9w0BBwGgggFQMIIBTDCB86ADAgECAgYBlT2fB9gwCgYIKoZIzj0EAwIwQjEWMBQGA1UEBhMNVW5pdGVkIFN0YXRlczETMBEGA1UEChMKQ3VtdWxvY2l0eTETMBEGA1UEAxMKbWFuYWdlbWVudDAeFw0yNTAyMjUxNDU5NDdaFw0yNjAyMjQwOTQxNDRaMBkxFzAVBgNVBAMMDnJtaV9kZXZpY2UwMDA1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0tJN3RwZ0K4ZxiWal7FDzYIlmlL7gCb/T4BzK1vFQzC+Uww4DR49ieS+3/zVYsYmwIIW530p1Hq7+bFJkF/hfDAKBggqhkjOPQQDAgNIADBFAiEAs/MGFehWXQXGebAIrbjQoNMnldmdoA1EkU/8J0dEWJICIFFmkiCLvv8Yua1bEuXqGv7nhM2YVHCreYQ3i09zpgzhMQA=";
    parse_pkcs7_certsonly_response(response);
}

fn parse_pkcs7_certsonly_response(message: &str) -> String {
    // 1. Filter response and remove \n and \r characters
    // Note: golang does this by default. Decode decodes src using the encoding enc. It writes at most [Encoding.DecodedLen](len(src)) bytes to dst and returns the number of bytes written. The caller must ensure that dst is large enough to hold all the decoded data. If src contains invalid base64 data, it will return the number of bytes successfully written and [CorruptInputError]. New line characters (\r and \n) are ignored.
    let message = message.replace(&['\n', '\r'], "");

    // 2. Decode Base64
    let message_bytes = BASE64_STANDARD.decode(message).unwrap();

    // 3. Parse the ber encoded SignedData
    let cms_response = cryptographic_message_syntax::SignedData::parse_ber(&message_bytes).unwrap();

    // 4. Convert each cert to x509 pem format (note, technically the order isn't guaranteed by the server as per the spec)
    let certificates_pem: Vec<String> = cms_response.certificates().map(|c| {
        c.encode_pem()
    }).collect();
    
    // 5. Return PEM contents as a string
    let contents = certificates_pem.join("\r\n");
    println!("{}", contents);
    contents
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_certificate() {
        let response = r#"
MIIBewYJKoZIhvcNAQcCoIIBbDCCAWgCAQExADALBgkqhkiG9w0BBwGgggFQMIIBTDCB86ADAgECAgYBlT2fB9gwCgYIKoZIzj0EAwIwQjEWMBQGA1UEBhMNVW5pdGVkIFN0YXRlczETMBEGA1UEChMKQ3VtdWxvY2l0eTETMBEGA1UEAxMKbWFuYWdlbWVudDAeFw0yNTAyMjUxNDU5NDdaFw0yNjAyMjQwOTQxNDRaMBkxFzAVBgNVBAMMDnJtaV9kZXZpY2UwMDA1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0tJN3RwZ0K4ZxiWal7FDzYIlmlL7gCb/T4BzK1vFQzC+Uww4DR49ieS+3/zVYsYmwIIW530p1Hq7+bFJkF/hfDAKBggqhkjOPQQDAgNIADBFAiEAs/MGFehWXQXGebAIrbjQoNMnldmdoA1EkU/8J0dEWJICIFFmkiCLvv8Yua1bEuXqGv7nhM2YVHCreYQ3i09zpgzhMQA=
"#;
        let output = parse_pkcs7_certsonly_response(response);
        
        assert_eq!(output, "");
    }
}
