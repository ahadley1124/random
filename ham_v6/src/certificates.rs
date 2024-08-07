use rustls_pemfile;

fn load_pem_file(filename: &str) -> Result<Vec<rustls_pemfile::Item>, std::io::Error> {
    let file = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid certificate"))
}

fn is_private_key_embedded(cert: &rustls::Certificate) -> bool {
    use rustls::internal::pemfile;
    let mut cursor = std::io::Cursor::new(&cert.0);
    let items = pemfile::certs(&mut cursor).unwrap();
    items.len() > 1
}

fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, std::io::Error> {
    let file = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(file);
    let items = rustls_pemfile::pkcs8_private_keys(&mut reader).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid private key"))?;
    if items.len() != 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid private key"));
    }
    Ok(items[0].clone())
}

fn load_cert_chain(filename: &str) -> Result<Vec<rustls::Certificate>, std::io::Error> {
    let file = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid certificate"))
}

fn load_certs_key(cert_filename: &str, key_filename: &str) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), std::io::Error> {
    let certs = load_cert_chain(cert_filename)?;
    let key = load_private_key(key_filename)?;
    Ok((certs, key))
}

fn load_certs_keys(cert_filename: &str, key_filename: &str) -> Result<(Vec<rustls::Certificate>, Vec<rustls::PrivateKey>), std::io::Error> {
    let certs = load_cert_chain(cert_filename)?;
    let key = load_private_key(key_filename)?;
    if is_private_key_embedded(&certs[0]) {
        let mut keys = Vec::new();
        keys.push(key);
        Ok((certs, keys))
    } else {
        let mut keys = load_private_keys(key_filename)?;
        if keys.len() != certs.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid private key"));
        }
        Ok((certs, keys))
    }
}

fn load_private_keys(filename: &str) -> Result<Vec<rustls::PrivateKey>, std::io::Error> {
    let file = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::pkcs8_private_keys(&mut reader).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid private key"))
}

fn load_certs_keys_from_file(filename: &str) -> Result<(Vec<rustls::Certificate>, Vec<rustls::PrivateKey>), std::io::Error> {
    let file = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(file);
    let items = rustls_pemfile::certs(&mut reader).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid certificate"))?;
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for item in items {
        match item {
            rustls_pemfile::Item::X509Certificate(cert) => certs.push(rustls::Certificate(cert)),
            rustls_pemfile::Item::RSAKey(key) => keys.push(rustls::PrivateKey(key)),
            rustls_pemfile::Item::PKCS8Key(key) => keys.push(rustls::PrivateKey(key)),
        }
    }
    Ok((certs, keys))
}
