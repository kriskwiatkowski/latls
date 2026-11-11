mod common;

mod handshake {
    use embedded_io::BufRead as _;
    use embedded_io_adapters::{std::FromStd, tokio_1::FromTokio};
    use embedded_io_async::BufRead as _;
    use rand::rngs::OsRng;
    use std::net::SocketAddr;
    use std::sync::Once;

    static LOG_INIT: Once = Once::new();
    static INIT: Once = Once::new();
    static mut ADDR: Option<SocketAddr> = None;

    fn init_log() {
        LOG_INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    fn setup() -> SocketAddr {
        use mio::net::TcpListener;
        init_log();
        INIT.call_once(|| {
            let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

            let listener = TcpListener::bind(addr).expect("cannot listen on port");
            let addr = listener
                .local_addr()
                .expect("error retrieving socket address");

            std::thread::spawn(move || {
                crate::common::run(listener);
            });
            #[allow(static_mut_refs)]
            unsafe {
                ADDR.replace(addr)
            };
        });
        unsafe { ADDR.unwrap() }
    }

    #[tokio::test]
    async fn connect_and_echo() {
        use latls::*;
        use tokio::net::TcpStream;
        let addr = setup();

        let stream = TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        log::info!("SIZE of connection is {}", core::mem::size_of_val(&tls));

        let open_fut = tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ));
        log::info!("SIZE of open fut is {}", core::mem::size_of_val(&open_fut));
        open_fut.await.expect("error establishing TLS connection");
        log::info!("Established");

        let write_fut = tls.write(b"ping");
        log::info!(
            "SIZE of write fut is {}",
            core::mem::size_of_val(&write_fut)
        );
        write_fut.await.expect("error writing data");
        tls.flush().await.expect("error flushing data");

        // Make sure reading into a 0 length buffer doesn't loop
        let mut rx_buf = [0; 0];
        let read_fut = tls.read(&mut rx_buf);
        log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
        let sz = read_fut.await.expect("error reading data");
        assert_eq!(sz, 0);

        let mut rx_buf = [0; 4096];
        let read_fut = tls.read(&mut rx_buf);
        log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
        let sz = read_fut.await.expect("error reading data");
        assert_eq!(4, sz);
        assert_eq!(b"ping", &rx_buf[..sz]);
        log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

        // Test that latls doesn't block if the buffer is empty.
        let mut rx_buf = [0; 0];
        let sz = tls.read(&mut rx_buf).await.expect("error reading data");
        assert_eq!(sz, 0);

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[tokio::test]
    async fn connect_buffered_read() {
        use latls::*;
        use tokio::net::TcpStream;
        let addr = setup();

        let stream = TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        log::info!("SIZE of connection is {}", core::mem::size_of_val(&tls));

        let open_fut = tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ));
        log::info!("SIZE of open fut is {}", core::mem::size_of_val(&open_fut));
        open_fut.await.expect("error establishing TLS connection");
        log::info!("Established");

        let write_fut = tls.write(b"data to echo");
        log::info!(
            "SIZE of write fut is {}",
            core::mem::size_of_val(&write_fut)
        );
        write_fut.await.expect("error writing data");
        tls.flush().await.expect("error flushing data");

        {
            let mut buf = tls.read_buffered().await.expect("error reading data");
            log::info!("Read bytes: {:?}", buf.peek_all());

            let read_bytes = buf.pop(2);
            assert_eq!(b"da", read_bytes);

            let read_bytes = buf.pop(2);
            assert_eq!(b"ta", read_bytes);
        }

        {
            let mut buf = tls.read_buffered().await.expect("error reading data");
            assert_eq!(b" to ", buf.pop(4));
        }

        {
            let mut buf = tls.read_buffered().await.expect("error reading data");
            let read_bytes = buf.pop_all();
            assert_eq!(b"echo", read_bytes);
        }

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[tokio::test]
    async fn connect_bufread_trait() {
        use latls::*;
        use tokio::net::TcpStream;

        let addr = setup();

        let stream = TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );
        tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .await
        .expect("error establishing TLS connection");
        log::info!("Established");

        tls.write(b"ping").await.expect("error writing data");
        tls.flush().await.expect("error flushing data");

        let buf = tls.fill_buf().await.expect("error reading data");

        assert_eq!(b"ping", buf);
        log::info!("Read bytes: {:?}", buf);

        let len = buf.len();
        tls.consume(len);

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[test]
    fn blocking_connect_and_echo() {
        use latls::blocking::*;
        use std::net::TcpStream;

        let addr = setup();
        let stream = TcpStream::connect(addr).expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls: SecureStream<FromStd<TcpStream>, Aes128GcmSha256> = SecureStream::new(
            FromStd::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );
        tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .expect("error establishing TLS connection");
        log::info!("Established");

        tls.write(b"ping").expect("error writing data");
        tls.flush().expect("error flushing data");

        // Make sure reading into a 0 length buffer doesn't loop
        let mut rx_buf = [0; 0];
        let sz = tls.read(&mut rx_buf).expect("error reading data");
        assert_eq!(sz, 0);

        let mut rx_buf = [0; 4096];
        let sz = tls.read(&mut rx_buf).expect("error reading data");
        assert_eq!(4, sz);
        assert_eq!(b"ping", &rx_buf[..sz]);
        log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

        // Test that latls doesn't block if the buffer is empty.
        let mut rx_buf = [0; 0];
        let sz = tls.read(&mut rx_buf).expect("error reading data");
        assert_eq!(sz, 0);

        tls.close()
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[test]
    fn blocking_buffered_read() {
        use latls::blocking::*;
        use std::net::TcpStream;

        let addr = setup();
        let stream = TcpStream::connect(addr).expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls: SecureStream<FromStd<TcpStream>, Aes128GcmSha256> = SecureStream::new(
            FromStd::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );
        tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .expect("error establishing TLS connection");
        log::info!("Established");

        tls.write(b"ping").expect("error writing data");
        tls.flush().expect("error flushing data");

        let mut buf = tls.read_buffered().expect("error reading data");
        log::info!("Read bytes: {:?}", buf.peek_all());

        let read_bytes = buf.pop(2);
        assert_eq!(b"pi", read_bytes);
        let read_bytes = buf.pop_all();
        assert_eq!(b"ng", read_bytes);

        core::mem::drop(buf);

        tls.close()
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[test]
    fn blocking_bufread_trait() {
        use latls::blocking::*;
        use std::net::TcpStream;

        let addr = setup();
        let stream = TcpStream::connect(addr).expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls: SecureStream<FromStd<TcpStream>, Aes128GcmSha256> = SecureStream::new(
            FromStd::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );
        tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .expect("error establishing TLS connection");
        log::info!("Established");

        tls.write(b"ping").expect("error writing data");
        tls.flush().expect("error flushing data");

        let buf = tls.fill_buf().expect("error reading data");

        assert_eq!(b"ping", buf);
        log::info!("Read bytes: {:?}", buf);

        let len = buf.len();
        tls.consume(len);

        tls.close()
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }
}

mod psk {
    use embedded_io_adapters::tokio_1::FromTokio;
    use latls::*;
    use openssl::ssl;
    use rand::rngs::OsRng;
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use std::net::TcpListener;
    use std::sync::Once;
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;
    use tokio::time::Duration;
    use tokio::time::timeout;

    static INIT: Once = Once::new();

    fn setup() -> (SocketAddr, JoinHandle<()>) {
        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });

        const DEFAULT_CIPHERS: &[&str] = &["PSK"];
        let mut builder =
            ssl::SslAcceptor::mozilla_intermediate_v5(ssl::SslMethod::tls_server()).unwrap();
        builder
            .set_private_key_file("tests/fixtures/leaf-server-key.pem", ssl::SslFiletype::PEM)
            .unwrap();
        builder
            .set_certificate_chain_file("tests/fixtures/leaf-server.pem")
            .unwrap();
        builder
            .set_min_proto_version(Some(ssl::SslVersion::TLS1_3))
            .unwrap();
        builder.set_cipher_list(&DEFAULT_CIPHERS.join(",")).unwrap();
        builder.set_psk_server_callback(move |_ssl, identity, secret_mut| {
            if let Some(b"vader") = identity {
                secret_mut[..4].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
                Ok(4)
            } else {
                Ok(0)
            }
        });
        let acceptor = builder.build();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        let h = tokio::task::spawn_blocking(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = acceptor.accept(stream).unwrap();
            let mut buf = [0; 64];
            let len = conn.read(&mut buf[..]).unwrap();
            conn.write_all(&buf[..len]).unwrap();
        });
        (addr, h)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_with_psk() {
        let (addr, h) = setup();
        timeout(Duration::from_secs(120), async move {
            println!("Connecting...");
            let stream = TcpStream::connect(addr)
                .await
                .expect("error connecting to server");

            println!("Connected");
            let mut read_record_buffer = [0; 16384];
            let mut write_record_buffer = [0; 16384];
            let config = ConnectConfig::new()
                .with_psk(&[0xaa, 0xbb, 0xcc, 0xdd], &[b"vader"])
                .with_server_name("localhost");

            let mut tls = SecureStream::new(
                FromTokio::new(stream),
                &mut read_record_buffer,
                &mut write_record_buffer,
            );

            assert!(
                tls.open(ConnectContext::new(
                    &config,
                    SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng)
                ))
                .await
                .is_ok()
            );
            println!("TLS session opened");

            tls.write(b"ping").await.unwrap();
            tls.flush().await.unwrap();

            println!("TLS data written");
            let mut rx = [0; 4];
            let l = tls.read(&mut rx[..]).await.unwrap();

            println!("TLS data read");
            assert_eq!(4, l);
            assert_eq!(b"ping", &rx[..l]);

            h.await.unwrap();
        })
        .await
        .unwrap();
    }
}

mod split {
    use embedded_io::{Read, Write};
    use embedded_io_adapters::std::FromStd;
    use rand_core::OsRng;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut ADDR: Option<SocketAddr> = None;

    fn setup() -> SocketAddr {
        use mio::net::TcpListener;
        INIT.call_once(|| {
            let _ = env_logger::try_init();

            let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();

            let listener = TcpListener::bind(addr).expect("cannot listen on port");
            let addr = listener
                .local_addr()
                .expect("error retrieving socket address");

            std::thread::spawn(move || {
                crate::common::run(listener);
            });
            #[allow(static_mut_refs)]
            unsafe {
                ADDR.replace(addr)
            };
        });
        unsafe { ADDR.unwrap() }
    }

    pub struct Clonable<T: ?Sized>(std::sync::Arc<T>);

    impl<T: ?Sized> Clone for Clonable<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }

    impl embedded_io::ErrorType for Clonable<TcpStream> {
        type Error = std::io::Error;
    }

    impl embedded_io::Read for Clonable<TcpStream> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let mut stream = FromStd::new(self.0.as_ref());
            stream.read(buf)
        }
    }

    impl embedded_io::Write for Clonable<TcpStream> {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            let mut stream = FromStd::new(self.0.as_ref());
            stream.write(buf)
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            let mut stream = FromStd::new(self.0.as_ref());
            stream.flush()
        }
    }

    #[test]
    fn blocking_split_io() {
        use latls::blocking::*;
        use std::net::TcpStream;
        use std::sync::Arc;
        let addr = setup();
        let stream = TcpStream::connect(addr).expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            Clonable(Arc::new(stream)),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .expect("error establishing TLS connection");

        let (mut reader, mut writer) = tls.split();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut buffer = [0; 4];
                reader.read_exact(&mut buffer).expect("Failed to read data");
            });
            scope.spawn(|| {
                writer.write(b"ping").expect("Failed to write data");
                writer.flush().expect("Failed to flush");
            });
        });

        tls.close()
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }
}

mod early_data {
    use embedded_io::{Read, Write};
    use embedded_io_adapters::std::FromStd;
    use rand_core::OsRng;
    use std::net::SocketAddr;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut ADDR: Option<SocketAddr> = None;

    fn setup() -> SocketAddr {
        use mio::net::TcpListener;
        INIT.call_once(|| {
            let _ = env_logger::try_init();

            let addr: SocketAddr = "127.0.0.1:12347".parse().unwrap();

            let listener = TcpListener::bind(addr).expect("cannot listen on port");
            let addr = listener
                .local_addr()
                .expect("error retrieving socket address");

            std::thread::spawn(move || {
                use crate::common::*;

                let versions = &[&rustls::version::TLS13];

                let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

                let certs = load_certs(&test_dir.join("fixtures").join("leaf-server.pem"));
                let privkey =
                    load_private_key(&test_dir.join("fixtures").join("leaf-server-key.pem"));

                let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
                    .with_no_client_auth()
                    .with_single_cert(certs, privkey)
                    .unwrap();

                config.max_early_data_size = 512;

                run_with_config(listener, config);
            });
            #[allow(static_mut_refs)]
            unsafe {
                ADDR.replace(addr)
            };
        });
        unsafe { ADDR.unwrap() }
    }

    #[test]
    fn handshake_skips_early_data() {
        use latls::blocking::*;
        use std::net::TcpStream;

        let addr = setup();
        let stream = TcpStream::connect(addr).expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromStd::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        tls.open(ConnectContext::new(
            &config,
            SkipVerifyProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .expect("error establishing TLS connection");

        tls.write_all(b"ping").expect("Failed to write data");
        tls.flush().expect("Failed to flush");

        let mut buffer = [0; 4];
        tls.read_exact(&mut buffer).expect("Failed to read data");

        tls.close()
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }
}

mod client_cert {
    use ecdsa::elliptic_curve::SecretKey;
    use embedded_io_adapters::tokio_1::FromTokio;
    use latls::{Certificate, CryptoBackend, SignatureScheme};
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use rand_core::CryptoRngCore;
    use rustls::server::WebPkiClientVerifier;
    use std::net::SocketAddr;
    use std::sync::{Arc, Once};

    static LOG_INIT: Once = Once::new();
    static INIT: Once = Once::new();
    static mut ADDR: Option<SocketAddr> = None;

    fn init_log() {
        LOG_INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    fn setup() -> SocketAddr {
        use mio::net::TcpListener;
        init_log();
        INIT.call_once(|| {
            let addr: SocketAddr = "127.0.0.1:12348".parse().unwrap();

            let listener = TcpListener::bind(addr).expect("cannot listen on port");
            let addr = listener
                .local_addr()
                .expect("error retrieving socket address");

            std::thread::spawn(move || {
                use crate::common::*;

                let versions = &[&rustls::version::TLS13];

                let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

                let ca = load_certs(&test_dir.join("fixtures").join("root-ca.pem"));
                let certs = load_certs(&test_dir.join("fixtures").join("leaf-server.pem"));
                let privkey =
                    load_private_key(&test_dir.join("fixtures").join("leaf-server-key.pem"));

                let mut client_auth_roots = rustls::RootCertStore::empty();
                for root in ca.into_iter() {
                    client_auth_roots.add(root).unwrap()
                }

                let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                    .build()
                    .unwrap();

                let config = rustls::ServerConfig::builder_with_protocol_versions(versions)
                    .with_client_cert_verifier(client_cert_verifier)
                    .with_single_cert(certs, privkey)
                    .unwrap();

                run_with_config(listener, config);
            });
            #[allow(static_mut_refs)]
            unsafe {
                ADDR.replace(addr)
            };
        });
        unsafe { ADDR.unwrap() }
    }

    struct Credentials<'a> {
        rng: OsRng,
        priv_key: &'a [u8],
        client_cert: Option<Certificate<&'a [u8]>>,
    }

    impl CryptoBackend for Credentials<'_> {
        type CipherSuite = latls::Aes128GcmSha256;
        type Signature = p256::ecdsa::DerSignature;

        fn rng(&mut self) -> impl CryptoRngCore {
            &mut self.rng
        }

        fn signer(
            &mut self,
        ) -> Result<
            (impl signature::SignerMut<Self::Signature>, SignatureScheme),
            latls::ProtocolError,
        > {
            let secret_key = SecretKey::from_sec1_der(self.priv_key)
                .map_err(|_| latls::ProtocolError::InvalidPrivateKey)?;

            Ok((
                SigningKey::from(&secret_key),
                SignatureScheme::EcdsaSecp256r1Sha256,
            ))
        }

        fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
            self.client_cert.clone()
        }
    }

    #[tokio::test]
    async fn mutual_tls_auth() {
        use latls::*;
        use tokio::net::TcpStream;
        let addr = setup();

        let client_cert_pem = include_str!("fixtures/leaf-client.pem");
        let client_cert_der = pem_parser::pem_to_der(client_cert_pem);

        let private_key_pem = include_str!("fixtures/leaf-client-key.pem");
        let private_key_der = pem_parser::pem_to_der(private_key_pem);

        let stream = TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        log::info!("Connected");
        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];
        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        log::info!("SIZE of connection is {}", core::mem::size_of_val(&tls));

        let mut provider = Credentials {
            rng: OsRng,
            priv_key: &private_key_der,
            client_cert: Some(Certificate::X509(&client_cert_der)),
        };
        let open_fut = tls.open(ConnectContext::new(&config, &mut provider));
        log::info!("SIZE of open fut is {}", core::mem::size_of_val(&open_fut));
        open_fut.await.expect("error establishing TLS connection");
        log::info!("Established");

        let write_fut = tls.write(b"ping");
        log::info!(
            "SIZE of write fut is {}",
            core::mem::size_of_val(&write_fut)
        );
        write_fut.await.expect("error writing data");
        tls.flush().await.expect("error flushing data");

        // Make sure reading into a 0 length buffer doesn't loop
        let mut rx_buf = [0; 0];
        let read_fut = tls.read(&mut rx_buf);
        log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
        let sz = read_fut.await.expect("error reading data");
        assert_eq!(sz, 0);

        let mut rx_buf = [0; 4096];
        let read_fut = tls.read(&mut rx_buf);
        log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
        let sz = read_fut.await.expect("error reading data");
        assert_eq!(4, sz);
        assert_eq!(b"ping", &rx_buf[..sz]);
        log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

        // Test that latls doesn't block if the buffer is empty.
        let mut rx_buf = [0; 0];
        let sz = tls.read(&mut rx_buf).await.expect("error reading data");
        assert_eq!(sz, 0);

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }
}

#[cfg(feature = "webpki")]
mod cert_verify {
    use embedded_io_adapters::tokio_1::FromTokio;
    use latls::cert_verify::CertVerifier;
    use latls::{Aes128GcmSha256, CryptoBackend, Verifier};
    use std::net::SocketAddr;
    use std::sync::OnceLock;
    use std::time::SystemTime;

    static LOG_INIT: OnceLock<()> = OnceLock::new();

    struct WebPkiProvider<'a> {
        rng: rand::rngs::OsRng,
        verifier: CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>,
    }

    impl CryptoBackend for WebPkiProvider<'_> {
        type CipherSuite = Aes128GcmSha256;
        type Signature = &'static [u8];

        fn rng(&mut self) -> impl latls::CryptoRngCore {
            &mut self.rng
        }

        fn verifier(
            &mut self,
        ) -> Result<&mut impl Verifier<Aes128GcmSha256>, latls::ProtocolError> {
            Ok(&mut self.verifier)
        }
    }

    fn init_log() {
        LOG_INIT.get_or_init(|| {
            let _ = env_logger::try_init();
        });
    }

    async fn setup() -> SocketAddr {
        init_log();

        use mio::net::TcpListener;
        use std::net::{IpAddr, Ipv4Addr};

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("cannot listen on port");

        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            crate::common::run(listener);
        });

        log::info!("Server at {:?}", addr);
        addr
    }

    #[tokio::test]
    async fn verify_server_cert() {
        use latls::*;

        let addr = setup().await;
        let pem = include_str!("fixtures/root-ca.pem");
        let der = pem_parser::pem_to_der(pem);

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];

        // Hostname verification is not enabled
        let config = ConnectConfig::new();

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        let open_fut = tls.open(ConnectContext::new(
            &config,
            WebPkiProvider {
                rng: rand::rngs::OsRng,
                verifier: CertVerifier::new(Certificate::X509(&der[..])),
            },
        ));

        open_fut.await.expect("error establishing TLS connection");

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }
}

#[cfg(feature = "native-pki")]
mod native_pki {
    use embedded_io_adapters::tokio_1::FromTokio;
    use latls::native_pki::CertVerifier;
    use latls::{
        Aes128GcmSha256, CryptoBackend, ProtocolError as ConnectError, SignatureScheme, Verifier,
    };
    use p256::SecretKey;
    use p256::ecdsa::{DerSignature, SigningKey};
    use rand_core::OsRng;
    use rustls::server::WebPkiClientVerifier;
    use signature::SignerMut;
    use std::net::SocketAddr;
    use std::sync::{Arc, Once};
    use std::time::SystemTime;

    static LOG_INIT: Once = Once::new();
    static INIT: Once = Once::new();
    static mut ADDR: Option<SocketAddr> = None;

    struct RustPkiProvider<'a> {
        rng: rand::rngs::OsRng,
        verifier: CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>,
        priv_key: Option<&'a [u8]>,
        client_cert: Option<latls::Certificate<&'a [u8]>>,
    }

    impl CryptoBackend for RustPkiProvider<'_> {
        type CipherSuite = Aes128GcmSha256;
        type Signature = DerSignature;

        fn rng(&mut self) -> impl latls::CryptoRngCore {
            &mut self.rng
        }

        fn verifier(&mut self) -> Result<&mut impl Verifier<Aes128GcmSha256>, ConnectError> {
            Ok(&mut self.verifier)
        }

        fn signer(
            &mut self,
        ) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), ConnectError> {
            let key_der = self.priv_key.ok_or(ConnectError::InvalidPrivateKey)?;
            let secret_key =
                SecretKey::from_sec1_der(key_der).map_err(|_| ConnectError::InvalidPrivateKey)?;

            Ok((
                SigningKey::from(&secret_key),
                SignatureScheme::EcdsaSecp256r1Sha256,
            ))
        }

        fn client_cert(&mut self) -> Option<latls::Certificate<impl AsRef<[u8]>>> {
            self.client_cert.clone()
        }
    }

    fn init_log() {
        LOG_INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    fn setup() -> SocketAddr {
        use mio::net::TcpListener;
        init_log();
        INIT.call_once(|| {
            let addr: SocketAddr = "127.0.0.1:12349".parse().unwrap();

            let listener = TcpListener::bind(addr).expect("cannot listen on port");
            let addr = listener
                .local_addr()
                .expect("error retrieving socket address");

            std::thread::spawn(move || {
                use crate::common::*;

                let versions = &[&rustls::version::TLS13];

                let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

                let ca = load_certs(&test_dir.join("fixtures").join("root-ca.pem"));
                let certs = load_certs(&test_dir.join("fixtures").join("chain.pem"));
                let privkey = load_private_key(
                    &test_dir
                        .join("fixtures")
                        .join("intermediate-server-key.pem"),
                );

                let mut client_auth_roots = rustls::RootCertStore::empty();
                for root in ca.into_iter() {
                    client_auth_roots.add(root).unwrap()
                }

                let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                    .allow_unauthenticated()
                    .build()
                    .unwrap();

                let config = rustls::ServerConfig::builder_with_protocol_versions(versions)
                    .with_client_cert_verifier(client_cert_verifier)
                    .with_single_cert(certs, privkey)
                    .unwrap();

                run_with_config(listener, config);
            });
            #[allow(static_mut_refs)]
            unsafe {
                ADDR.replace(addr)
            };
        });
        unsafe { ADDR.unwrap() }
    }

    #[tokio::test]
    async fn native_pki_verify_server_cert() {
        use latls::*;

        let addr = setup();
        let pem = include_str!("fixtures/root-ca.pem");
        let der = pem_parser::pem_to_der(pem);

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];

        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        let open_fut = tls.open(ConnectContext::new(
            &config,
            RustPkiProvider {
                rng: OsRng,
                verifier: CertVerifier::new(Certificate::X509(&der[..])),
                priv_key: None,
                client_cert: None,
            },
        ));

        open_fut.await.expect("error establishing TLS connection");

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[tokio::test]
    async fn native_pki_mutual_cert() {
        use latls::*;

        let addr = setup();
        let ca_pem = include_str!("fixtures/root-ca.pem");
        let ca_der = pem_parser::pem_to_der(ca_pem);

        let cli_pem = include_str!("fixtures/leaf-client.pem");
        let cli_der = pem_parser::pem_to_der(cli_pem);

        let key_pem = include_str!("fixtures/leaf-client-key.pem");
        let key_der = pem_parser::pem_to_der(key_pem);

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("error connecting to server");

        let mut read_record_buffer = [0; 16384];
        let mut write_record_buffer = [0; 16384];

        let config = ConnectConfig::new().with_server_name("localhost");

        let mut tls = SecureStream::new(
            FromTokio::new(stream),
            &mut read_record_buffer,
            &mut write_record_buffer,
        );

        let open_fut = tls.open(ConnectContext::new(
            &config,
            RustPkiProvider {
                rng: OsRng,
                verifier: CertVerifier::new(Certificate::X509(&ca_der[..])),
                priv_key: Some(&key_der),
                client_cert: Some(Certificate::X509(&cli_der[..])),
            },
        ));

        open_fut.await.expect("error establishing TLS connection");

        tls.close()
            .await
            .map_err(|(_, e)| e)
            .expect("error closing session");
    }

    #[cfg(feature = "rsa")]
    mod rsa_pki {
        use digest::FixedOutputReset;
        use embedded_io_adapters::tokio_1::FromTokio;
        use latls::native_pki::CertVerifier;
        use latls::{
            Aes128GcmSha256, CryptoBackend, ProtocolError as ConnectError, SignatureScheme,
            Verifier,
        };
        use rand_core::{CryptoRngCore, OsRng};
        use rsa::pkcs8::DecodePrivateKey;
        use rustls::server::WebPkiClientVerifier;
        use sha2::{Digest, Sha256};
        use signature::RandomizedSigner;
        use signature::SignerMut;
        use std::net::SocketAddr;
        use std::sync::{Arc, Once};
        use std::time::SystemTime;

        static LOG_INIT: Once = Once::new();
        static INIT: Once = Once::new();
        static mut ADDR: Option<SocketAddr> = None;

        struct RsaPssSigningKey<D: Digest, R: CryptoRngCore> {
            rng: R,
            key: rsa::pss::SigningKey<D>,
        }

        impl<D: Digest + FixedOutputReset, R: CryptoRngCore> SignerMut<Box<[u8]>>
            for RsaPssSigningKey<D, R>
        {
            fn try_sign(&mut self, msg: &[u8]) -> Result<Box<[u8]>, rsa::signature::Error> {
                let signature = self.key.try_sign_with_rng(&mut self.rng, msg)?;
                Ok(signature.into())
            }
        }

        struct RustPkiProvider<'a> {
            rng: rand::rngs::OsRng,
            verifier: CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>,
            priv_key: Option<&'a [u8]>,
            client_cert: Option<latls::Certificate<&'a [u8]>>,
        }

        impl CryptoBackend for RustPkiProvider<'_> {
            type CipherSuite = Aes128GcmSha256;
            type Signature = Box<[u8]>;

            fn rng(&mut self) -> impl latls::CryptoRngCore {
                &mut self.rng
            }

            fn verifier(&mut self) -> Result<&mut impl Verifier<Aes128GcmSha256>, ConnectError> {
                Ok(&mut self.verifier)
            }

            fn signer(
                &mut self,
            ) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), ConnectError>
            {
                let key_der = self.priv_key.ok_or(ConnectError::InvalidPrivateKey)?;
                let private_key = rsa::RsaPrivateKey::from_pkcs8_der(key_der)
                    .map_err(|_| ConnectError::InvalidPrivateKey)?;
                let signer = RsaPssSigningKey {
                    rng: &mut self.rng,
                    key: rsa::pss::SigningKey::<Sha256>::new(private_key),
                };

                Ok((signer, SignatureScheme::RsaPssRsaeSha256))
            }

            fn client_cert(&mut self) -> Option<latls::Certificate<impl AsRef<[u8]>>> {
                self.client_cert.clone()
            }
        }

        fn init_log() {
            LOG_INIT.call_once(|| {
                let _ = env_logger::try_init();
            });
        }

        fn setup() -> SocketAddr {
            use mio::net::TcpListener;
            init_log();
            INIT.call_once(|| {
                let addr: SocketAddr = "127.0.0.1:12350".parse().unwrap();

                let listener = TcpListener::bind(addr).expect("cannot listen on port");
                let addr = listener
                    .local_addr()
                    .expect("error retrieving socket address");

                std::thread::spawn(move || {
                    use crate::common::*;

                    let versions = &[&rustls::version::TLS13];

                    let test_dir =
                        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

                    let ca = load_certs(&test_dir.join("fixtures").join("rsa-root-ca.pem"));
                    let certs = load_certs(&test_dir.join("fixtures").join("rsa-leaf-server.pem"));
                    let privkey = load_private_key(
                        &test_dir.join("fixtures").join("rsa-leaf-server-key.pem"),
                    );

                    let mut client_auth_roots = rustls::RootCertStore::empty();
                    for root in ca.into_iter() {
                        client_auth_roots.add(root).unwrap()
                    }

                    let client_cert_verifier =
                        WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                            .allow_unauthenticated()
                            .build()
                            .unwrap();

                    let config = rustls::ServerConfig::builder_with_protocol_versions(versions)
                        .with_client_cert_verifier(client_cert_verifier)
                        .with_single_cert(certs, privkey)
                        .unwrap();

                    run_with_config(listener, config);
                });
                #[allow(static_mut_refs)]
                unsafe {
                    ADDR.replace(addr)
                };
            });
            unsafe { ADDR.unwrap() }
        }

        #[tokio::test]
        async fn rsa_pki_verify_and_auth() {
            use latls::*;

            let addr = setup();
            let pem = include_str!("fixtures/rsa-root-ca.pem");
            let der = pem_parser::pem_to_der(pem);

            let cli_pem = include_str!("fixtures/rsa-leaf-client.pem");
            let cli_der = pem_parser::pem_to_der(cli_pem);

            let key_pem = include_str!("fixtures/rsa-leaf-client-key.pem");
            let key_der = pem_parser::pem_to_der(key_pem);

            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("error connecting to server");

            let mut read_record_buffer = [0; 16640];
            let mut write_record_buffer = [0; 16640];

            let config = ConnectConfig::new().with_server_name("localhost");

            let mut tls = SecureStream::new(
                FromTokio::new(stream),
                &mut read_record_buffer,
                &mut write_record_buffer,
            );

            let open_fut = tls.open(ConnectContext::new(
                &config,
                RustPkiProvider {
                    rng: OsRng,
                    verifier: CertVerifier::new(Certificate::X509(&der[..])),
                    priv_key: Some(&key_der),
                    client_cert: Some(Certificate::X509(&cli_der[..])),
                },
            ));

            open_fut.await.expect("error establishing TLS connection");

            tls.close()
                .await
                .map_err(|(_, e)| e)
                .expect("error closing session");
        }
    }
}
