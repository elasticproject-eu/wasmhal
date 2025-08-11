// Socket interface implementation - Requirement 1

use crate::error::{HalError, HalResult};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use rustls::{ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::atomic::{AtomicU64, Ordering};

/// Socket handle type
pub type SocketHandle = u64;

/// Socket interface for network communication
#[derive(Debug)]
pub struct SocketInterface {
    sockets: Arc<RwLock<HashMap<SocketHandle, SocketWrapper>>>,
    next_handle: AtomicU64,
    tls_config: Arc<RwLock<TlsConfiguration>>,
}

/// Socket wrapper to handle different socket types
#[derive(Debug)]
enum SocketWrapper {
    TcpListener(TcpListener),
    TcpStream(TcpStream),
    TlsStream(TlsStream<TcpStream>),
    UdpSocket(UdpSocket),
    // DTLS would require additional implementation
}

/// TLS configuration storage
#[derive(Debug, Default)]
struct TlsConfiguration {
    server_configs: HashMap<String, Arc<ServerConfig>>,
    client_configs: HashMap<String, Arc<ClientConfig>>,
    certificates: HashMap<String, CertificateDer<'static>>,
    private_keys: HashMap<String, PrivateKeyDer<'static>>,
}

/// Socket operation result
#[derive(Debug)]
pub struct SocketResult {
    pub bytes_transferred: usize,
    pub peer_address: Option<SocketAddr>,
}

impl SocketInterface {
    /// Create a new socket interface
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
            next_handle: AtomicU64::new(1),
            tls_config: Arc::new(RwLock::new(TlsConfiguration::default())),
        }
    }

    /// Create a TCP socket and bind to address
    pub async fn create_tcp_socket(&self, bind_addr: &str) -> HalResult<SocketHandle> {
        let addr = bind_addr.to_socket_addrs()
            .map_err(|e| HalError::NetworkError(format!("Invalid address: {}", e)))?
            .next()
            .ok_or_else(|| HalError::NetworkError("Failed to resolve address".to_string()))?;

        let listener = TcpListener::bind(addr).await
            .map_err(|e| HalError::NetworkError(format!("Failed to bind TCP socket: {}", e)))?;

        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut sockets = self.sockets.write().await;
        sockets.insert(handle, SocketWrapper::TcpListener(listener));

        Ok(handle)
    }

    /// Connect to a TCP server
    pub async fn tcp_connect(&self, server_addr: &str) -> HalResult<SocketHandle> {
        let addr = server_addr.to_socket_addrs()
            .map_err(|e| HalError::NetworkError(format!("Invalid address: {}", e)))?
            .next()
            .ok_or_else(|| HalError::NetworkError("Failed to resolve address".to_string()))?;

        let stream = TcpStream::connect(addr).await
            .map_err(|e| HalError::NetworkError(format!("Failed to connect: {}", e)))?;

        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut sockets = self.sockets.write().await;
        sockets.insert(handle, SocketWrapper::TcpStream(stream));

        Ok(handle)
    }

    /// Accept incoming TCP connection
    pub async fn tcp_accept(&self, listener_handle: SocketHandle) -> HalResult<SocketHandle> {
        let mut sockets = self.sockets.write().await;
        
        if let Some(SocketWrapper::TcpListener(listener)) = sockets.get_mut(&listener_handle) {
            let (stream, _addr) = listener.accept().await
                .map_err(|e| HalError::NetworkError(format!("Failed to accept connection: {}", e)))?;

            let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
            sockets.insert(handle, SocketWrapper::TcpStream(stream));
            
            Ok(handle)
        } else {
            Err(HalError::NotFound("TCP listener not found".to_string()))
        }
    }

    /// Create a UDP socket
    pub async fn create_udp_socket(&self, bind_addr: &str) -> HalResult<SocketHandle> {
        let addr = bind_addr.to_socket_addrs()
            .map_err(|e| HalError::NetworkError(format!("Invalid address: {}", e)))?
            .next()
            .ok_or_else(|| HalError::NetworkError("Failed to resolve address".to_string()))?;

        let socket = UdpSocket::bind(addr).await
            .map_err(|e| HalError::NetworkError(format!("Failed to bind UDP socket: {}", e)))?;

        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut sockets = self.sockets.write().await;
        sockets.insert(handle, SocketWrapper::UdpSocket(socket));

        Ok(handle)
    }

    /// Read data from socket (async)
    pub async fn socket_read(&self, handle: SocketHandle, buffer: &mut [u8]) -> HalResult<SocketResult> {
        use tokio::io::AsyncReadExt;
        
        let mut sockets = self.sockets.write().await;
        
        match sockets.get_mut(&handle) {
            Some(SocketWrapper::TcpStream(stream)) => {
                let bytes_read = stream.read(buffer).await
                    .map_err(|e| HalError::NetworkError(format!("TCP read failed: {}", e)))?;
                
                let peer_addr = stream.peer_addr().ok();
                Ok(SocketResult {
                    bytes_transferred: bytes_read,
                    peer_address: peer_addr,
                })
            }
            Some(SocketWrapper::TlsStream(stream)) => {
                let bytes_read = stream.read(buffer).await
                    .map_err(|e| HalError::NetworkError(format!("TLS read failed: {}", e)))?;
                
                let peer_addr = stream.get_ref().0.peer_addr().ok();
                Ok(SocketResult {
                    bytes_transferred: bytes_read,
                    peer_address: peer_addr,
                })
            }
            Some(SocketWrapper::UdpSocket(socket)) => {
                let (bytes_read, peer_addr) = socket.recv_from(buffer).await
                    .map_err(|e| HalError::NetworkError(format!("UDP recv failed: {}", e)))?;
                
                Ok(SocketResult {
                    bytes_transferred: bytes_read,
                    peer_address: Some(peer_addr),
                })
            }
            _ => Err(HalError::NotFound("Socket not found or invalid type".to_string())),
        }
    }

    /// Write data to socket (async)
    pub async fn socket_write(&self, handle: SocketHandle, data: &[u8]) -> HalResult<SocketResult> {
        use tokio::io::AsyncWriteExt;
        
        let mut sockets = self.sockets.write().await;
        
        match sockets.get_mut(&handle) {
            Some(SocketWrapper::TcpStream(stream)) => {
                stream.write_all(data).await
                    .map_err(|e| HalError::NetworkError(format!("TCP write failed: {}", e)))?;
                
                let peer_addr = stream.peer_addr().ok();
                Ok(SocketResult {
                    bytes_transferred: data.len(),
                    peer_address: peer_addr,
                })
            }
            Some(SocketWrapper::TlsStream(stream)) => {
                stream.write_all(data).await
                    .map_err(|e| HalError::NetworkError(format!("TLS write failed: {}", e)))?;
                
                let peer_addr = stream.get_ref().0.peer_addr().ok();
                Ok(SocketResult {
                    bytes_transferred: data.len(),
                    peer_address: peer_addr,
                })
            }
            _ => Err(HalError::NotFound("Socket not found or invalid type for write".to_string())),
        }
    }

    /// Send UDP data to specific address
    pub async fn udp_send_to(
        &self,
        handle: SocketHandle,
        data: &[u8],
        target_addr: &str,
    ) -> HalResult<SocketResult> {
        let addr = target_addr.to_socket_addrs()
            .map_err(|e| HalError::NetworkError(format!("Invalid target address: {}", e)))?
            .next()
            .ok_or_else(|| HalError::NetworkError("Failed to resolve target address".to_string()))?;

        let mut sockets = self.sockets.write().await;
        
        if let Some(SocketWrapper::UdpSocket(socket)) = sockets.get_mut(&handle) {
            let bytes_sent = socket.send_to(data, addr).await
                .map_err(|e| HalError::NetworkError(format!("UDP send failed: {}", e)))?;
            
            Ok(SocketResult {
                bytes_transferred: bytes_sent,
                peer_address: Some(addr),
            })
        } else {
            Err(HalError::NotFound("UDP socket not found".to_string()))
        }
    }

    /// Create TLS client connection
    pub async fn create_tls_client(
        &self,
        server_addr: &str,
        server_name: &str,
        config_name: Option<&str>,
    ) -> HalResult<SocketHandle> {
        // Connect TCP first
        let tcp_stream = {
            let addr = server_addr.to_socket_addrs()
                .map_err(|e| HalError::NetworkError(format!("Invalid address: {}", e)))?
                .next()
                .ok_or_else(|| HalError::NetworkError("Failed to resolve address".to_string()))?;

            TcpStream::connect(addr).await
                .map_err(|e| HalError::NetworkError(format!("Failed to connect: {}", e)))?
        };

        // Get TLS client config
        let tls_config = self.tls_config.read().await;
        let client_config = if let Some(config_name) = config_name {
            tls_config.client_configs.get(config_name)
                .ok_or_else(|| HalError::NotFound(format!("TLS client config '{}' not found", config_name)))?
                .clone()
        } else {
            // Create default client config
            Arc::new(self.create_default_client_config()?)
        };

        // Establish TLS connection
        let connector = TlsConnector::from(client_config);
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| HalError::NetworkError(format!("Invalid server name: {}", e)))?;

        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| HalError::NetworkError(format!("TLS handshake failed: {}", e)))?;

        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut sockets = self.sockets.write().await;
        sockets.insert(handle, SocketWrapper::TlsStream(tokio_rustls::TlsStream::Client(tls_stream)));

        Ok(handle)
    }

    /// Create TLS server socket
    pub async fn create_tls_server(
        &self,
        bind_addr: &str,
        config_name: &str,
    ) -> HalResult<SocketHandle> {
        // Create TCP listener first
        let tcp_handle = self.create_tcp_socket(bind_addr).await?;
        
        // Store server config name for later use during accept
        // In a real implementation, you might want to store this mapping
        
        Ok(tcp_handle)
    }

    /// Accept TLS connection
    pub async fn tls_accept(
        &self,
        listener_handle: SocketHandle,
        config_name: &str,
    ) -> HalResult<SocketHandle> {
        // Accept TCP connection first
        let tcp_handle = self.tcp_accept(listener_handle).await?;
        
        // Get the TCP stream and upgrade to TLS
        let tcp_stream = {
            let mut sockets = self.sockets.write().await;
            if let Some(SocketWrapper::TcpStream(stream)) = sockets.remove(&tcp_handle) {
                stream
            } else {
                return Err(HalError::Internal("Failed to retrieve TCP stream".to_string()));
            }
        };

        // Get TLS server config
        let tls_config = self.tls_config.read().await;
        let server_config = tls_config.server_configs.get(config_name)
            .ok_or_else(|| HalError::NotFound(format!("TLS server config '{}' not found", config_name)))?
            .clone();

        // Establish TLS connection
        let acceptor = TlsAcceptor::from(server_config);
        let tls_stream = acceptor.accept(tcp_stream).await
            .map_err(|e| HalError::NetworkError(format!("TLS accept failed: {}", e)))?;

        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut sockets = self.sockets.write().await;
        sockets.insert(handle, SocketWrapper::TlsStream(tokio_rustls::TlsStream::Server(tls_stream)));

        Ok(handle)
    }

    /// Write server/client key context (PKCS12)
    pub async fn write_key_context(
        &self,
        context_name: &str,
        pkcs12_data: &[u8],
        password: &str,
        is_server: bool,
    ) -> HalResult<()> {
        // Parse PKCS12 data
        let (cert_chain, private_key) = self.parse_pkcs12(pkcs12_data, password)?;

        let mut tls_config = self.tls_config.write().await;

        // Store certificate and key
        if let Some(cert) = cert_chain.first() {
            tls_config.certificates.insert(context_name.to_string(), cert.clone());
        }
        tls_config.private_keys.insert(context_name.to_string(), private_key.clone_key());

        if is_server {
            // Create server config
            let mut server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| HalError::CryptographicError(format!("Invalid server certificate: {}", e)))?;

            // Enable ALPN if needed
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            tls_config.server_configs.insert(context_name.to_string(), Arc::new(server_config));
        } else {
            // Create client config with certificate
            let mut client_config = ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| HalError::CryptographicError(format!("Invalid client certificate: {}", e)))?;

            // Enable ALPN if needed
            client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            tls_config.client_configs.insert(context_name.to_string(), Arc::new(client_config));
        }

        Ok(())
    }

    /// Close socket
    pub async fn close_socket(&self, handle: SocketHandle) -> HalResult<()> {
        let mut sockets = self.sockets.write().await;
        sockets.remove(&handle);
        Ok(())
    }

    /// Get socket information
    pub async fn get_socket_info(&self, handle: SocketHandle) -> HalResult<SocketInfo> {
        let sockets = self.sockets.read().await;
        
        match sockets.get(&handle) {
            Some(SocketWrapper::TcpListener(listener)) => {
                let local_addr = listener.local_addr()
                    .map_err(|e| HalError::NetworkError(format!("Failed to get local address: {}", e)))?;
                
                Ok(SocketInfo {
                    socket_type: "TCP_LISTENER".to_string(),
                    local_address: Some(local_addr),
                    peer_address: None,
                    is_secure: false,
                })
            }
            Some(SocketWrapper::TcpStream(stream)) => {
                let local_addr = stream.local_addr().ok();
                let peer_addr = stream.peer_addr().ok();
                
                Ok(SocketInfo {
                    socket_type: "TCP_STREAM".to_string(),
                    local_address: local_addr,
                    peer_address: peer_addr,
                    is_secure: false,
                })
            }
            Some(SocketWrapper::TlsStream(stream)) => {
                let local_addr = stream.get_ref().0.local_addr().ok();
                let peer_addr = stream.get_ref().0.peer_addr().ok();
                
                Ok(SocketInfo {
                    socket_type: "TLS_STREAM".to_string(),
                    local_address: local_addr,
                    peer_address: peer_addr,
                    is_secure: true,
                })
            }
            Some(SocketWrapper::UdpSocket(socket)) => {
                let local_addr = socket.local_addr()
                    .map_err(|e| HalError::NetworkError(format!("Failed to get local address: {}", e)))?;
                
                Ok(SocketInfo {
                    socket_type: "UDP_SOCKET".to_string(),
                    local_address: Some(local_addr),
                    peer_address: None,
                    is_secure: false,
                })
            }
            None => Err(HalError::NotFound("Socket not found".to_string())),
        }
    }

    // Private helper methods

    fn create_default_client_config(&self) -> HalResult<ClientConfig> {
        let config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        Ok(config)
    }

    fn parse_pkcs12(&self, pkcs12_data: &[u8], password: &str) -> HalResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // In a real implementation, this would parse actual PKCS12 data
        // For now, we'll simulate with placeholder data
        
        if pkcs12_data.is_empty() {
            return Err(HalError::CryptographicError("Empty PKCS12 data".to_string()));
        }

        // Simulate certificate and key extraction
        let cert = CertificateDer::from(vec![0x30, 0x82]); // Placeholder DER certificate
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x30, 0x82])); // Placeholder DER private key

        Ok((vec![cert], key))
    }
}

/// Socket information structure
#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub socket_type: String,
    pub local_address: Option<SocketAddr>,
    pub peer_address: Option<SocketAddr>,
    pub is_secure: bool,
}

impl Default for SocketInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_tcp_socket_creation() {
        let socket_interface = SocketInterface::new();
        
        let handle = socket_interface.create_tcp_socket("127.0.0.1:0").await.unwrap();
        assert!(handle > 0);

        let info = socket_interface.get_socket_info(handle).await.unwrap();
        assert_eq!(info.socket_type, "TCP_LISTENER");
        assert!(info.local_address.is_some());
    }

    #[tokio::test]
    async fn test_udp_socket_creation() {
        let socket_interface = SocketInterface::new();
        
        let handle = socket_interface.create_udp_socket("127.0.0.1:0").await.unwrap();
        assert!(handle > 0);

        let info = socket_interface.get_socket_info(handle).await.unwrap();
        assert_eq!(info.socket_type, "UDP_SOCKET");
        assert!(info.local_address.is_some());
    }

    #[tokio::test]
    async fn test_tcp_connection() {
        let socket_interface = SocketInterface::new();
        
        // Create listener
        let listener_handle = socket_interface.create_tcp_socket("127.0.0.1:0").await.unwrap();
        let listener_info = socket_interface.get_socket_info(listener_handle).await.unwrap();
        let listen_addr = listener_info.local_address.unwrap();

        // Connect in background task
        let socket_interface_clone = Arc::new(socket_interface);
        let connect_task = {
            let socket_interface = socket_interface_clone.clone();
            let addr = format!("127.0.0.1:{}", listen_addr.port());
            tokio::spawn(async move {
                socket_interface.tcp_connect(&addr).await
            })
        };

        // Accept connection
        let accept_result = timeout(
            Duration::from_secs(1),
            socket_interface_clone.tcp_accept(listener_handle)
        ).await;

        let accept_handle = accept_result
            .expect("Accept timeout")
            .expect("Accept failed");

        let connect_handle = connect_task.await
            .expect("Connect task failed")
            .expect("Connect failed");

        // Verify both handles are valid
        assert!(accept_handle > 0);
        assert!(connect_handle > 0);
        assert_ne!(accept_handle, connect_handle);
    }

    #[tokio::test]
    async fn test_udp_send_recv() {
        let socket_interface = SocketInterface::new();
        
        // Create two UDP sockets
        let socket1 = socket_interface.create_udp_socket("127.0.0.1:0").await.unwrap();
        let socket2 = socket_interface.create_udp_socket("127.0.0.1:0").await.unwrap();

        // Get addresses
        let info1 = socket_interface.get_socket_info(socket1).await.unwrap();
        let info2 = socket_interface.get_socket_info(socket2).await.unwrap();
        
        let addr1 = info1.local_address.unwrap();
        let addr2 = info2.local_address.unwrap();

        // Send data from socket1 to socket2
        let test_data = b"Hello UDP";
        let send_result = socket_interface.udp_send_to(
            socket1,
            test_data,
            &addr2.to_string()
        ).await.unwrap();

        assert_eq!(send_result.bytes_transferred, test_data.len());

        // Receive data on socket2
        let mut buffer = [0u8; 1024];
        let recv_result = socket_interface.socket_read(socket2, &mut buffer).await.unwrap();

        assert_eq!(recv_result.bytes_transferred, test_data.len());
        assert_eq!(&buffer[..recv_result.bytes_transferred], test_data);
        assert_eq!(recv_result.peer_address.unwrap(), addr1);
    }

    #[tokio::test]
    async fn test_socket_closure() {
        let socket_interface = SocketInterface::new();
        
        let handle = socket_interface.create_tcp_socket("127.0.0.1:0").await.unwrap();
        
        // Socket should exist
        assert!(socket_interface.get_socket_info(handle).await.is_ok());
        
        // Close socket
        socket_interface.close_socket(handle).await.unwrap();
        
        // Socket should no longer exist
        assert!(socket_interface.get_socket_info(handle).await.is_err());
    }

    #[tokio::test]
    async fn test_invalid_socket_operations() {
        let socket_interface = SocketInterface::new();
        
        // Try to use non-existent socket
        let mut buffer = [0u8; 100];
        let result = socket_interface.socket_read(999, &mut buffer).await;
        assert!(result.is_err());

        let result = socket_interface.socket_write(999, b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_key_context_operations() {
        let socket_interface = SocketInterface::new();
        
        // Test writing key context (with placeholder PKCS12 data)
        let pkcs12_data = b"placeholder_pkcs12_data";
        let result = socket_interface.write_key_context(
            "test_server",
            pkcs12_data,
            "password",
            true
        ).await;

        // Should not fail even with placeholder data (in real implementation, 
        // this would parse actual PKCS12)
        assert!(result.is_ok());
    }
}
