use std::{io, net::SocketAddr};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};
use reach_core::{DnsAttemptResult, DnsQueryType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::PlatformError;

pub(crate) fn build_query(
    message_id: u16,
    query_name: &str,
    query_type: DnsQueryType,
) -> Result<Message, PlatformError> {
    let name = Name::from_ascii(query_name)
        .map_err(|error| PlatformError::InvalidDnsQueryName(error.to_string()))?;
    let record_type = match query_type {
        DnsQueryType::A => RecordType::A,
        DnsQueryType::Aaaa => RecordType::AAAA,
    };
    let mut message = Message::new(message_id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    Ok(message)
}

pub(crate) async fn udp_exchange(
    resolver: SocketAddr,
    wire: &[u8],
    query: &Message,
    cancellation: &CancellationToken,
) -> Result<DnsAttemptResult, PlatformError> {
    let bind_address = if resolver.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = match tokio::net::UdpSocket::bind(bind_address).await {
        Ok(socket) => socket,
        Err(error) => return transport_error(error),
    };
    if let Err(error) = socket.connect(resolver).await {
        return transport_error(error);
    }
    if let Err(error) = socket.send(wire).await {
        return transport_error(error);
    }

    let mut buffer = vec![0_u8; 65_535];
    loop {
        let received = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(PlatformError::OperationCancelled),
            result = socket.recv(&mut buffer) => result,
        };
        let length = match received {
            Ok(length) => length,
            Err(error) => return transport_error(error),
        };
        let response = match Message::from_vec(&buffer[..length]) {
            Ok(response) => response,
            Err(_) => return Ok(DnsAttemptResult::ProtocolError),
        };
        if response.metadata.id != query.metadata.id {
            continue;
        }
        return Ok(parse_correlated_response(response, query));
    }
}

pub(crate) async fn tcp_exchange(
    resolver: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> Result<DnsAttemptResult, PlatformError> {
    let mut stream = match tokio::net::TcpStream::connect(resolver).await {
        Ok(stream) => stream,
        Err(error) => return transport_error(error),
    };
    let length = match u16::try_from(wire.len()) {
        Ok(length) => length,
        Err(_) => return Ok(DnsAttemptResult::ProtocolError),
    };
    if let Err(error) = stream.write_all(&length.to_be_bytes()).await {
        return transport_error(error);
    }
    if let Err(error) = stream.write_all(wire).await {
        return transport_error(error);
    }
    let mut length_prefix = [0_u8; 2];
    if let Err(error) = stream.read_exact(&mut length_prefix).await {
        return transport_error(error);
    }
    let response_length = usize::from(u16::from_be_bytes(length_prefix));
    let mut response_wire = vec![0_u8; response_length];
    if let Err(error) = stream.read_exact(&mut response_wire).await {
        return transport_error(error);
    }
    let response = match Message::from_vec(&response_wire) {
        Ok(response) => response,
        Err(_) => return Ok(DnsAttemptResult::ProtocolError),
    };
    Ok(parse_correlated_response(response, query))
}

pub(crate) fn parse_correlated_response(response: Message, query: &Message) -> DnsAttemptResult {
    if response.metadata.id != query.metadata.id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.queries != query.queries
    {
        return DnsAttemptResult::ProtocolError;
    }

    let mut addresses = Vec::new();
    let mut aliases = Vec::new();
    for record in &response.answers {
        match &record.data {
            RData::A(address) => addresses.push(std::net::IpAddr::V4(address.0)),
            RData::AAAA(address) => addresses.push(std::net::IpAddr::V6(address.0)),
            RData::CNAME(name) => aliases.push(name.to_string()),
            _ => {}
        }
    }
    DnsAttemptResult::Response {
        response_code: response.metadata.response_code.into(),
        addresses,
        aliases,
        truncated: response.metadata.truncation,
    }
}

fn transport_error(error: io::Error) -> Result<DnsAttemptResult, PlatformError> {
    if crate::is_resource_exhaustion(&error) {
        Err(PlatformError::ResourceExhausted(error.to_string()))
    } else if error.kind() == io::ErrorKind::TimedOut {
        Ok(DnsAttemptResult::Timeout)
    } else {
        Ok(DnsAttemptResult::TransportError {
            os_code: error.raw_os_error(),
        })
    }
}
