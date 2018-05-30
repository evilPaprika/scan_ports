import argparse
import concurrent.futures
import socket
import re
import time


def main(begin, end):
    with concurrent.futures.ThreadPoolExecutor(max_workers=800) as executor:
        futures = [executor.submit(scan_tcp, port) for port in range(begin, end)]
        print("\ntcp scan started")
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if not result == None:
                pretty_print(*result)
        print("tcp scan finished\n")

        futures = [executor.submit(scan_udp, port) for port in range(begin, end)]
        print("udp scan started")
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if not result == None:
                pretty_print(*result)
        print("udp scan finished")


dns_query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00' \
            b'\x00\x00\x07\x61\x76\x61\x74\x61\x72\x73' \
            b'\x03\x6d\x64\x73\x06\x79\x61\x6e\x64\x65' \
            b'\x78\x03\x6e\x65\x74\x00\x00\x01\x00\x01'

tcp_test_payload = [(b'GET \r\n', re.compile(b'^HTTP.+'), 'http'),
                    (b'\x00(' + dns_query, re.compile(b'^.{2}\x00\x00.+$'), 'dns'),
                    (b'EHLO', re.compile(b'^\d{3}.+'), 'smtp'),
                    (b'AUTH', re.compile(b'^\+.+'), 'pop3')]

udp_test_payload = [(dns_query, re.compile(b'^\x00\x00.+$'), 'dns'),
                    (b"\x1b" + 47 * b"\0", re.compile(b'^.{48}$'), 'sntp')]


def scan_tcp(port):
    for payload in tcp_test_payload:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                try:
                    s.settimeout(1)
                    s.connect((remote_address, port))
                except (socket.timeout, socket.error):
                    return None
                s.sendall(payload[0])
                r = s.recv(100)
                if payload[1].match(r):
                    return port, payload[2]
                else:
                    continue
            except (socket.timeout, socket.error):
                continue
    return port, None


def scan_udp(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        flag = False
        for payload in udp_test_payload:
            try:
                s.sendto(payload[0], (remote_address, port))
                r, addr = s.recvfrom(1024)
                if payload[1].match(r):
                    return port, payload[2]
                elif addr == (remote_address, port):
                    flag = True
                    continue
                else:
                    continue
            except (socket.timeout, socket.error):
                continue
        if flag:
            return port, None
        return None


def pretty_print(port, protocol=None):
    s = f"{str(port)} is open"
    if protocol:
        s += ", protocol is " + protocol
    print(s)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='скатирование портов tcp/udp')
    parser.add_argument('host', type=str, help='удаленный хост')
    parser.add_argument('begin', type=int, help='начало диапазона')
    parser.add_argument('end', type=int, help='конец диапазона')
    args = parser.parse_args()
    if args.end > 2 ** 16 and args.end > args.begin and args.begin >= 0:
        print("bad range")
        exit(1)
    remote_address = args.host
    main(args.begin, args.end)
