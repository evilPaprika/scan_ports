import concurrent.futures
import socket
import struct
import time
import re


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=800) as executor:
        futures = [executor.submit(scan_tcp, port) for port in range(1000)]
        print("tcp scan started")
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if not result == None:
                pretty_print(*result)
        print("tcp scan finished")

        futures = [executor.submit(scan_udp, port) for port in range(1000)]
        print("udp scan started")
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if not result == None:
                pretty_print(*result)
        print("udp scan finished")

tcp_test_payload = [(b"GET \r\n", re.compile(b"^HTTP.+"), "http"),
                    (b"EHLO", re.compile(b"^\d{3}.+"), "smtp"),
                    (b"AUTH", re.compile(b"^\+.+"), "pop3")]

udp_test_payload = [(b'\xff\x75\x01\x00\x00\x01\x00\x00\x00\x00' \
                 b'\x00\x00\x07\x61\x76\x61\x74\x61\x72\x73' \
                 b'\x03\x6d\x64\x73\x06\x79\x61\x6e\x64\x65' \
                 b'\x78\x03\x6e\x65\x74\x00\x00\x01\x00\x01', re.compile(b"^HTTP.+"), "dns"),
                    (b"\x1b" + 47 * b"\0", re.compile(b"^.{48}$"), "sntp")]

def scan_tcp(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(0.6)
            s.connect((remote_address, port))
            for payload in tcp_test_payload:
                s.sendall(payload[0])
                try:
                    r = s.recv(100)
                    if payload[1].match(r):
                        return port, payload[2] + " " + str(r)
                    else:
                        # print(port, r) ###
                        continue
                except socket.timeout:
                    continue
        except (socket.timeout, socket.error):
            return None
        # try:
        #     receive = s.recv(100)
        # except:
        #     return (port, None)
        return port, None


def scan_udp(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        for payload in udp_test_payload:
            try:
                s.sendto(payload[0], (remote_address, port))
                r, addr = s.recvfrom(1024)
                if payload[1].match(r):
                    return (port, payload[2] + " " + str(r))
                elif addr == (remote_address, port):
                    return port, None
                else:
                    print(port, r)  ###
                    continue
            except (socket.timeout, socket.error):
                continue
        return None

def pretty_print(port, protocol = None):
    s = f"{str(port)} is open"
    if protocol:
        s += ", protocol is " + protocol
    print(s)


if __name__ == "__main__":
    remote_address = "1.1.1.1"
    main()
    # scan_udp(123)
    # print(struct.unpack())