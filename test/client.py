import socket
import sys

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"ping\n", (host, port))
        s.settimeout(5)
        try:
            data, _ = s.recvfrom(1024)
            print(f"Response received: {data.decode().strip()}")
        except socket.timeout:
            print("No response (timeout) - expected if reply routing is not set up")

if __name__ == "__main__":
    main()
