import socket
import sys

def main():
    port = int(sys.argv[1])
    host = "0.0.0.0"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        print(f"UDP server listening on {host}:{port}")

        while True:
            data, addr = s.recvfrom(1024)
            client_ip, client_port = addr
            print(f"Packet from {client_ip}:{client_port}: {data.decode().strip()}")
            response = f"Hello! Your IP is {client_ip}, port {client_port}\n"
            s.sendto(response.encode(), addr)

if __name__ == "__main__":
    main()
