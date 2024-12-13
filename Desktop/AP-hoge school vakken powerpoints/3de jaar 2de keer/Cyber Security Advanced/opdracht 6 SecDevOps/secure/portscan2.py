import socket

def scan_ports(host, startport = 1, endport = 1024):
    open_ports=[]
    for port in range(startport, endport +1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a connection timeout

        result = sock.connect_ex((host, port))

        if result == 0:
            open_ports.append(port)
            print(f"Port {port} is open")
    return open_ports