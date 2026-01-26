#!/usr/bin/env python3
import socket
import sys

CID = int(sys.argv[1]) if len(sys.argv) > 1 else 16
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((CID, PORT))
s.sendall(b"ping")
resp = s.recv(1024)
print(resp.decode("utf-8", errors="replace"))
s.close()
