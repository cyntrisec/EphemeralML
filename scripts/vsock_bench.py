import socket
import time
import numpy as np

def run_ping_pong(cid, port, payload_size, iterations=100):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, port))
    
    latencies = []
    payload = b'a' * payload_size
    
    # Warmup
    for _ in range(10):
        s.sendall(payload_size.to_bytes(4, 'big') + payload)
        s.recv(4 + payload_size)

    for _ in range(iterations):
        start = time.perf_counter()
        s.sendall(payload_size.to_bytes(4, 'big') + payload)
        
        # Recv length
        resp_len_bytes = s.recv(4)
        resp_len = int.from_bytes(resp_len_bytes, 'big')
        
        # Recv body
        received = 0
        while received < resp_len:
            data = s.recv(min(resp_len - received, 4096))
            received += len(data)
            
        end = time.perf_counter()
        latencies.append((end - start) * 1000) # ms
        
    s.close()
    
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    avg = np.mean(latencies)
    
    print(f"Payload: {payload_size:7} B | Avg: {avg:6.3f}ms | p50: {p50:6.3f}ms | p95: {p95:6.3f}ms | p99: {p99:6.3f}ms")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python vsock_bench.py <cid> <port>")
        sys.exit(1)
        
    cid = int(sys.argv[1])
    port = int(sys.argv[2])
    
    print(f"--- VSOCK Ping-Pong Benchmark (iterations=500) ---")
    for size in [64, 1024, 64*1024, 1024*1024]:
        run_ping_pong(cid, port, size, iterations=500)
