import socket
import threading
import time

HOST    = "127.0.0.1"
PORT    = 50979          # your port
CLIENTS = 10             # number of concurrent clients

results = []
lock    = threading.Lock()

def client_worker(client_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, PORT))

        # Read welcome message
        welcome = s.recv(1024).decode()

        # Send a REGISTER command using LEN framing
        msg    = f"REGISTER stressuser{client_id} pass{client_id}"
        header = f"LEN:{len(msg.encode())}\n"
        s.sendall((header + msg).encode())

        # Read response
        resp = s.recv(1024).decode().strip()

        with lock:
            results.append((client_id, "OK", resp))
            print(f"  Client {client_id:02d} → {resp}")

        # Stay connected for 15 seconds so ps can capture the children
        time.sleep(15)
        s.close()

    except Exception as e:
        with lock:
            results.append((client_id, "ERR", str(e)))
            print(f"  Client {client_id:02d} → ERROR: {e}")

print(f"Launching {CLIENTS} concurrent clients...")
threads = []
for i in range(CLIENTS):
    t = threading.Thread(target=client_worker, args=(i,))
    threads.append(t)
    t.start()
    time.sleep(0.1)   # tiny gap so connections don't pile up instantly

print(f"All {CLIENTS} clients connected. Sleeping 5s then checking processes...")
time.sleep(5)

print(f"\nDone. {sum(1 for r in results if r[1]=='OK')}/{CLIENTS} clients succeeded.")
for t in threads:
    t.join()
