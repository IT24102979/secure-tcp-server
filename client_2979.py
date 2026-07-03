import socket
import sys

HOST = "127.0.0.1"
PORT = 50979         

#  SEND a framed message using LEN:<n> protocol

def send_message(sock, message):
    """
    Frame the message and send it.
    Format:  LEN:<byte_count>\n<payload>
    Example: LEN:22\nREGISTER user1 pass1
    """
    encoded = message.encode("utf-8")          # convert string → bytes
    header  = f"LEN:{len(encoded)}\n"          # build header
    frame   = header.encode("utf-8") + encoded # join header + payload
    sock.sendall(frame)                        # sendall ensures full send


#  RECEIVE a response from the server

def receive_response(sock):
    """
    Read the server's response line by line.
    Server sends plain text ending with newline.
    """
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        if b"\n" in response:   # stop once we have a full line
            break
    return response.decode("utf-8").strip()

#  REGISTER a new user

def register(sock):
    print("\n── REGISTER ──────────────────────────")
    username = input("  Enter username : ").strip()
    password = input("  Enter password : ").strip()

    if not username or not password:
        print("  [!] Username and password cannot be empty.")
        return

    command = f"REGISTER {username} {password}"
    send_message(sock, command)

    response = receive_response(sock)
    print(f"  Server → {response}")

#  LOGIN and get a session token

def login(sock):
    print("\n── LOGIN ──────────────────────────────")
    username = input("  Enter username : ").strip()
    password = input("  Enter password : ").strip()

    if not username or not password:
        print("  [!] Username and password cannot be empty.")
        return None, None

    command = f"LOGIN {username} {password}"
    send_message(sock, command)

    response = receive_response(sock)
    print(f"  Server → {response}")

    # Try to extract the session token from the response

    token = None
    if response.startswith("OK"):
        for part in response.split():
            if part.startswith("TOKEN:"):
                token = part.split(":", 1)[1]
                print(f"  [+] Session token received: {token}")
                break
        if not token:
            print("  [i] Logged in (no token in response yet).")
        return username, token

    return None, None

#  LOGOUT

def logout(sock, token):
    print("\n── LOGOUT ─────────────────────────────")

    # Include token if we have one (protected command)
    if token:
        command = f"LOGOUT TOKEN:{token}"
    else:
        command = "LOGOUT"

    send_message(sock, command)
    response = receive_response(sock)
    print(f"  Server → {response}")
    return None, None   # clear username + token


#  SEND a custom command (for testing)

def send_custom(sock, token):
    print("\n── CUSTOM COMMAND ─────────────────────")
    command = input("  Enter command : ").strip()

    if not command:
        print("  [!] Empty command ignored.")
        return

    # Automatically attach token if logged in
    if token and "TOKEN:" not in command:
        command = f"{command} TOKEN:{token}"

    send_message(sock, command)
    response = receive_response(sock)
    print(f"  Server → {response}")



#  SEND oversized payload  

def test_oversized(sock):
    print("\n── OVERSIZED TEST ─────────────────────")
    big_payload = "X" * 5000   # 5000 bytes > 4096 limit
    print(f"  Sending {len(big_payload)} bytes (server should reject)...")
    send_message(sock, big_payload)
    response = receive_response(sock)
    print(f"  Server → {response}")

#  PRINT the status bar at the top of the menu

def print_status(username, token):
    print("\n" + "=" * 46)
    print("  IE2102 Client  |  Port 50979  |  SID:1029")
    print("=" * 46)
    if username:
        tok_display = token[:8] + "..." if token else "none"
        print(f"  Logged in as : {username}")
        print(f"  Token        : {tok_display}")
    else:
        print("  Status : not logged in")
    print("-" * 46)

#Test rate limiting++++++++++++++++++++++++++++
def test_rate_limit(sock):
    print("\n── RATE LIMIT TEST ────────────────────")
    for i in range(25):   # send 25 messages — exceeds the limit of 20
        msg = f"HELLO {i}"
        send_message(sock, msg)
        resp = receive_response(sock)
        print(f"  [{i+1}] {resp}")
        if "429" in resp:
            print("  [+] Rate limit triggered correctly!")
            break

#Test Burte-Force lockout ++++++++++++++++

def test_brute_force(sock):
    print("\n── BRUTE FORCE TEST ───────────────────")
    username = input("  Enter username to attack: ").strip()
    
    for i in range(7):
        try:
            msg = f"LOGIN {username} wrongpassword{i}"
            send_message(sock, msg)
            resp = receive_response(sock)
            print(f"  Attempt {i+1}: {resp}")
            if "423" in resp:
                print("  [+] Lockout triggered correctly!")
                break
            if "401" in resp and i >= 4:
                print(f"  [!] Expected lockout by now — check server.")
                break
        except Exception as e:
            print(f"  [!] Connection closed at attempt {i+1}: {e}")
            break





#  MAIN  – connect and show interactive menu

def main():
    print(f"Connecting to {HOST}:{PORT} ...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        sock.settimeout(10)   # 10-second timeout on reads
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {HOST}:{PORT}")
        print("    Make sure your server is running first.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Connection error: {e}")
        sys.exit(1)

    # Read the welcome message from server
    try:
        welcome = receive_response(sock)
        print(f"Server → {welcome}\n")
    except Exception:
        pass

    username = None
    token    = None

    while True:
        print_status(username, token)
        print("  1. Register")
        print("  2. Login")
        print("  3. Logout")
        print("  4. Send custom command")
        print("  5. Test oversized payload")
        print("  6. Test rate limiting")
        print("  7. Test brute-force lockout")
        print("  0. Quit")
        print("-" * 46)

        choice = input("  Choose: ").strip()

        try:
            if choice == "1":
                register(sock)

            elif choice == "2":
                username, token = login(sock)

            elif choice == "3":
                if not username:
                    print("  [!] You are not logged in.")
                else:
                    username, token = logout(sock, token)

            elif choice == "4":
                send_custom(sock, token)

            elif choice == "5":
                test_oversized(sock)

            elif choice == "6":
                test_rate_limit(sock)

            elif choice == "7":
                test_brute_force(sock)

            elif choice == "0":
                print("\n  Closing connection. Goodbye!")
                sock.close()
                sys.exit(0)

            else:
                print("  [!] Invalid choice. Enter 0-5.")

        except socket.timeout:
            print("  [!] Server did not respond in time (timeout).")
        except BrokenPipeError:
            print("  [!] Connection lost. Server may have closed.")
            break
        except Exception as e:
            print(f"  [!] Error: {e}")
            break

    sock.close()


if __name__ == "__main__":
    main()
