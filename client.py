import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 55000
BUFFER_SIZE = 4096


def send_frame(sock, payload):
    data = payload.encode()
    frame = f"LEN:{len(data)}\n".encode() + data
    sock.sendall(frame)


def receive_response(sock):
    data = sock.recv(BUFFER_SIZE)
    if not data:
        print("Disconnected from server")
        return None

    text = data.decode(errors="replace").strip()
    print("Server:", text)
    return text


def main():
    token = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((SERVER_IP, SERVER_PORT))
            print(f"Connected to Seccure Authentication Server at  {SERVER_IP}:{SERVER_PORT}")
        except Exception as e:
            print("Connection failed:", e)
            return

        while True:
            print("\n========= MENU =========")
            print("1. REGISTER")
            print("2. LOGIN")
            print("3. WHOAMI (protected)")
            print("4. LOGOUT")
            print("5. RAW COMMAND")
            print("6. SPAM TEST (rate limit)")
            print("7. INVALID FRAME TEST")
            print("8. EXIT")

            choice = input("Enter choice: ").strip()

            if choice == "1":
                user = input("Username: ").strip()
                pw = input("Password: ").strip()
                send_frame(sock, f"REGISTER {user} {pw}")
                receive_response(sock)

            elif choice == "2":
                user = input("Username: ").strip()
                pw = input("Password: ").strip()
                send_frame(sock, f"LOGIN {user} {pw}")
                reply = receive_response(sock)

                if reply and "TOKEN:" in reply:
                    token = reply.split("TOKEN:")[1].strip()
                    print("Saved token:", token)

            elif choice == "3":
                if not token:
                    print("You must login first.")
                    continue
                send_frame(sock, f"WHOAMI {token}")
                receive_response(sock)

            elif choice == "4":
                if not token:
                    print("You must login first.")
                    continue
                send_frame(sock, f"LOGOUT {token}")
                receive_response(sock)
                token = None

            elif choice == "5":
                cmd = input("Enter raw command: ").strip()
                send_frame(sock, cmd)
                receive_response(sock)

            elif choice == "6":
                print("Sending 10 quick requests...")
                for i in range(10):
                    if token:
                        send_frame(sock, f"WHOAMI {token}")
                    else:
                        send_frame(sock, f"REGISTER spamuser{i} test123")
                    receive_response(sock)

            elif choice == "7":
                print("Sending invalid frame manually...")
                bad_frame = b"BADHEADER\nHELLO"
                sock.sendall(bad_frame)
                receive_response(sock)

            elif choice == "8":
                print("Exiting client...")
                break

            else:
                print("Invalid choice")


if __name__ == "__main__":
    main()
