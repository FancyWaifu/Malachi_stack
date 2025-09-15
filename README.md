I’m writing a tiny network stack in Python for learning and fun. It runs directly over Ethernet, does node discovery, and encrypts Layer-3 and above using libsodium. Might get real-world-useful later, but it’s a playground for now.

Prerequisites
1) Linux/macOS with Python 3.10+ (No idea if it works on windows)
2) Root privileges (or CAP_NET_RAW) to send raw Ethernet frames
3) libpcap (usually preinstalled; on Ubuntu: sudo apt install libpcap-dev)
4) libsodium (sudo apt install libsodium23 or libsodium & brew install libsodium)
5) pip3

Installing:
1) git clone https://github.com/FancyWaifu/Malachi_stack.git
2) cd Malachi_stack
3) python3 -m venv .venv
4) source .venv/bin/activate
5) pip3 install scapy pynacl blake3 pysodium

Starting the interactive mode:
1) Find your network interface
2) Run sudo python3 stack.py --iface *Network_interface*
3) This generate you an identity along with a signing key + public/private key
4) To regenerate a fresh idenity do: sudo python3 stack.py --iface *Network_interface* --new-identity
5) Once in the shell, type help and a list of commands will be present

Optional: Pre-Shared Key (PSK) binding for NDPv2
1) You can add a PSK to bind discovery to a shared secret:
2) echo -n "supersecret" > psk.bin
3) sudo -E python3 stack.py --iface <iface> --psk-file psk.bin
