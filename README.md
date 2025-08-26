I'm writing my own network stack in Python for educational purposes and fun. Maybe could use this for real world application but I doubt it
Still have a lot to work on with this project

Prerequisites
1) Linux/macOS with Python 3.10+ (No idea if it works on windows)
2) Root privileges (or CAP_NET_RAW) to send raw Ethernet frames
3) libpcap (usually preinstalled; on Ubuntu: sudo apt install libpcap-dev)
4) pip3

Installing:
1) git clone https://github.com/FancyWaifu/Malachi_stack.git
2) cd Malachi_stack
3) python3 -m venv .venv
4) source .venv/bin/activate
5) pip3 install scapy pynacl blake3

Starting the interactive mode:
1) Find your network interface
2) Run sudo python3 stack.py --iface *Network_interface*
3) This generate you an identity along with a signing key + public/private key
4) To regenerate a fresh idenity do: sudo python3 stack.py --iface *Network_interface* --new-identity
5) Once in the shell, type help and a list of commands will be present
