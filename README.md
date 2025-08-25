I'm writing my own network stack in Python for educational purposes and fun. Maybe could use this for real world application but I doubt it

Prerequisites
1) Linux/macOS with Python 3.10+ (No idea if it works on windows)
2) Root privileges (or CAP_NET_RAW) to send raw Ethernet frames
3) libpcap (usually preinstalled; on Ubuntu: sudo apt install libpcap-dev)
4) pip

git clone https://github.com/FancyWaifu/Malachi_stack.git
cd Malachi_stack
python3 -m venv .venv
source .venv/bin/activate
pip3 install scapy pynacl blake3

Starting the interactive mode:
1) Find your network interface
2) Run sudo python3 stack.py --iface *Network_interface*
3) This generate you an identity along with a signing key + public/private key
4) To regenerate a fresh idenity do: sudo python3 stack.py --iface *Network_interface* --new-identity
5) Once in the shell, type help and a list of commands will be present
