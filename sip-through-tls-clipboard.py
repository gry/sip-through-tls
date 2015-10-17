#!/usr/bin/env python

from __future__ import with_statement
from __future__ import print_function
from scapy_ssl_tls.ssl_tls import *
import pyperclip

tls_version = TLSVersion.TLS_1_1


def tls_hello(sock):
    client_hello = TLSRecord(version=tls_version) / \
                   TLSHandshake() / \
                   TLSClientHello(version=tls_version,
                                  compression_methods=(
                                      TLSCompressionMethod.NULL),
                                  # cipher_suites=(TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA))
                                  # cipher_suites=(TLSCipherSuite.RSA_WITH_RC4_128_SHA))
                                  cipher_suites=(
                                      TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA))
                                  # cipher_suites=(TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA))
    sock.sendall(client_hello)
    server_hello = sock.recvall()
    # server_hello.show()


def tls_client_key_exchange(sock):
    client_key_exchange = TLSRecord(version=tls_version) / TLSHandshake() / TLSClientKeyExchange(
        data=sock.tls_ctx.get_client_kex_data())
    client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
    sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
    sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
    server_finished = sock.recvall()
    # server_finished.show()


def parse2sip(text):
    # 1. rid out of any \r\n or similar and last white lines
    lines_list = text.strip().splitlines()

    # 2. rid out of initial spaces
    lines_list = [re.sub(r'^[\b\t]+', '', line) for line in lines_list]
    lines_list.append('')
    lines_list.append('')

    # 3. Join with \r\n
    return '\r\n'.join(lines_list)


def main():
    if len(sys.argv) != 3:
        print('Usage: %s <SIP_IP> <SIP_Port>' % (sys.argv[0]))
        sys.exit(1)
    target = (sys.argv[1], int(sys.argv[2]))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(target)
    sock = TLSSocket(sock, client=True)
    tls_hello(sock)
    tls_client_key_exchange(sock)
    # Handshake Finished

    # Get sip packet from clipboard :D
    clipboard = pyperclip.paste()

    # Prepare SIP Plaintext packet
    sip = str(parse2sip(clipboard))
    print(sip)

    sock.sendall(to_raw(TLSPlaintext(data=sip), sock.tls_ctx))

    resp = sock.recvall()

    # Print received responses
    for rec in resp.fields['records']:
        if rec.haslayer(TLSPlaintext):
            print(rec.getlayer(TLSPlaintext).data)


if __name__ == '__main__':
    main()
