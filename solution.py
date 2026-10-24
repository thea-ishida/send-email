import socket
import os
import sys
import time

DNS_PORT = 1053
SMTP_PORT = 1025
QTYPE_A = 1
QTYPE_MX = 15

def _valid_address(address):
    local, at, domain = address.partition('@')
    return bool(at and local and domain and '@' not in domain
                and not any(c.isspace() for c in address))

def parse_email(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except (OSError, UnicodeDecodeError):
        raise SystemExit(1)
 
    headers_text, sep, body = content.partition('\n\n')
    if not sep:
        raise SystemExit(1)
 
    headers = {}
    for line in headers_text.split('\n'):
        name, colon, value = line.strip().partition(':')
        if colon:
            headers[name] = value.strip()
 
    try:
        sender = headers['From']
        recipient = headers['To']
        subject = headers['Subject']
    except KeyError:
        raise SystemExit(1)
 
    if not (_valid_address(sender) and _valid_address(recipient)):
        raise SystemExit(1)
 
    return (sender, recipient, subject, body)


def build_dns_query(id, domain, qtype):
    try: 
        query_bytes = id.to_bytes(1, byteorder='big')
        labels = domain.rstrip('.').split('.')

        for label in labels:
            if not label:
                raise SystemExit(1)
            encoded_label = label.encode('ascii')
            query_bytes += len(encoded_label).to_bytes(1, byteorder='big') + encoded_label

        query_bytes += b'\x00'

        query_bytes += qtype.to_bytes(1, byteorder='big')
        return query_bytes
    
    except:
        raise SystemExit(1)

def send_dns_query(dns_ip, query):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3.0)
            sock.sendto(query, (dns_ip, DNS_PORT))
            response, _ = sock.recvfrom(4096)
            return response
            
    except (OSError):
        raise SystemExit(1)

def _skip_name(response, offset):
    while True:
        label_len = response[offset]
        offset += 1
        if label_len == 0:
            return offset
        offset += label_len
 

def parse_dns_response(response, expected_id, qtype):
    try:
        if not response or response[0] != expected_id:
            raise SystemExit(1)
            
        offset = _skip_name(response, 1)


        qcode = response[offset]
        offset += 1
        if qcode != 0:
            raise SystemExit(1)

        answer_length = response[offset]
        offset += 1
        answer = response[offset: offset + answer_length]

        if len(answer) != answer_length:
            raise SystemExit(1)

        if qtype == QTYPE_MX:
            labels = []
            index = 0
            while True:
                label_len = answer[index]
                index+=1 
                if label_len == 0:
                    break
                label = answer[index:index + label_len]
                if len(label) != label_len:
                    raise SystemExit(1)
                labels.append(label.decode('ascii'))
                index += label_len

            if index != answer_length or not labels:
                raise SystemExit(1)
            return ".".join(labels)
        elif qtype == QTYPE_A:
            if answer_length != 4:
                raise SystemExit(1)
            return f"{answer[0]}.{answer[1]}.{answer[2]}.{answer[3]}"
        else:
            raise SystemExit(1)
    except (IndexError, ValueError, TypeError):
        raise SystemExit(1)


def send_smtp_email(ip, sender, recipient, subject, body):
    try:
        sender_domain = sender.split('@')[1]
        
        with socket.create_connection((ip, SMTP_PORT), timeout=5.0) as sock:
            
            with sock.makefile('rw', encoding='utf-8', newline='\n') as f:

                def expect(code):
                    line = f.readline()

                    if len(line) < 3 or line[:3] != str(code):
                        raise SystemExit(1)
                
                def send_line(text):
                    f.write(text + '\n')
                    f.flush()

                expect(220)
                 
                send_line(f"HELO {sender_domain}")
                expect(250)
 
                send_line(f"MAIL FROM: {sender}")
                expect(250)
 
                send_line(f"RCPT TO: {recipient}")
                expect(250)
 
                send_line("DATA")
                expect(354)

                if body:
                    f.write(body)
                    if not body.endswith('\n'):
                        f.write('\n')
                send_line(".")
                expect(250)
 
                send_line("QUIT")
                expect(221)
                
    except (OSError, IndexError, ValueError):
        raise SystemExit(1)

if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit(1)
    file_path = sys.argv[1]
    dns_ip = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'

    sender, recipient, subject, body = parse_email(file_path)
    domain = recipient.split('@')[1]

    mx_query = build_dns_query(18, domain, QTYPE_MX)    # MX
    mx_response = send_dns_query(dns_ip, mx_query)
    mx_host = parse_dns_response(mx_response, 18, 15)

    a_query = build_dns_query(19, mx_host, QTYPE_A)     # A
    a_response = send_dns_query(dns_ip, a_query)
    ip = parse_dns_response(a_response, 19, 1)

    send_smtp_email(ip, sender, recipient, subject, body)