import socket
import os
import sys
import time

'''

UDP DNS query and the TCP SMTP connection, sys is for the command-line arguments,
 and os and time are optional extras (time could be useful for timeouts). 
 Right now only sys is used.

'''

'''
Open the file. Wrap the read in try/except OSError and raise SystemExit(1) on failure.
Split the headers from the body at the first blank line. Splitting on '\n\n' with maxsplit=1 works. If there’s no blank line, treat it as an error.
Go through the header lines and pull out the From:, To: and Subject: values. Strip the whitespace after the colon.
Validate the addresses: each must have exactly one @, with non-empty text on both sides. The template only asks for '@' to be present, but checking both sides costs nothing and catches the case "alice@".
If any header is missing or invalid, raise SystemExit(1).
Return (sender, recipient, subject, body).
'''
def parse_email(file_path):
    """
    TODO: Read file and return (sender, recipient, subject, body).
    Validate that sender and recipient include '@'.
    On any parsing/validation error, raise SystemExit(1).
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except (OSError, UnicodeDecodeError):
        raise SystemExit(1)

    print("content =", content)

    parts = content.split('\n\n', 1)
    if len(parts) != 2:
        raise SystemExit(1)
    
    headers_text, body = parts

    sender = None
    recipient = None
    subject = None

    for line in headers_text.split('\n'):
        if line.startswith('From:'):
            sender = line[5:].strip()
        elif line.startswith('To:'):
            recipient = line[3:].strip()
        elif line.startswith('Subject:'):
            subject = line[8:].strip()

    if sender is None or recipient is None or subject is None:
        raise SystemExit(1)

    # Validate the addresses: exactly one @, with non-empty text on both sides
    for address in (sender, recipient):
        if address.count('@') != 1:
            raise SystemExit(1)
        
        local_part, domain_part = address.split('@')
        if not local_part or not domain_part:
            raise SystemExit(1)

    return (sender, recipient, subject, body)


    

def build_dns_query(id, domain, qtype):
    """
    TODO: Build bytes: ID(1) + QNAME + QTYPE(1)
    QNAME = label_len(1) + label_bytes ... + 0x00
    """
    query_bytes = id.to_bytes(1, byteorder='big')
    
    # 2. Construct the QNAME
    # Split the domain by dots and encode each label with its length prefix
    for label in domain.split('.'):
        encoded_label = label.encode('ascii')
        # Add the 1-byte length of the label, followed by the ASCII bytes
        query_bytes += len(encoded_label).to_bytes(1, byteorder='big') + encoded_label
        
    # Terminate the QNAME with a 0x00 byte
    query_bytes += b'\x00'
    
    # 3. Add the 1-byte QTYPE
    query_bytes += qtype.to_bytes(1, byteorder='big')
    
    return query_bytes

def send_dns_query(dns_ip, query):
    """
    TODO: Send UDP to (dns_ip, 1053), return response bytes (use timeout).
    On error or timeout, raise SystemExit(1).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Set a timeout for the socket operations (e.g., 3 seconds)
            sock.settimeout(3.0)
            
            # Send the query to the specified DNS IP on port 1053
            sock.sendto(query, (dns_ip, 1053))
            
            # Receive the response (4096 bytes is more than enough for a DNS packet)
            response, _ = sock.recvfrom(4096)
            
            return response
            
    except (OSError):
        # On any socket error or timeout, raise SystemExit(1)
        raise SystemExit(1)

def parse_dns_response(response, expected_id, qtype):
    """
    TODO: Validate response[0] == expected_id, parse QNAME echo,
    read QCODE (0 success / 1 error), then ANSWER_LEN(1) and ANSWER.
    For MX (qtype=15): ANSWER is label-encoded hostname ending with 0x00.
    For A  (qtype=1):  ANSWER is 4 bytes IPv4. Return 'a.b.c.d'.
    On any error, raise SystemExit(1).
    """
    try:
        # Validate ID[cite: 1, 2]
        if not response or response[0] != expected_id:
            raise SystemExit(1)
            
        offset = 1
        
        # Parse and skip QNAME echo[cite: 1, 2]
        while True:
            label_len = response[offset]
            offset += 1
            if label_len == 0:
                break
            offset += label_len
            
        # Read QCODE[cite: 1, 2]
        qcode = response[offset]
        offset += 1
        
        if qcode != 0:
            raise SystemExit(1)
            
        # Read ANSWER_LEN[cite: 1, 2]
        ans_len = response[offset]
        offset += 1
        
        # Parse ANSWER based on QTYPE[cite: 1]
        if qtype == 15:  # MX
            labels = []
            while True:
                label_len = response[offset]
                offset += 1
                if label_len == 0:
                    break
                labels.append(response[offset:offset+label_len].decode('ascii'))
                offset += label_len
            return ".".join(labels)
            
        elif qtype == 1:  # A
            ip_bytes = response[offset:offset+4]
            if len(ip_bytes) != 4:
                raise SystemExit(1)
            return f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
            
        else:
            raise SystemExit(1)
            
    except (IndexError, ValueError, AttributeError, UnicodeDecodeError):
        # On any parsing error, raise SystemExit(1)
        raise SystemExit(1)

def send_smtp_email(ip, sender, recipient, subject, body):
    """
    TODO: Connect TCP to (ip, 1025). Exchange lines with '\\n' endings:
    - read '220 ...'
    - send 'HELO <send_domain>'
    - 'MAIL FROM: <sender>'
    - 'RCPT TO: <recipient>'
    - 'DATA' then body, '.', expect '250'
    - 'QUIT', expect '221'
    On any error, raise SystemExit(1).
    """
    raise NotImplementedError

if __name__ == '__main__':
    # Accept either: script email_file  OR script email_file dns_ip

    if len(sys.argv) not in (2, 3):
        raise SystemExit(1)
    file_path = sys.argv[1]
    dns_ip = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'

    sender, recipient, subject, body = parse_email(file_path)
    domain = recipient.split('@')[1]

    # mx_query = build_dns_query(18, domain, 15)    # MX
    # mx_response = send_dns_query(dns_ip, mx_query)
    # mx_host = parse_dns_response(mx_response, 18, 15)

    # a_query = build_dns_query(19, mx_host, 1)     # A
    # a_response = send_dns_query(dns_ip, a_query)
    # ip = parse_dns_response(a_response, 19, 1)

    # send_smtp_email(ip, sender, recipient, subject, body)