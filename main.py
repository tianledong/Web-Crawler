import socket
import sys
import re

queue = []
visited_urls = {}
flags = []

LOGIN_URL = "http://webcrawler-site.ccs.neu.edu/accounts/login/?next=/fakebook/"
HOST = "webcrawler-site.ccs.neu.edu"
PORT = 80
USERNAME = "dong.tia"
PASSWORD = "CP2VSD48LYTFHSVA"
DELIMITER = "\r\n\r\n"


def is_full_message(message):
    if len(message) > 0:
        return message[-1] == '\n'
    else:
        print("Invalid Message")
        raise SystemExit


def send_recv_mes(message):
    # Create socket normally
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to server
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print(e)
        raise SystemExit

    s.send(message.encode())
    is_full = False
    full_message = ""
    # when the message not full, keep receiving from the server
    while not is_full:
        received_message = s.recv(16384).decode()
        full_message += received_message
        is_full = is_full_message(received_message)
    # Disconnect
    s.close()
    return full_message


def login(username, password):
    send_list = [
        'GET /accounts/login/?next=/fakebook/ HTTP/1.1',
        f'Host: {HOST}',
        '\r\n\r\n'
    ]
    send_str = '\r\n'.join(send_list)
    res = send_recv_mes(send_str)
    header, deli, body = res.partition(DELIMITER)

    # find token in header
    t_string = 'csrftoken='
    token_index = header.find(t_string) + len(t_string)
    other_index = header.find(';', token_index, len(header))
    token = header[token_index:other_index]

    # find middlewaretoken in body
    m_token_index = body.find('csrfmiddlewaretoken') + len('csrfmiddlewaretoken')
    m_token_value_index = body.find('value="', m_token_index, len(body)) + len('value="')
    m_token_back_quote_index = body.find('"', m_token_value_index, len(body))
    m_token = body[m_token_value_index:m_token_back_quote_index]

    credential = f"username={username}&password={password}&csrfmiddlewaretoken={m_token}&next=%2Ffakebook%2F"

    send_list = [
        'POST /accounts/login/?next=/fakebook/ HTTP/1.1',
        f'Host: {HOST}',
        f'Cookie: csrftoken={token}',
        "Content-Type: application/x-www-form-urlencoded",
        f'Content-length: {len(credential)}\r\n',
        credential
    ]
    send_str = '\r\n'.join(send_list)
    mes = send_recv_mes(send_str)

    # find token in return message
    s_string = 'sessionid='
    token_index = mes.find(s_string) + len(s_string)
    other_index = mes.find(';', token_index, len(mes))
    session_id = mes[token_index:other_index]

    print(token, session_id)
    return token, session_id


def main():
    token, session_id = login(USERNAME, PASSWORD)

    # while len(queue) > 0:
    #     link = queue.pop()
    #     if link not in visited_urls:
    #         pass


if __name__ == '__main__':
    main()
