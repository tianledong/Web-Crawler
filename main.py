import socket
import sys

stack = []
visited_urls = []
flags = []

HOST = "webcrawler-site.ccs.neu.edu"
PORT = 80
DELIMITER = "\r\n\r\n"
ROOT = '/fakebook/'
FLAG_STR = "<h2 class='secret_flag'"


def is_full_message(message):
    if len(message) > 0:
        return message[-1] == '\n'
    else:
        print("Invalid Message")
        raise SystemExit


def send_recv_mes(message):
    # Create socket
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


# Login with username and password. Will return session ID and token.
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

    # find session id in return message
    s_string = 'sessionid='
    token_index = mes.find(s_string) + len(s_string)
    other_index = mes.find(';', token_index, len(mes))
    session_id = mes[token_index:other_index]
    return token, session_id


# get url from 301 header
def get_url_301(header):
    lst = header.split('\n')
    keyword = 'Location: '
    index = [i for i, s in enumerate(lst) if keyword in s]
    location_line = lst[index[0]]
    url = location_line[len(keyword):]
    return url


def get_request(session_id, token, url):
    # we make the host always as webcrawler-site.ccs.neu.edu to make sure we wont go to other webs
    send_list = [
        f'GET {url} HTTP/1.1',
        f'Host: {HOST}',
        f'Cookie: csrftoken={token}; sessionid={session_id}',
        '\r\n'
    ]
    send_str = '\r\n'.join(send_list)
    res = send_recv_mes(send_str)
    header, deli, body = res.partition(DELIMITER)
    status = get_header_status(header)
    # success
    if status == '200':
        return body
    # redirect status. try new url
    elif status == '301':
        new_url = get_url_301(header)
        return get_request(session_id, token, new_url)
    # retry the request to this url until success
    elif status == '500':
        return get_request(session_id, token, url)
    # when status == '403' or status == '404' or other. Abandon url
    else:
        return


def get_header_status(header):
    header = header.split('\n')[0]
    status = header.split(' ')[1]
    return status


def search_flag(body):
    # as the syntax of the flag exactly follow the format
    index = body.find(FLAG_STR)
    if index != -1:
        # the length of the previous html is 47 long
        index = index + 48
        # the flag is exactly 64 long
        flag = body[index:index + 64]
        print(flag)
        return flag


def find_url_in_body(body):
    index = body.find('<div id="content">')
    body_len = len(body)
    while index < body_len:
        index = body.find('href="', index, body_len)
        # if does not find any link end search
        if index == -1:
            return
        index += len('href="')
        back_index = body.find('"', index, body_len)
        url = body[index:back_index]
        if url not in stack and url not in visited_urls:
            stack.append(url)
        index = back_index


def crawl(token, session_id, root_url):
    stack.append(root_url)
    while len(stack) > 0:
        url = stack.pop()
        visited_urls.append(url)
        # make a get request to get data from this url
        body = get_request(session_id, token, url)
        if body:
            flag = search_flag(body)
            if flag:
                flags.append(flag)
                # when find all flags break the loop
                if len(flags) > 4:
                    return
            find_url_in_body(body)


def main(args):
    if len(args) > 2:
        username = args[1]
        password = args[2]
    else:
        print("Invalid Inputs")
        raise SystemExit

    token, session_id = login(username, password)
    crawl(token, session_id, ROOT)


if __name__ == '__main__':
    main(sys.argv)
