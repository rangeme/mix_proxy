#!/usr/bin/env python
#coding: utf-8
import os
import re
import ssl
import sys
import time
import json
import base64
import socket
import urlparse
import warnings
import requests
import threading
from hashlib import md5


warnings.filterwarnings("ignore")

'''
Mix proxy with HTTP and HTTPS.
Use local key file and cert file to get https flow.
If there is a "connect" method first, then https it is.
Else it's a http packet.
Request to remote server with python requests lib.
Function content_deal() is with a hook which can edit or save requests to somewhere.
Function res_deal() is whith a hook which can edit response to client.
'''


def https_things(sock):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.load_cert_chain(certfile = "key.crt", keyfile = "key.pem")
    connstream = context.wrap_socket(sock, server_side=True)
    client_conn(connstream, True)


def print_help():
    print 'Usage:'
    print '    python %s (default 127.0.0.1) port' % sys.argv[0]
    print '    python %s bind_address port'        % sys.argv[0]
    print 'Example:'
    print '    python %s 10086'                    % sys.argv[0]
    print '    python %s 127.0.0.1 10086'          % sys.argv[0]
    exit()


def get_str(res):
    code = str(res.status_code)
    reason = res.reason
    data = ''
    headers = res.headers
    if 'Content-Encoding' in headers.keys():
        del headers['Content-Encoding']
    if 'Transfer-Encoding' in headers.keys():
        del headers['Transfer-Encoding']
    headers['Content-Length'] = len(res.content)
    data += 'HTTP/1.1 %s %s\r\n' % (code, reason)
    for key in res.headers.keys():
        data += '%s: %s\r\n' % (key, headers[key])
    data += '\r\n' + res.content
    return data


def get_res(data, connstream, https):
    try:
        headers = {}
        post = ''
        if data[0:7] == 'CONNECT':
            connstream.sendall("HTTP/1.1 200 Connection established\r\n\r\n")
            https_things(connstream)
            return
        if not re.search('(GET|POST) (.*) HTTP',data):
            return

        methods = re.findall('(GET|POST) (.*) HTTP',data)[0]
        url = methods[1]
        method = methods[0]

        if method == 'GET':
            head = data.split('\r\n')[1:]
            for h in head:
                if ': ' in h[2:]:
                    headers[h.split(': ')[0]] = h.split(': ')[1]
            host = headers['Host'].replace(' ', '')

            if not https:
                uri = url
            else:
                uri = "https://%s%s" % (host, url)
            print uri
            content_deal(headers, host, method, postdata = '', uri = uri)

            if 'Host' in headers.keys():
                del headers['Host']

            res = requests.get(uri, headers = headers, verify = False)
            response = get_str(res)
            response = res_deal(response)
            connstream.sendall(response)
            connstream.close()
            return

        elif method == 'POST':
            body = data.split('\r\n\r\n')[1]
            head = data.split('\r\n\r\n')[0].split('\r\n')[1:]
            for h in head:
                if ': ' in h[2:]:
                    headers[h.split(': ')[0]] = h.split(': ')[1]
            host = headers['Host'].replase(' ', '')

            if not https:
                uri = url
            else:
                uri = "https://%s%s" % (host, url)
            print uri
            content_deal(headers, host, method, postdata = body, uri = uri)

            if 'Host' in headers.keys():
                del headers['Host']
                
            res = requests.post(uri, headers = headers, data = body, verify = False)
            response = get_str(res)
            response = res_deal(response)
            connstream.sendall(response)
            connstream.close()
            return

    except Exception, e:
        if 'url' in dir():
            print url
        print "Http Error: " + str(e)
        try:
            err  = "HTTP/1.1 500 Internal Server Error\r\n"
            err += "Content-Length-Type: text/html;\r\n"
            err += "Content-Length: 17\r\n\r\n"
            err += "HTTP Error"
            connstream.sendall()
            connstream.close()
        except Exception, e:
            pass
        finally:
            return 

def res_deal(response):
    return response

def content_deal(headers, host, method, postdata, uri):
    pass

def client_conn(connstream, https=False):
    try:
        connstream.settimeout(0.5)
        data = ""
        while True:
            tmp = connstream.recv(10240)
            data += tmp
            if tmp == '':
                break
    except Exception, e:
        pass
    connstream.settimeout(10)
    get_res(data, connstream, https)


def main(addr, port):
    try:
        bindsocket = socket.socket()
        bindsocket.bind((addr, port))
        bindsocket.listen(300)
    except Exception, e: 
        print e
        exit()

    while True:
        try:
            connstream, fromaddr = bindsocket.accept()
            t = threading.Thread(target = client_conn, args = (connstream,))
            t.start()
        except Exception, e:
            print e
            if 'connstream' in dir():
                connstream.close()


if __name__ == '__main__':
    port = 10086
    addr = '127.0.0.1'
    if len(sys.argv) == 1:
        print_help()
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])
        address = sys.argv[1]
    main(addr, port)
