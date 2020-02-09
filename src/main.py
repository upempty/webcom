#!/usr/bin/python
#coding:utf-8

import time
import sys
import _thread as thread
import select

OPCODE_TEXT = 0x1
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

class WebSocketServer:
    def __init__(self, port=9001, on_open=None, on_msg=None, on_ping=None, on_pong=None):
        print ('WS server started')
        self.ws = None
        self.port = port

        self.on_open = on_open
        self.on_msg = on_msg
        self.on_ping = on_ping
        self.on_pong = on_pong


        self.wss = []        
        self.read_socks = []
        self.conn_socks = []

    def run_forever(self):

        self.CALLBACKS = { OPCODE_TEXT: self.on_msg,
                           OPCODE_PING: self.on_ping,
                           OPCODE_PONG: self.on_pong }

        server = Sock.create_server(('', self.port))
        self.read_socks = [server]
        first_handshakes = []
        while True:
            readable, writable, exceptional = select.select(self.read_socks, [], [], 1)        
            for s in readable:
                if s is server:
                    conn = Sock.server_accept(server)
                    print('accepted conn:', conn)
                    conn.setblocking(0)
                    self.read_socks.append(conn)
                    self.conn_socks.append(conn)
                    first_handshakes.append(True)
                else:
                    print('read conn:', s)
                    id = self.conn_socks.index(s)
                    if first_handshakes[id]: 
                        first_handshakes[id] = False
                        ws = WebSocketChannel(s, 1)
                        print ("idid ", id)
                        ws.response_handshake(host="127.0.0.1:{}".format(self.port))
                        self.wss.append(ws)
                        self._callback(self.on_open, self.wss[id]) #use for on_xx(msg, ping)
                        print('read ws handling1')
                    else:
                        self.handle_recv(self.wss[id])
                        print('read ws handling11')
                        
            time.sleep(2)
            print('server callback handling')
    
    def multicast(self, except_ws,  msg):
        for w in self.wss:
            if w is except_ws:
                print("!!!!!!!!!!!!!!!!ooooooooown-own----------!!!!!!!!!!!!=======")
                continue
            w.send(msg, opcode=OPCODE_TEXT)
            print ('broadcast!!!!!')
        
    def send(self, ws, data, opcode=OPCODE_TEXT):
        print ('==write:', data)
        ws.send(data, opcode)

    def handle_recv(self, ws):
        print ('read on server')
        msg, opcode = ws.recv()
        if not msg:
            return
        print ("received msg and opcode, callback func::", msg, opcode, self.CALLBACKS[opcode])
        self._callback(self.CALLBACKS[opcode], ws, msg)
        if opcode == OPCODE_TEXT:
            self.multicast(ws, msg)

    def _callback(self, callback, ws, *args):
        print ('callback defination on server', args)
        if callback:
            callback(ws, *args)


""" 
    def run_forever(self):

        self.CALLBACKS = { OPCODE_TEXT: self.on_msg,
                           OPCODE_PING: self.on_ping,
                           OPCODE_PONG: self.on_pong }

        server = Sock.create_server(('', self.port))
        conn = Sock.server_accept(server)
        self.ws = WebSocketChannel(conn)
        self.ws.response_handshake(host="127.0.0.1:{}".format(self.port))
        self._callback(self.on_open) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            self.read()
            print('server callback handling')

    def write(self, data, opcode=OPCODE_TEXT):
        print ('==write:', data)
        self.ws.write_frame_s(data, opcode)

    def read(self):
        #1
        print ('read on server')
        msg, opcode = self.ws.read_frame()
        print ("received msg and opcode, callback func::", msg, opcode, self.CALLBACKS[opcode])
        #self._callback(self.on_msg, msg)
        self._callback(self.CALLBACKS[opcode], msg)
        #2 ping or pong

    def _callback(self, callback, *args):
        print ('callback defination on server', args)
        if callback:
            callback(self, *args)
"""

from urllib.parse import urlsplit as urlsplit

class WebSocketClient:
    def __init__(self, url="ws://localhost:9001/ws",  on_open=None, on_msg=None, 
                       on_ping=None, on_pong=None):
        print ('WS client started')
        self.on_open = on_open
        self.on_msg = on_msg
        self.on_ping = on_ping
        self.on_pong = on_pong
        self.url = url
        self.parse_connection()
    
    def parse_connection(self):
        ret = urlsplit(self.url)       
        self.addr = (ret.hostname, ret.port)
        print ("URL=", self.url, ", addr=", self.addr)
        self.resource = ret.path
            
    def run_forever(self):
        self.CALLBACKS = { OPCODE_TEXT: self.on_msg,
                           OPCODE_PING: self.on_ping,
                           OPCODE_PONG: self.on_pong }

        #addr = ('127.0.0.1', 9001)
        conn = Sock.create_connect(self.addr)
        self.ws = WebSocketChannel(conn, 0)
        self.ws.request_handshake(self.addr[0], self.addr[1])
        self._callback(self.on_open) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            print('client ready to read')
            self.handle_recv()
            print('client ready to read done')
            print('client callback handling')

    def handle_recv(self):
        #1
        print ('read on client')
        msg, opcode = self.ws.recv()
        #self._callback(self.on_msg, msg)
        self._callback(self.CALLBACKS[opcode], msg)
        #2 ping or pong

    def _callback(self, callback, *args):
        print ('callback defination on client', args)
        if callback:
            callback(self, *args)

import socket

class Sock:
    @classmethod
    def create_server(self, addr):
        print ('create server:{})'.format(addr))
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        so.bind(addr)
        so.listen(5)
        return so

    @classmethod
    def server_accept(self, server):
        print ('server accept')
        conn, addr = server.accept() 
        print ('accepted: server accept', addr)
        return conn 

    @classmethod
    def create_connect(self, addr):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.connect(addr)
        print ('create connected to {}'.format(addr))
        return so 

class WebSocketChannel:
    def __init__(self, sock, server_role = 0):
        self.sock = sock    
        self.role = server_role 
        print ('WebSocketChannel init')
 
    def send(self, data, opcode=OPCODE_TEXT):
        if self.role == 1:
            print ('==ws send s:', data)
            self.write_frame_s(data, opcode)
        else: 
            print ('==ws send c', data)
            self.write_frame_c(data, opcode)

    def recv(self):
        print ('read on server or client')
        msg, opcode = self.read_frame()
        print("==ws recv", msg, " opcode:", opcode)
        return msg, opcode

    def write_frame_s(self, data, opcode=OPCODE_TEXT):
        print ('write frame in channel')
        dd = FrameStream.encode_frame(opcode, data, mask=0) 
        print ('write bytes:', dd)
        self.sock.send(dd)
 
    def write_frame_c(self, data, opcode=OPCODE_TEXT):
        print ('write frame in channel')
        dd = FrameStream.encode_frame(opcode, data, mask=1) 
        print ('write bytes:', dd)
        self.sock.send(dd)


    def read_frame(self):
        #Sock.recv_bytes(self.sock, 2)
        first2bytes = self.sock.recv(2)
        if not first2bytes:
            print("null")
            return "",1
        print('first 2 bytes:{}, len={}'.format(first2bytes, len(first2bytes)))
        fin, opcode = FrameStream.decode_frame0(first2bytes[0])
        mask, init_payloadlen = FrameStream.decode_frame1(first2bytes[1])
        data = b""
        maskkey_data = b""
        if init_payloadlen < LENGTH_7:
            if mask == 1:
                maskkey_data = self.sock.recv(init_payloadlen+4)
                print ("LEN compare with mask", len(maskkey_data), init_payloadlen+4) 
            else:
                maskkey_data = self.sock.recv(init_payloadlen)
                print ("LEN compare no mask", len(maskkey_data), init_payloadlen) 
            maskkey, data = FrameStream.decode_frame2(mask, maskkey_data)
            print('==maskkey:{}; data={}'.format(maskkey, data))
        elif init_payloadlen == LENGTH_7:
            datalen = self.sock.recv(2)
            data_len = struct.unpack('>H', datalen)[0]
            if mask == 1:
                maskkey_data = self.sock.recv(data_len+4)
            else:
                maskkey_data = self.sock.recv(data_len)
            maskkey, data = FrameStream.decode_frame2(mask, maskkey_data)
        elif init_payloadlen > LENGTH_7:
            datalen = self.sock.recv(8)
            data_len = struct.unpack('>Q', data_len)[0]
            if mask == 1:
                maskkey_data = self.sock.recv(data_len+4)
            else:
                maskkey_data = self.sock.recv(data_len)
            maskkey, data = FrameStream.decode_frame2(mask, maskkey_data)
        
        str = data.decode()
        print ('==read on WebSocketChannel', str)
        return str, opcode 

    def request_handshake(self, host="127.0.0.1", port=9001):
        print ('request handshake begin')
        data = HandShake.encode_handshake_req(host, port, resource='chat')
        self.sock.send(data)
        data_recv =self.sock.recv(1024)
        ret = HandShake.decode_handshake_resp(data_recv)
        print ('request handshake end')

    def response_handshake(self, host):
        print ('reponse handshake begin')
        data =self.sock.recv(1024)
        host, accept_key = HandShake.decode_handshake_req(data)
        data_send = HandShake.encode_handshake_resp(host, accept_key)
        self.sock.send(data_send)
        print ('reponse handshake end')

import os
import struct
import array

LENGTH_7 = 0x7E
LENGTH_16 = 0x1<<16
"""
7BITS:
 < LENGTH_7: LEN_BYTES=1, MASK_OFFSET=2, MASK_LEN=4
 = LENGTH_7: LEN_BYTES=2, MASK_OFFSET=4, MASK_LEN=4
 > LENGTH_7: LEN_BYTES=8, MASK_OFFSET=10, MASK_LEN=4
"""
HeaderType = {-1: ['>', 'B', 'B'],
               0: ['>', 'B', 'B', 'H'],
               1: ['>', 'B', 'B', 'Q']
             }
 
class FrameStream:
    '''
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - - +-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                |
 +---------------------------------------------------------------+
x1,x2,... = struct.unpack(fmt, bytes)

    '''
    @staticmethod
    def _make_masked(mask_key, data):
        arr_data = array.array("B", data)
        for i in range(len(arr_data)):
            arr_data[i] ^= mask_key[i % 4]
        d = mask_key + arr_data.tobytes()
        return d
    
    @classmethod
    def encode_frame(self, opcode, data, mask=0x1):
        fin_opcode = (0x1<<7) | opcode
        #length = len(data) Note: issue to support chinese, it shall use len of encode of chinese.
        length = len(data.encode())
        if length < LENGTH_7:
            header_index = -1
            #mask_payload_len = (0x1<<7) | length
            mask_payload_len = (mask<<7) | length
            header1 = struct.pack(''.join(HeaderType[header_index]), fin_opcode, mask_payload_len)
        elif length < LENGTH_16:
            header_index = 0
            mask_payload_len = (mask<<7) | LENGTH_7 
            header1 = struct.pack(''.join(HeaderType[header_index]), fin_opcode, 
                                  mask_payload_len, length)
        else:
            header_index = 1
            mask_payload_len = (mask<<7) | (LENGTH_7+1)
            header1 = struct.pack(''.join(HeaderType[header_index]), fin_opcode, 
                                  mask_payload_len, length)
        if mask == 1:
            maskkey = os.urandom(4) 
            #mask_data = self._make_masked(maskkey, data.encode("utf-8"))
            mask_data = self._make_masked(maskkey, data.encode())
        else:
            mask_data = data.encode()
        print ("==encode frame mask:{}, data:{}==".format(mask, data))
        m = header1 + mask_data
        return m
    
    @classmethod
    def decode_frame0(self, data_fin_opcode): #after read_bytes(2)
        #return (fin, opcode)
        fin = data_fin_opcode >> 7 & 1
        opcode = data_fin_opcode & 0xf
        return fin, opcode

    @classmethod
    def decode_frame1(self, data_mask_init_payload):
        #return (mask, initpayload)
        mask = data_mask_init_payload >> 7 & 1
        init_payload_len = data_mask_init_payload & 0x7F
        return mask, init_payload_len

    @classmethod
    def decode_frame2(self, mask, maskkey_data): 
        #based on initpayload <0x7E, 0x7E, 0x7F 
        #after read_bytes(4); read_bytes(2+4);read_bytes(4+8);read_bytes(dlen)
        mask_key = b''
        if mask == 1:
            mask_key = maskkey_data[:4] 
            raw_data = maskkey_data[4:]
            maskkey_data_d = self._make_masked(mask_key, raw_data)
            data = maskkey_data_d[4:]
        else:
            data = maskkey_data
        return mask_key, data
        #return (mask_key, data)


import random
import base64
import hashlib

class HandShake:
    @classmethod
    def encode_handshake_req(self, host, port, resource):
        bytes_key = bytes(random.getrandbits(8) for _ in range(16))
        key = base64.b64encode(bytes_key).decode()
        header = {'Host': '{}:{}'.format(host, port),
                  'Connection': 'Upgrade',
                  'Upgrade': 'websocket',
                  'User-Agent': 'Python3.7',
                  'Origin': 'http://{}:{}'.format(host, port),
                  'Sec-WebSocket-Key': key,
                  'Sec-WebSocket-Version': '13'
                 }
        headers = ['{}: {}'.format(k, item) for k, item in header.items()]
        headers.insert(0, 'GET /{} HTTP/1.1'.format(resource))
        headers.append('\r\n')
        req =  '\r\n'.join(headers)
        print ('handshake req sending=======\n', req)
        print ('handshake req sending=======end\n')
        data = req.encode()
        return data
 
    @classmethod
    def decode_handshake_resp(self, data):
        data = str(data, encoding='utf-8')
        print ('handshake resp recv=======\n', data)
        print ('handshake resp recv=======end\n')
        header, _ = data.split('\r\n\r\n', 1)
        header_list = header.split('\r\n')
        for i in header_list:
            print (i)
        return 0

    @classmethod
    def decode_handshake_req(self, data):

        def ws_accept_key(sec_key):
            MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            sha1 = hashlib.sha1()
            sha1.update((sec_key + MAGIC).encode()) 
            return base64.b64encode(sha1.digest()).decode()

        data = str(data, encoding='utf-8')
        print ('handshake req recv=======\n', data)
        print ('handshake req recv=======end\n')
 
        header, _ = data.split('\r\n\r\n', 1)
        header_list = header.split('\r\n')
        h_dict = {}
        for i,s in enumerate(header_list):
            print (i,s)
            if i != 0:
                k, v = header_list[i].split(':', 1)
                h_dict[k] = v.strip() 

        protocols = header_list[0].split()[:2]
        print('header[0] recv', header, header_list)
        print('h dict', h_dict)

        host = h_dict['Host'] 
        key = h_dict['Sec-WebSocket-Key'] 
        accept_key = ws_accept_key(key)
        return host, accept_key

    @classmethod
    def encode_handshake_resp(self, host, key):
        """
        header = {
                  'Connection': 'Upgrade',
                  'Upgrade': 'websocket',
                  'Sec-WebSocket-Accept': key,
                  'Sec-WebSocket-Protocol': 'chat',
                  'Sec-WebSocket-location': 'ws://{}'.format(host)
                 }

        """
        # if client sends Sec-WebSocket-Protocol, then response with protocol needed, or not needed.
        header = {
                  'Connection': 'Upgrade',
                  'Upgrade': 'websocket',
                  'Sec-WebSocket-Accept': key,
                  'Sec-WebSocket-location': 'ws://{}'.format(host)
                 }


        headers = ['{}: {}'.format(k, item) for k, item in header.items()]
        headers.insert(0, 'HTTP/1.1 101 Switching Protocols')
        headers.append('\r\n')
        resp =  '\r\n'.join(headers)
        print ('handshake resp send=======\n', resp)
        print ('handshake resp send=======end\n')
 
        data = resp.encode()
        return data 


import json
AA = json.dumps({1: 'a', 2: 'b'})
# AA = "" also OK

def on_open_s(ws):
    print ('on open init message')
    AA = json.dumps({1: 'ping'})
    def run(*args):
        while True:
            time.sleep(2)
            print ('server open thread run inside on_open!!!!!!send')
            ws.send(AA, OPCODE_PING)
            print (AA)
    thread.start_new_thread(run, ())

def on_open_c(ws):
    print ('on open init message')
    def run(*args):
        while True:
            time.sleep(2)
            print ('client open thread run inside on_open!!!!!!send')
            ws.send(AA)
            print (AA)
    thread.start_new_thread(run, ())


from os import path
from jinja2 import Environment, FileSystemLoader


project_path = path.abspath(path.join(path.dirname(__file__), '..'))
templates_path = '{}/templates'.format(project_path)
print ('templates_path=', templates_path)
loader = FileSystemLoader(templates_path)
env = Environment(loader=loader)

def render_template(template, **kwargs):
    temp = env.get_template(template)
    return temp.render(**kwargs)

def on_msg(ws, *args):
    print ('on message *args!!!!:========: ', *args)
    print ('on message  args!!!!:========: ', args)
    ws.send(*args)
    
    #append image to html: option1: render html file; option2: html text directly in code;
    """
    flask_data = "WS cannot long"
    rend = render_template('block.html', flask_data=flask_data)
    print ('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$', rend)
    ws.write(rend)
    """
    #img1 = "client1.jpg"
    #block = """<span class="content">block2</span>
    #           <img src="{}" alt="client1" width="400", height="341" title="client fei">
    #        """.format(img1)
    #ws.send(block)


def on_ping(ws, *args):
    print ('on ping!!!!!!!!!!!!!!!!!!!!!!!!!')
    ws.send(*args, OPCODE_PONG)
    print ('send pong!!!!!!!!!!!!!!!!!!!!!!!!!')

def on_pong(ws, *args):
    print ('on pong!!!!!!!!!!!!!!!!!!!!!!!!!')

if __name__=='__main__':

    print (sys.argv)
    if not (len(sys.argv) == 2):
        print ('argv incorrect')
        sys.exit() 
    id = int(sys.argv[1])
    
    daemon_role = {
        1: WebSocketClient,
        2: WebSocketServer
    }
    
    print('main entry:主入口')
    #wserver = WebSocketClient()
    ws = daemon_role.get(id, WebSocketClient)()

    ws.on_msg = on_msg
    ws.on_ping = on_ping
    ws.on_pong = on_pong
 
    if id == 2: # server send ping to client.
        ws.on_open = on_open_s
    else: 
        ws.on_open = on_open_c
    ws.run_forever()


