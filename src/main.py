#!/usr/bin/python
#coding:utf-8

import time
import sys
import _thread as thread

OPCODE_TEXT = 0x1
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

class WebSocketServer:
    def __init__(self, on_open=None, on_msg=None, on_ping=None, on_pong=None):
        print ('WS server started')
        self.ws = None
        self.on_open = on_open
        self.on_msg = on_msg
        self.on_ping = on_ping
        self.on_pong = on_pong

    def run_forever(self):
        self.CALLBACKS = { OPCODE_TEXT: self.on_msg,
                           OPCODE_PING: self.on_ping,
                           OPCODE_PONG: self.on_pong }

        server = Sock.create_server(('127.0.0.1', 9001))
        conn = Sock.server_accept(server)
        self.ws = WebSocketChannel(conn)
        self.ws.response_handshake()
        self._callback(self.on_open) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            self.read()
            print('server callback handling')

    def write(self, data, opcode=OPCODE_TEXT):
        print ('==write:', data)
        self.ws.write_frame(data, opcode)

    def read(self):
        #1
        print ('read on server')
        msg, opcode = self.ws.read_frame()
        print ("MMMMMM", msg, opcode, self.CALLBACKS[opcode])
        #self._callback(self.on_msg, msg)
        self._callback(self.CALLBACKS[opcode], msg)
        #2 ping or pong

    def _callback(self, callback, *args):
        print ('callback defination on server', args)
        if callback:
            print('!!!!!!!!!!!', args)
            callback(self, *args)
            print('!!!!!!!!!!!', args)

class WebSocketClient:
    def __init__(self, on_open=None, on_msg=None, on_ping=None, on_pong=None):
        print ('WS client started')
        self.on_open = on_open
        self.on_msg = on_msg
        self.on_ping = on_ping
        self.on_pong = on_pong

    def run_forever(self):
        self.CALLBACKS = { OPCODE_TEXT: self.on_msg,
                           OPCODE_PING: self.on_ping,
                           OPCODE_PONG: self.on_pong }

        addr = ('127.0.0.1', 9001)
        conn = Sock.create_connect(addr)
        self.ws = WebSocketChannel(conn)
        self.ws.request_handshake()
        self._callback(self.on_open) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            print('client ready to read')
            self.read()
            print('client ready to read done')
            print('client callback handling')

    def write(self, data, opcode=OPCODE_TEXT):
        print ('==write:', data)
        self.ws.write_frame(data, opcode)

    def read(self):
        #1
        print ('read on client')
        msg, opcode = self.ws.read_frame()
        #self._callback(self.on_msg, msg)
        self._callback(self.CALLBACKS[opcode], msg)
        #2 ping or pong

    def _callback(self, callback, *args):
        print ('callback defination on client', args)
        if callback:
            print('!!!!!!!!!!!', args)
            callback(self, *args)
            print('!!!!!!!!!!!', args)

import socket

class Sock:
    @classmethod
    def create_server(self, addr):
        print ('create server:{})'.format(addr))
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    def __init__(self, sock):
        self.sock = sock    
        print ('WebSocketChannel init')
   

 
    def write_frame(self, data, opcode=OPCODE_TEXT):
        print ('write frame in channel')
        dd = FrameStream.encode_frame(opcode, data) 
        print ('write bytes:', dd)
        self.sock.send(dd)

    def read_frame(self):
        #Sock.recv_bytes(self.sock, 2)
        first2bytes = self.sock.recv(2)
        print('first 2 bytes:{}, len={}'.format(first2bytes, len(first2bytes)))
        fin, opcode = FrameStream.decode_frame0(first2bytes[0])
        mask, init_payloadlen = FrameStream.decode_frame1(first2bytes[1])
        data = b""
        if init_payloadlen < LENGTH_7:
            maskkey_data = self.sock.recv(init_payloadlen+4)
            print ("LEN compare", len(maskkey_data), init_payloadlen+4) 
            maskkey, data = FrameStream.decode_frame2(init_payloadlen, maskkey_data)
        elif baselen == LENGTH_7:
            datalen = self.sock.recv(2)
            data_len = struct.unpack('>H', datalen)[0]
            maskkey_data = self.sock.recv(data_len+4)
            maskkey, data = FrameStream.decode_frame2(init_payloadlen, maskkey_data)
        elif baselen > LENGTH_7:
            datalen = self.sock.recv(8)
            data_len = struct.unpack('>Q', datalen)[0]
            maskkey_data = self.sock.recv(data_len+4)
            maskkey, data = FrameStream.decode_frame2(init_payloadlen, maskkey_data)
        
        str = data.decode()
        print ('==read on WebSocketChannel', str)
        return str, opcode 

    def request_handshake(self):
        print ('request handshake begin')
        data = HandShake.encode_handshake_req(host='127.0.0.1', port='9001', resource='chat')
        self.sock.send(data)
        data_recv =self.sock.recv(1024)
        ret = HandShake.decode_handshake_resp(data_recv)
        print ('request handshake end')

    def response_handshake(self):
        print ('reponse handshake begin')
        data =self.sock.recv(1024)
        host, accept_key = HandShake.decode_handshake_req(data)
        data_send = HandShake.encode_handshake_resp('127.0.0.1:9001', accept_key)
        self.sock.send(data_send)
        print ('reponse handshake end')
    
    def request_ping(self, data=""):
        print ('write ping frame in channel')
        dd = FrameStream.encode_frame(OPCODE_PING, data)
        print ('write bytes:', dd)
        self.sock.send(dd)

    def response_pong(self, data=""):
        print ('write pong frame in channel')
        dd = FrameStream.encode_frame(OPCODE_PONG, data)
        print ('write bytes:', dd)
        self.sock.send(dd)

import os
import struct
import array
import six

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
    def encode_frame(self, opcode, data):
        fin_opcode = (0x1<<7) | opcode
        length = len(data)
        if length < LENGTH_7:
            header_index = -1
            mask_payload_len = (0x1<<7) | length
            header1 = struct.pack(''.join(HeaderType[header_index]), fin_opcode, mask_payload_len)
        elif length < LENGTH_16:
            header_index = 0
            mask_payload_len = (0x1<<7) | LENGTH_7 
            header1 = struct.pack(''.join(HeaderType[header_index]), fin_opcode, mask_payload_len, length)
        else:
            header_index = 1
            mask_payload_len = (0x1<<7) | (LENGTH_7+1)
            header1 = struct.pack(''.join(HeaderType[header_index]), fin_opcode, mask_payload_len, length)
        mask = os.urandom(4) 
        #mask_data = self._make_masked(mask, data.encode("utf-8"))
        print ("JJJJJJJJJJJJJJJJJJ", data)
        mask_data = self._make_masked(mask, six.b(data))
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
    def decode_frame2(self, baselen, maskkey_data): 
        #based on initpayload <0x7E, 0x7E, 0x7F after read_bytes(4); read_bytes(2+4);read_bytes(4+8);read_bytes(dlen)
        mask_key = maskkey_data[:4] 
        raw_data = maskkey_data[4:]
        maskkey_data_d = self._make_masked(mask_key, raw_data)
        data = maskkey_data_d[4:]
        return mask_key, data
        #return (mask_key, data)

    #all variable to store local data not global.    
    """
    @classmethod 
    def decode_frame(self):
        #sock.recv(1024) to buffer
        #data from buffer
        #a=bytearray()a.append(byte)
        raw_data = b""
        raw_data += data
        data[0] fin opcode;
        data[1] maks payload len
        if payloadlen<0x7E: ==0x7E: ==7F:
            lengthoffset=1:2; 2:4; 2:10
            makskeyoffset=2:6; 4:8; 10:14
            dataoffset=6:x+6; 8:x+8; 14:x+10
        pass
    """
import random
import base64
import hashlib

class HandShake:
    @classmethod
    def encode_handshake_req(self, host, port, resource):
        bytes_key = bytes(random.getrandbits(8) for _ in range(16))
        key = base64.b64encode(bytes_key).decode()
        header = {'host': '{}:{}'.format(host, port),
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

        host = h_dict['host'] 
        key = h_dict['Sec-WebSocket-Key'] 
        accept_key = ws_accept_key(key)
        return host, accept_key

    @classmethod
    def encode_handshake_resp(self, host, key):
        header = {
                  'Connection': 'Upgrade',
                  'Upgrade': 'websocket',
                  'Sec-WebSocket-Accept': key,
                  'Sec-WebSocket-Protocol': 'chat',
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


class Pingpong:
    def encode_ping(self):
        pass
    def decode_pong(self):
        pass

    def decode_ping(self):
        pass
    def encode_pong(self):
        pass

import json
AA = json.dumps({1: 'a', 2: 'b'})
# AA = "" also OK

def on_open(ws):
    print ('on open init message')
    def run(*args):
        while True:
            time.sleep(2)
            print ('thread run inside on_open!!!!!!send')
            ws.write(AA, OPCODE_PING)
            print (AA)
    thread.start_new_thread(run, ())

def on_msg(ws, *args):
    print ('on message!!!!')

def on_ping(ws, *args):
    print ('on ping!!!!!!!!!!!!!!!!!!!!!!!!!')
    ws.write(*args, OPCODE_PONG)
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
    ws.on_open = on_open
    ws.on_msg = on_msg
    ws.on_ping = on_ping
    ws.on_pong = on_pong
    ws.run_forever()

