#!/usr/bin/python
#coding:utf-8

import time
import sys
import _thread as thread

class WebSocketServer:
    def __init__(self, on_open=None, on_msg=None):
        print ('WS server started')
        self.ws = None
        self.on_open = on_open
        self.on_msg = on_msg

    def run_forever(self):
        Sock.create_server(('127.0.0.1', 9001))
        conn = Sock.server_accept()
        self.ws = WebSocketChannel(conn)
        self.ws.response_handshake()
        self._callback(self.on_open) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            self.read()
            print('server callback handling')

    def write(self, data):
        print ('write:', data)
        self.ws.write_frame(data)

    def read(self):
        #1
        print ('read on server')
        msg = self.ws.read_frame()
        self._callback(self.on_msg, msg)
        #2 ping or pong

    def _callback(self, callback, *args):
        print ('callback defination on server', args)
        if callback:
            callback(self, *args)

class WebSocketClient:
    def __init__(self, on_open=None, on_msg=None):
        print ('WS client started')
        self.on_open = on_open
        self.on_msg = on_msg


    def run_forever(self):
        addr = ('127.0.0.1', 9001)
        conn = Sock.create_connect(addr)
        self.ws = WebSocketChannel(conn)
        self.ws.request_handshake()
        self._callback(self.on_open) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            self.read()
            print('client callback handling')

    def read(self):
        #1
        print ('read on client')
        msg = self.ws.read_frame()
        self._callback(self.on_msg, msg)
        #2 ping or pong

    def _callback(self, callback, *args):
        print ('callback defination on client', args)
        if callback:
            callback(self, *args)


       
class Sock:
    @classmethod
    def create_server(self, addr):
        print ('create server:{})'.format(addr))

    @classmethod
    def server_accept(self):
        print ('server accept')
        return 0

    @classmethod
    def create_connect(self, addr):
        print ('create connect to {}'.format(addr))
        return 0

class WebSocketChannel:
    def __init__(self, sock):
        self.sock = sock    
        print ('WebSocketChannel init')
    
    def write_frame(self, data):
        print ('write frame in channel')
        dd = FrameStream.encode_frame(1, data) 
        print ('dd=', dd)
        #self.sock.send(dd)

    def read_frame(self):
        print ('WebSocketChannel read')
        return 0

    def request_handshake(self):
        print ('request handshake')

    def response_handshake(self):
        print ('reponse handshake')
    
    def request_ping(self):
        pass
    def response_pong(self):
        pass

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
        mask_data = self._make_masked(mask, six.b(data))
        m = header1 + mask_data
        return m

    def decode_frame(self):
        pass

class HandShake:
    def encode_handshake_req(self):
        pass
    
    def decode_handshake_resp(self):
        pass

    def decode_handshake_req(self):
        pass
    def encode_handshake_resp(self):
        pass

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
def on_open(ws):
    print ('on open init message')
    def run(*args):
        while True:
            time.sleep(2)
            print ('thread run inside on_open!!!!!!send')
            ws.write(AA)
            print (AA)
    thread.start_new_thread(run, ())
def on_msg(ws, *args):
    print ('on message!!!!')


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
    ws.run_forever()

