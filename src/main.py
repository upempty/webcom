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
    
    def write(self, data):
        pass

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
 
class FrameStream:
    def encode_frame(self, data):
        pass

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

def on_open(ws):
    print ('on open init message')
    def run(*args):
        while True:
            time.sleep(2)
            print ('thread run inside on_open!!!!!!')
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

