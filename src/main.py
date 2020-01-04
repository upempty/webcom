#!/usr/bin/python
#coding:utf-8

import time
import sys

class WebSocketServer:
    def __init__(self):
        print ('server started')

    def run_forever(self):
        #createServer
        #accept
        #handshake_response
        #callback(self, cb, *args) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            #self.read()
            ##self._callback(self.on_msg, *args))
            print('server callback handling')

class WebSocketClient:
    def __init__(self):
        print ('client started')

    def run_forever(self):
        #connect()
        #handshake_req()
        while True:
            time.sleep(2)
            #self.read()
            ##self._callback(self.on_msg, *args))
            print('client callback handling')
       
class Sock:
    def create_server(self, addr):
        pass

    def server_accept(self, server):
        pass

    def create_connect(self, addr):
        pass

class WebSocketChannel:
    def __init__(self, sock):
        self.sock = sock    
    
    def write(self, data):
        pass

    def read(self):
        pass

    def request_handshake(self):
        pass
    def response_handshake(self):
        pass 
    
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
    ws.run_forever()

