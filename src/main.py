#!/usr/bin/python
#coding:utf-8

import time
class WebSocketServer:
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

    def request__handshake(self):
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
    print('main entry:主入口')
    wserver = WebSocketClient()
    wserver.run_forever()
