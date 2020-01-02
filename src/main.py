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
    pass

class WebSocketChannel:
    pass

class FrameStream:
    pass

class HandShake:
    pass

class Pingpong:
    pass

if __name__=='__main__':
    print('main entry:主入口')
    wserver = WebSocketClient()
    wserver.run_forever()
