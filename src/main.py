#!/usr/bin/python
#coding:utf-8

import time
class WebSocketServer:
    def run_forever(self):
        #createServer
        #accept
        #callback(self, cb, *args) #use for on_xx(msg, ping)
        while True:
            time.sleep(2)
            #self.read()
            print('callback handling')
    pass

class WebSocketClient:
    pass

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
    wserver = WebSocketServer()
    wserver.run_forever()
