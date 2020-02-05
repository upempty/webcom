
1. python3 src/main.py 2
2. open test/c4.html
3. ali cloud server debug/tested OK : 
pc client-----ali web wwww html server with 80 port-----websocket server 9001 port
=>in this html, it create ws to server ip:90001.

3.1 c4.html websocket client html renaming to index.html to /var/www/html/  
3.2 httpd with 80 port running  
3.3 run ws server:python3 src/main.py 2  
3.3 run web access to web server:http://118.31.109.239/index.html via browser  
3.4 add in ali console management to allow port 9001 accessed by web client   
