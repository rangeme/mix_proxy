#mix_proxy

Mix proxy with HTTP and HTTPS.  
Use local key file and cert file to get https flow.  
If there is a "connect" method first, then https it is.  
Else it's a http packet.  
Request to remote server with python requests lib.  
Edit or save requests to somewhere.

###Usage:
`python mix_proxy.py (default 127.0.0.1) port`  
`python mix_proxy.py bind_address port`

###Example:
`python mix_proxy.py 10086`  
`python mix_proxy.py 127.0.0.1 10086`

###NEW Crt:
`openssl req -new -x509 -days 365 -nodes -out key.crt -keyout key.pem`

###Do something with content:
fuction `content_deal(headers, host, method, postdata, uri)`  is with a hook which can edit or save requests to somewhere.

