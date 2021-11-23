import base64
with open('Crypt_webshell.txt','rb') as f:
	print(base64.b64encode(f.read()))