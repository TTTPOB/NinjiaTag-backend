#!/usr/bin/env python3
import os
import argparse


def main():
    parser = argparse.ArgumentParser(description='Interactive login to create/update auth.json')
    parser.add_argument('-t', '--trusteddevice', action='store_true', help='Use trusted device 2FA instead of SMS')
    parser.add_argument('-r', '--regen', action='store_true', help='Force regenerate search-party-token')
    parser.add_argument('--debug', action='store_true', help='Enable verbose HTTP request/response logging (redacted)')
    args = parser.parse_args()

    # Enable debug logging for downstream modules before importing them
    if args.debug:
        os.environ['DEBUG_HTTP'] = '1'

    # Import here so DEBUG_HTTP takes effect during import-time setup
    from request_reports import getAuth

    data_dir = os.environ.get('DATA_DIR') or '/data'
    os.makedirs(data_dir, exist_ok=True)
    print(f'Using data directory: {data_dir}')

    dsid, token = getAuth(regenerate=args.regen, second_factor='trusted_device' if args.trusteddevice else 'sms')
    print('Login successful. Auth saved.')


if __name__ == '__main__':
    main()
