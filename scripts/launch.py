#!/usr/bin/env python
# coding: utf8

import time
import string
import random
import sys
import os
import subprocess
import logging
import logging.config
import json
import operator
import argparse
from datetime import datetime
import concurrent.futures
import socket
import socketserver
import pathlib

# https://wiki.archlinux.org/title/Category:Eye_candy
# https://wiki.archlinux.org/title/Color_output_in_console
# https://chrisyeh96.github.io/2020/03/28/terminal-colors.html

# https://github.com/fidian/ansi
# curl -L https://git.io/ansi -o ~/.local/bin/ansi

COLOR_BEGIN = '\N{ESC}'
COLOR_END = '\u001b[0m'
COLOR_BLACK, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE = [
    f'[{value}m' for value in range(30, 38)
]

def get_256_color(f, b=0):
    return f'[38;5;{f};48;5;{b}m'

def get_rgb_color(fr, fg, fb, br=0, bg=0, bb=0):
    return f'[38;2;{fr};{fg};{fb};48;2;{br};{bg};{bb}m'

CHECK = f'{COLOR_BEGIN}{COLOR_GREEN}✓{COLOR_END}'
CROSS = f'{COLOR_BEGIN}{COLOR_RED}✗{COLOR_END}'

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
        # 'echo': { 'format': f'{COLOR_BEGIN}{get_rgb_color(255, 0, 0)}ECHO %(asctime)s %(message)s{COLOR_END}' },
        'echo': { 'format': f'{COLOR_BEGIN}{get_256_color(30, 0)}ECHO %(asctime)s %(message)s{COLOR_END}' },
        'echo_server': { 'format': f'{COLOR_BEGIN}{get_256_color(100)}ECHO_SERVE %(asctime)s %(message)s{COLOR_END}' },
        'wsc_message': { 'format': f'{COLOR_BEGIN}{COLOR_CYAN}WSC %(message)s{COLOR_END}' },
        'wsd_message': { 'format': f'{COLOR_BEGIN}{COLOR_MAGENTA}WSD %(message)s{COLOR_END}' },
    },
    'handlers': {
        'console': {
            'level':'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'echo'
        },
        'echo_server_console': {
            'level':'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'echo_server'
        },
        'wsc_console':{
            'level':'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'wsc_message'
        },
        'wsd_console':{
            'level':'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'wsd_message'
        },
        'wsc_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'formatter': 'simple',
            'filename': '/tmp/wsc.log',
            "mode": "w"
        },
        'wsd_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'formatter': 'simple',
            'filename': '/tmp/wsd.log',
            "mode": "w"
        }
    },
    'loggers': {
        'echo': {
            'handlers': ['console'],
            'propagate': False,
            'level': 'DEBUG',
        },
        'echo_server': {
            'handlers': ['echo_server_console'],
            'propagate': False,
            'level': 'DEBUG',
        },
        'wsc': {
            'handlers':['wsc_console', 'wsc_file'],
            'propagate': False,
            'level':'DEBUG',
        },
        'wsd': {
            'handlers': ['wsd_console', 'wsd_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    }
})

def dump_watchexec_envs(log):

    prefix = 'WATCHEXEC_'

    for k, v in os.environ.items():
        if k.startswith(prefix):
            log.info(f'{k} => {v}')

def launch_ws_reverse_server(server_host: string, server_port: int, forwards, debug=False, mode='r-wsserver'):
    log = logging.getLogger('wsd')

    log.info('%s server %s %s', '-' * 20, datetime.now().isoformat(), '-' * 20)
    dump_watchexec_envs(log)

    subprocess.run(['rm', '-rf', 'kptunnel*'])
    subprocess.run(['go', 'build'])
    log.info('kpt compiled')

    log.info('listening on :%s', server_port)
    cmd =  ['./kptunnel', 'r-wsserver', f':{server_port}', *forwards, '-pass', 'cpass', '-encPass', 'tpass']
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        for line in p.stdout:
            j = json.loads(line.strip())
            dt, level, caller, message, role, sessionId = (j.get(k) for k in ('time', 'level', 'caller', 'message', 'role', 'sessionId'))
            fn, filename, lineno = caller.split(':')
            _, fn = fn.rsplit('.', 1)
            if debug:
                log.info('%-21s %13s %-4s %-32s %-3s %s', dt[11:], filename, lineno, fn, sessionId or '-', message)

def launch_ws_reverse_client(server_host, server_port, forward, debug=False, mode='r-wsclient', path='/ws', exe='kptunnel', compile=True):
    log = logging.getLogger('wsc')
    log.info('%s client %s %s', '-' * 20, datetime.now().isoformat(), '-' * 20)

    if compile:
        # subprocess.run(['rm', '-rf', 'kptunnel*'])
        pathlib.Path('kptunnel.exe').unlink(missing_ok=True)

        subprocess.run(['go', 'build'])
        log.info('kpt compiled')

    log.info('connect to %s:%s, forward: %s', server_host, server_port, forward)
    cmd =  ['./kptunnel', 'r-wsclient', f'{server_host}:{server_port}', '-tls', '-wspath', path, '-pass', 'cpass', '-encPass', 'tpass']
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        for line in p.stdout:
            j = json.loads(line.strip())
            dt, level, caller, message, role, sessionId = (j.get(k) for k in ('time', 'level', 'caller', 'message', 'role', 'sessionId'))
            if 'bad status' in message:
                p.kill()
            fn, filename, lineno = caller.split(':')
            _, fn = fn.rsplit('.', 1)
            if debug:
                log.info('%-21s %13s %-4s %-32s %-3s %s', dt[11:], filename, lineno, fn, sessionId or '-', message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mode', default='test')
    parser.add_argument('--host', type=str, default='46.d1f.xyz')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('-f', '--forwards', type=str, nargs='*', default=[]) # collect all as a list: -f a b => [a, b]
    args = parser.parse_args()
    print(f'mode: {args.mode}')

    if args.mode == 'ws-client':
        while True:
            launch_ws_reverse_client(args.host, args.port, [], debug=True)
            time.sleep(3)

    if args.mode == 'dev-client':
        while True:
            launch_ws_reverse_client(args.host, args.port, [], debug=True, path='/dev', exe='kpt')
            time.sleep(3)

    if args.mode == 'ws-server':
        # ports for pwsh, pwsh/admin, console
        forwards = [':2222,localhost:2222', ':2223,localhost:2223', ':2224,localhost:2224', *args.forwards]
        print(f"forwards: {forwards}")
        launch_ws_reverse_server('127.0.0.1', 34022, forwards, debug=True, mode='r-wsserver')

    if args.mode == 'dev-server':
        forwards = [':4122,127.0.0.1:22', *args.forwards]
        print(f"forwards: {forwards}")
        launch_ws_reverse_server('127.0.0.1', 34122, forwards, debug=True, mode='r-wsserver')

if __name__ == '__main__':
    main()