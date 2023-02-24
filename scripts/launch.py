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

def launch_wsd(server_host: string, server_port: int, debug=False, mode='wsserver'):
    log = logging.getLogger('wsd')

    log.info('%s WSD %s %s', '-' * 20, datetime.now().isoformat(), '-' * 20)
    dump_watchexec_envs(log)

    subprocess.run(['go', 'build', '-o', 'wsd', 'cmd/websocket_server/main.go'])
    log.info('wsd compiled')

    log.info('listening on :%s', server_port)
    cmd =  ['./wsd', 'wsserver', f'{server_host}:{server_port}', '-pass', '42', '-encPass', '42']
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        for line in p.stdout:
            j = json.loads(line.strip())
            dt, level, caller, message, role, sessionId = (j.get(k) for k in ('time', 'level', 'caller', 'message', 'role', 'sessionId'))
            fn, filename, lineno = caller.split(':')
#             if fn.startswith('github.com/emctoo/'):
#                 fn = fn[len('github.com/emctoo/'):]
#             if fn.startswith('kptunnel.'):
#                 fn = fn[len('kptunnel.'):]
#             if fn.startswith('main.'):
#                 fn = fn[len('main.'):]
            _, fn = fn.rsplit('.', 1)
            if debug:
                log.info('%-18s %13s %-4s %-32s %-3s %s', dt[11:], filename, lineno, fn, sessionId or '-', message)

def launch_wsc(server_host, server_port, forward, debug=False, mode='wsclient'):
    log = logging.getLogger('wsc')
    log.info('%s WSC %s %s', '-' * 20, datetime.now().isoformat(), '-' * 20)

    subprocess.run(['go', 'build', '-o', 'wsc', 'cmd/websocket_client/main.go'])
    log.info('wsc compiled')

    log.info('connect to :1034, forward: %s', forward)
    cmd =  ['./wsc', 'wsclient', f'{server_host}:{server_port}', forward, '-pass', '42', '-encPass', '42']
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as p:
        for line in p.stdout:
            j = json.loads(line.strip())
            dt, level, caller, message, role, sessionId = (j.get(k) for k in ('time', 'level', 'caller', 'message', 'role', 'sessionId'))
            fn, filename, lineno = caller.split(':')
#             if fn.startswith('github.com/emctoo/'):
#                 fn = fn[len('github.com/emctoo/'):]
#             if fn.startswith('kptunnel.'):
#                 fn = fn[len('kptunnel.'):]
#             if fn.startswith('main.'):
#                 fn = fn[len('main.'):]
            _, fn = fn.rsplit('.', 1)
            if debug:
                log.info('%-18s %13s %-4s %-32s %-3s %s', dt[11:], filename, lineno, fn, sessionId or '-', message)


def launch_echo_server(port: int) -> subprocess.Popen:
    log = logging.getLogger('echo')
    with subprocess.Popen(['socat', f'tcp-l:{port},reuseaddr,fork', 'exec:"/bin/cat"']) as p:
        log.info('echo service is ready')


class MyTCPHandler(socketserver.BaseRequestHandler):
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.count = 0

    def handle(self):
        log = logging.getLogger('echo_server')
        server_prefix = '#SERVER#'
        while True:
            buf = self.request.recv(65535)
            prefix = b'#CLIENT#'
            if buf.startswith(prefix):
                i = int.from_bytes(buf[len(prefix): len(prefix)+2], 'big')
                log.info('client request, case %s', i)

            if not buf:
                log.info('received empty bytes, exit now')
                break
            log.info('received buf: %d, echo back', len(buf))
            self.request.sendall(buf)

def echo_server(port: int, host='localhost'):
    log = logging.getLogger('echo_server')
    with socketserver.TCPServer((host, port), MyTCPHandler) as server:
        server.serve_forever()

# TODO when max=65535, error happens
def random_string(min=10, max=1024) -> string:
    return ''.join(random.choices(string.printable, k=random.randint(min, max)))

def echo_client(connections: int, rounds: int, ip='localhost', port=2022):
    log = logging.getLogger('echo')

    results = []
    for c in range(connections):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            retry = True
            while retry:
                try:
                    log.info('connecting %s:%s...', ip, port)
                    sock.connect((ip, port))
                except Exception as ex:  # most likely connection refused, because server is not ready yet
                    log.error('fail to connect, %s', ex)
                    time.sleep(1)
                else:
                    break
                    log.info('connected')

            prefix = '#CLIENT#'.encode()
            for r in range(rounds):
                content = random_string().encode()
                sent_bytes = prefix + (c * rounds + r).to_bytes(2, 'big') + len(content).to_bytes(2, 'big') + content
                log.info('%s/%s sending buf %s bytes ...', c, r, len(sent_bytes))
                sock.sendall(sent_bytes)
                buf_received = sock.recv(65535)
                correct = len(sent_bytes) == len(buf_received)
                results.append((c, r, len(sent_bytes), len(buf_received), correct))
                log.info('%s/%s received buf %s bytes, %s', c, r, len(buf_received), CHECK if correct else CROSS)
                time.sleep(random.randint(100, 100) / 1000)

    if False in [result[-1] for result in results]:
        log.info(f'{COLOR_BEGIN}{COLOR_RED}c=%s r=%s{COLOR_END} {CROSS}', connections, rounds)
    else:
        log.info(f'{COLOR_BEGIN}{COLOR_GREEN}c=%s r=%s{COLOR_END} {CHECK}', connections, rounds)

def test():
    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.submit(launch_wsc, server_host='127.0.0.1', server_port=1034, forward=':2022,127.0.0.1:2023')
        executor.submit(launch_wsd, server_host='127.0.0.1', server_port=1034)
#         executor.submit(launch_echo_server, port=2023)
        executor.submit(echo_server, port=2023)
        executor.submit(echo_client, connections=5, rounds=7)
        executor.submit(echo_client, connections=1, rounds=20, port=2022)

def debug():
    # TODO shutdown gracefully
    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.submit(launch_wsc, server_host='127.0.0.1', server_port=1035, forward=':2042,127.0.0.1:2043', debug=True)
        executor.submit(launch_wsd, server_host='127.0.0.1', server_port=1035, debug=True)
        executor.submit(launch_echo_server, port=2043)
        executor.submit(echo_client, connections=1, rounds=1, port=2042)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', default='test')
    args = parser.parse_args()
    if args.action == 'test':
        test()
    if args.action == 'debug':
        debug()

if __name__ == '__main__':
    main()
