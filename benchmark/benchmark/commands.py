# Copyright(C) Facebook, Inc. and its affiliates.
import os
import subprocess
import sys
from os.path import exists, join

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cargo build --quiet --release --features benchmark'

    @staticmethod
    def compile_env():
        env = os.environ.copy()
        if sys.platform != 'darwin':
            return env

        sdkroot = env.get('SDKROOT', '')
        if sdkroot and not sdkroot.startswith('/Library/Developer/CommandLineTools/'):
            return env

        sdk_path = CommandMaker._macos_sdk_path()
        if sdk_path:
            env['SDKROOT'] = sdk_path
        return env

    @staticmethod
    def _macos_sdk_path():
        try:
            sdk_path = subprocess.check_output(
                ['xcrun', '--sdk', 'macosx', '--show-sdk-path'],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            if sdk_path and exists(sdk_path):
                return sdk_path
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

        xcode_sdk = (
            '/Applications/Xcode.app/Contents/Developer/Platforms/'
            'MacOSX.platform/Developer/SDKs/MacOSX.sdk'
        )
        return xcode_sdk if exists(xcode_sdk) else None

    @staticmethod
    def generate_ed_key(filename):
        assert isinstance(filename, str)
        return f'./node generate_keys --filename {filename}'
    
    @staticmethod
    def generate_bls_key(filename):
        assert isinstance(filename, str)
        return f'./node generate_bls_keys --filename {filename}'

    @staticmethod
    def generate_bls_keys(total_nodes, threshold_val, path):
        assert isinstance(total_nodes, int)
        assert isinstance(threshold_val, int)
        assert isinstance(path, str)
        return f'./node generate_bls_keys --nodes {total_nodes} --threshold {threshold_val} --path {path}'


    @staticmethod
    def run_primary(edkeys,blskeys, committee, store, parameters, debug=False):
        assert isinstance(edkeys, str)
        assert isinstance(blskeys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        rust_log = 'debug' if debug else 'info'
        return (f'RUST_LOG={rust_log} ./node {v} run --edkeys {edkeys} --blskeys {blskeys} --committee {committee} '
                f'--store {store} --parameters {parameters} primary')

    @staticmethod
    def run_worker(edkeys, blskeys,committee, store, parameters, id, debug=False):
        assert isinstance(edkeys, str)
        assert isinstance(blskeys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        rust_log = 'debug' if debug else 'info'
        return (f'RUST_LOG={rust_log} ./node {v} run --edkeys {edkeys} --blskeys {blskeys} --committee {committee} '
                f'--store {store} --parameters {parameters} worker --id {id}')

    @staticmethod
    def run_client(address, size, burst, rate, nodes):
        assert isinstance(address, str)
        assert isinstance(size, int) and size > 0
        assert isinstance(burst, int) and burst > 0
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        nodes = f'--nodes {" ".join(nodes)}' if nodes else ''
        return f'RUST_LOG=info ./benchmark_client {address} --size {size} --burst {burst} --rate {rate} {nodes}'

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node, client = join(origin, 'node'), join(origin, 'benchmark_client')
        return f'rm node ; rm benchmark_client ; ln -s {node} . ; ln -s {client} .'
