# Copyright(C) Facebook, Inc. and its affiliates.
import os
import platform
from os.path import abspath, dirname, exists, join

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
    def cargo_home():
        return join(abspath(join(dirname(__file__), '..', '..')), '.cargo-home')

    @staticmethod
    def compile_shell():
        return (
            'CARGO_HOME=../.cargo-home '
            'CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse '
            f'{CommandMaker.compile()}'
        )

    @staticmethod
    def compile_env():
        env = os.environ.copy()
        env['CARGO_HOME'] = CommandMaker.cargo_home()
        env['CARGO_REGISTRIES_CRATES_IO_PROTOCOL'] = 'sparse'

        xcode_sdk = (
            '/Applications/Xcode.app/Contents/Developer/Platforms/'
            'MacOSX.platform/Developer/SDKs/MacOSX.sdk'
        )
        if (
            platform.system() != 'Darwin'
            or os.environ.get('SDKROOT')
            or not exists(xcode_sdk)
        ):
            return env

        env['SDKROOT'] = xcode_sdk
        return env

    @staticmethod
    def generate_key(filename):
        assert isinstance(filename, str)
        return f'./node generate_keys --filename {filename}'

    @staticmethod
    def run_primary(keys, committee, store, parameters, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'./node {v} run --keys {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} primary')

    @staticmethod
    def run_worker(keys, committee, store, parameters, id, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'./node {v} run --keys {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} worker --id {id}')

    @staticmethod
    def run_client(address, size, rate, nodes):
        assert isinstance(address, str)
        assert isinstance(size, int) and size > 0
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        nodes = f'--nodes {" ".join(nodes)}' if nodes else ''
        return f'./benchmark_client {address} --size {size} --rate {rate} {nodes}'

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node, client = join(origin, 'node'), join(origin, 'benchmark_client')
        return f'rm node ; rm benchmark_client ; ln -s {node} . ; ln -s {client} .'
