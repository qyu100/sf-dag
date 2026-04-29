# Copyright(C) Facebook, Inc. and its affiliates.
from fabric import task

from benchmark.local import LocalBench
from benchmark.logs import ParseError, LogParser
from benchmark.utils import Print
from benchmark.plot import Ploter, PlotError
from benchmark.instance import InstanceManager
from benchmark.remote import Bench, BenchError
from math import floor


@task
def local(ctx, debug=True, consensus_only=True, aggregate=False):
    ''' Run benchmarks on localhost '''
    bench_params = {
        'faults': 0,
        'nodes': 50,
        'workers': 1,
        'rate': 10_000,
        'tx_size': 512,
        'duration': 20,
        'burst': 50,
        'bls_threshold' : 2,
    }
    node_params = {
        'n': bench_params['nodes'], # Number of nodes
        'f': 16, #Number of Byzantine parties tolerated
        'c': 0, # Number of crash faults,
        'k': 0, # a parameter
        'max_block_size': 10,
        'consensus_only': consensus_only,
        'timeout_delay': 1000,  # ms
        'header_size': 512_000,  # bytes
        'max_header_delay': 200,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 5_000,  # ms
        'sync_retry_nodes': 3,  # number of nodes
        'batch_size': 512_000,  # bytes
        'max_batch_delay': 200,  # ms
        'rs_block_size': 16 * 1024,  # bytes
        'rs_block_threads': 8,
        'use_vote_aggregator': aggregate,
        # FailureBestCase | FailureMidCase | FailureWorstCase | FairSuccession | Simple
        'leader_elector': 'Simple',
        'threadpool_size' : 4,
    }
    try:
        ret = LocalBench(bench_params, node_params).run(debug, consensus_only)
        print(ret.result())
    except BenchError as e:
        Print.error(e)


@task
def create(ctx, nodes=1):
    ''' Create a testbed'''
    try:
        InstanceManager.make().create_instances(nodes)
    except BenchError as e:
        Print.error(e)


@task
def destroy(ctx):
    ''' Destroy the testbed '''
    try:
        InstanceManager.make().delete_instances()
    except BenchError as e:
        Print.error(e)


@task
def start(ctx):
    ''' Start at most `max` machines per data center '''
    try:
        InstanceManager.make().start_instances()
    except BenchError as e:
        Print.error(e)


@task
def stop(ctx):
    ''' Stop all machines '''
    try:
        InstanceManager.make().stop_instances()
    except BenchError as e:
        Print.error(e)


@task
def info(ctx):
    ''' Display connect information about all the available machines '''
    try:
        InstanceManager.make().print_info()
    except BenchError as e:
        Print.error(e)


@task
def install(ctx):
    ''' Install the codebase on all machines '''
    try:
        Bench(ctx).install()
    except BenchError as e:
        Print.error(e)


@task
def create_firewall(ctx):
    ''' Create firewall rules '''
    try:
        InstanceManager.make().create_firewall_rule()
    except BenchError as e:
        Print.error(e)


@task
def remote(ctx, block_size=50, debug=False, consensus_only=True, update=True, aggregate=False):
    ''' Run benchmarks on GCP '''
    
    bench_params = {
        'faults': 0,
        'nodes': [50],
        'workers': 1,
        'collocate': True,
        'rate': [100_000],
        'tx_size': 512,
        'duration': 120,
        'runs': 1,
        'burst': [0],
    }

    nodes = bench_params['nodes'][0]
    bench_params['bls_threshold'] = 2 * floor(nodes/3)

    precision = 20
    nodes = bench_params['nodes'][0]
    rate = 2000 * nodes * precision
    bench_params['rate'] = [rate]
 
    node_params = {
        'n': bench_params['nodes'][0], # Number of nodes
        'f': 16, #Number of Byzantine parties tolerated
        'c': 0, # Number of crash faults,
        'k': 0, # a parameter
        'max_block_size': block_size,
        'consensus_only': consensus_only,
        'timeout_delay': 5_000,  # ms
        'header_size': 1024_000,  # bytes
        'max_header_delay': 2000,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 5_000,  # ms
        'sync_retry_nodes': 3,  # number of nodes
        'batch_size': 1024_000,  # bytes
        'max_batch_delay': 2000,  # ms
        'rs_block_size': 16 * 1024,  # bytes
        'rs_block_threads': 8,
        'use_vote_aggregator': aggregate,
        # FailureBestCase | FailureMidCase | FailureWorstCase | FairSuccession | Simple
        'leader_elector': 'Simple',
        'threadpool_size' : 4,
    }

    try:
        Bench(ctx).run(bench_params, node_params, debug, consensus_only, update)
    except BenchError as e:
        Print.error(e)

@task
def run_clients(ctx, debug=False, consensus_only=False, update=False, aggregate=False):
    '''Run the clients'''
    bench_params = {
        'faults': 0,
        'nodes': [4],
        'workers': 1,
        'collocate': True,
        'rate': [40_000],
        'tx_size': 512,
        'duration': 20,
        'runs': 1,
        'burst': 60,
    }
    try:
        Bench(ctx).run_clients(bench_params, debug, consensus_only, update)
    except BenchError as e:
        Print.error(e)


@task
def plot(ctx):
    ''' Plot performance using the logs generated by "fab remote" '''
    plot_params = {
        'faults': [0],
        'nodes': [10],
        'workers': [1, 4, 7, 10],
        'collocate': True,
        'tx_size': 512,
        'max_latency': [2_000, 2_500]
    }
    try:
        Ploter.plot(plot_params)
    except PlotError as e:
        Print.error(BenchError('Failed to plot performance', e))


@task
def kill(ctx):
    ''' Stop execution on all machines '''
    try:
        Bench(ctx).kill()
    except BenchError as e:
        Print.error(e)


@task
def logs(ctx, dir='./logs', consensus_only=False, debug=False):
    ''' Print a summary of the logs '''
    try:
        print(LogParser.process(dir, consensus_only=consensus_only, debug=debug).result())
    except ParseError as e:
        Print.error(BenchError('Failed to parse logs', e))

@task
def download_logs(ctx, consensus_only=False):
    ''' Download logs from the currently running network '''
    try:
        Bench(ctx).download_logs(consensus_only)
    except BenchError as e:
        Print.error(e)
