# Copyright(C) Facebook, Inc. and its affiliates.
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean

from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self, clients, primaries, workers, faults=0, consensus_only=False):
        inputs = [clients, primaries]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        if consensus_only:
            assert primaries
        else:
            assert all(x for x in inputs)

        self.consensus_only = consensus_only

        self.faults = faults
        if isinstance(faults, int):
            self.committee_size = len(primaries) + int(faults)
            self.workers = len(clients) // len(primaries) if primaries else '?'
        else:
            self.committee_size = '?'
            self.workers = '?'

        # Parse clients logs unless this is a consensus-only run.
        if not consensus_only:
            try:
                with Pool() as p:
                    results = p.map(self._parse_clients, clients)
            except (ValueError, IndexError, AttributeError) as e:
                raise ParseError(f'Failed to parse clients\' logs: {e}')
            self.size, self.rate, self.start, misses, self.sent_samples \
                = zip(*results)
            self.misses = sum(misses)
        else:
            self.size, self.rate, self.start = (), (), ()
            self.sent_samples = []
            self.misses = 0

        # Parse the primaries logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_primaries, primaries)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse nodes\' logs: {e}')
        proposals, commits, self.configs, primary_ips, self.received_samples, sizes = zip(*results)
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.commits = self._merge_results([x.items() for x in commits])
        self.sizes = {
            k: v for x in sizes for k, v in x.items() if k in self.commits
        }

        if consensus_only:
            tx_size = self.configs[0]['transaction_size'] if self.configs else 1
            self.size = (tx_size,)
            start = min(self.proposals.values()) if self.proposals else 0
            self.start = (start,)

        # Payload is produced in the primary, so there are no worker logs to compare against.
        self.collocate = True

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(
                f'Clients missed their target rate {self.misses:,} time(s)'
            )

    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or merged[k] > v:
                    merged[k] = v
        return merged

    def _search_group(self, pattern, log, error, default=None):
        match = search(pattern, log)
        if match is None:
            if default is not None:
                return default
            raise ParseError(error)
        return match.group(1)

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        size = int(self._search_group(
            r'Transactions size: (\d+)',
            log,
            'Missing transaction size in client log',
        ))
        rate = int(self._search_group(
            r'Transactions rate: (\d+)',
            log,
            'Missing transaction rate in client log',
        ))

        tmp = search(r'\[(.*Z) .* Start(?: sending transactions)?', log)
        if tmp is None:
            tmp = search(r'\[(.*Z) ', log)
        if tmp is None:
            raise ParseError('Missing timestamp in client log')
        start = self._to_posix(tmp.group(1))

        misses = len(findall(r'rate too high', log))

        tmp = findall(r'\[(.*Z) .* (?:sample transaction|Sending sample transaction) (\d+)', log)
        samples = {int(s): self._to_posix(t) for t, s in tmp}

        return size, rate, start, misses, samples

    def _parse_primaries(self, log):
        if search(r'(?:panicked|Error)', log) is not None:
            raise ParseError('Primary(s) panicked')

        tmp = findall(r'\[(.*Z) INFO  primary::proposer\] Created ([^\s]+)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])

        tmp = findall(r'\[(.*Z) INFO  primary::committer\] Committed ([^\s]+)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])

        samples = {}
        tmp = findall(r'Header ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        configs = {
            #'timeout_delay': int(
            #    search(r'Timeout delay .* (\d+)', log).group(1)
            #),
            'header_size': int(
                search(r'Header size .* (\d+)', log).group(1)
            ),
            'max_header_delay': int(
                search(r'Max header delay .* (\d+)', log).group(1)
            ),
            'gc_depth': int(
                search(r'Garbage collection depth .* (\d+)', log).group(1)
            ),
            'sync_retry_delay': int(
                search(r'Sync retry delay .* (\d+)', log).group(1)
            ),
            'sync_retry_nodes': int(
                search(r'Sync retry nodes .* (\d+)', log).group(1)
            ),
            'batch_size': int(
                search(r'Batch size .* (\d+)', log).group(1)
            ),
            'max_batch_delay': int(
                search(r'Max batch delay .* (\d+)', log).group(1)
            ),
            'transaction_size': int(
                search(r'Transaction size .* (\d+)', log).group(1)
            ),
        }

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        return proposals, commits, configs, ip, samples, sizes

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _consensus_throughput(self):
        if not self.commits:
            return 0, 0, 0
        start, end = min(self.proposals.values()), max(self.commits.values())
        duration = end - start
        bytes = sum(self.sizes.values())
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _consensus_latency(self):
        latency = [c - self.proposals[d] for d, c in self.commits.items()]
        return mean(latency) if latency else 0

    def _end_to_end_throughput(self):
        if self.consensus_only:
            return self._consensus_throughput()
        if not self.commits:
            return 0, 0, 0
        start, end = min(self.start), max(self.commits.values())
        duration = end - start
        bytes = sum(self.sizes.values())
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _end_to_end_latency(self):
        if self.consensus_only:
            return 0
        latency = []
        list_latencies = []
        first_start = 0
        set_first = True
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, batch_id in received.items():
                if batch_id in self.commits:
                    assert tx_id in sent  # We receive txs that we sent.
                    start = sent[tx_id]
                    end = self.commits[batch_id]
                    if set_first:
                        first_start = start
                        first_end = end
                        set_first = False
                    latency += [end-start]
                    list_latencies += [(start-first_start, end-first_start, end-start)]

        list_latencies.sort(key=lambda tup: tup[0])
        with open('latencies.txt', 'w') as f:
            for line in list_latencies:
                f.write(str(line[0]) + ',' + str(line[1]) + ',' + str((line[2])) + '\n')
        return mean(latency) if latency else 0

    def result(self):
        #timeout_delay = self.configs[0]['timeout_delay']
        header_size = self.configs[0]['header_size']
        max_header_delay = self.configs[0]['max_header_delay']
        gc_depth = self.configs[0]['gc_depth']
        sync_retry_delay = self.configs[0]['sync_retry_delay']
        sync_retry_nodes = self.configs[0]['sync_retry_nodes']
        batch_size = self.configs[0]['batch_size']
        max_batch_delay = self.configs[0]['max_batch_delay']

        consensus_latency = self._consensus_latency() * 1_000
        consensus_tps, consensus_bps, _ = self._consensus_throughput()
        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1_000

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Worker(s) per node: {self.workers} worker(s)\n'
            f' Collocate primary and workers: {self.collocate}\n'
            f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            #f' Timeout delay: {timeout_delay:,} ms\n'
            f' Header size: {header_size:,} B\n'
            f' Max header delay: {max_header_delay:,} ms\n'
            f' GC depth: {gc_depth:,} round(s)\n'
            f' Sync retry delay: {sync_retry_delay:,} ms\n'
            f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
            f' batch size: {batch_size:,} B\n'
            f' Max batch delay: {max_batch_delay:,} ms\n'
            '\n'
            ' + RESULTS:\n'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus BPS: {round(consensus_bps):,} B/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n'
            # '\n'
            # f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            # f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
            # f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            '-----------------------------------------\n'
        )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, faults=0, *args, **kwargs):
        assert isinstance(directory, str)

        clients = []
        for filename in sorted(glob(join(directory, 'client-*.log'))):
            with open(filename, 'r') as f:
                clients += [f.read()]
        primaries = []
        for filename in sorted(glob(join(directory, 'primary-*.log'))):
            with open(filename, 'r') as f:
                primaries += [f.read()]
        return cls(clients, primaries, [], faults=faults, *args, **kwargs)
