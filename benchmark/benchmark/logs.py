from datetime import datetime
from glob import glob
from os.path import join
from re import findall, search
from statistics import mean

from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self, clients, nodes, faults):
        inputs = [clients, nodes]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert nodes

        self.faults = faults
        if isinstance(faults, int):
            self.committee_size = len(nodes) + int(faults)
        else:
            self.committee_size = '?'

        if clients:
            # Parse the clients logs.
            try:
                results = list(map(self._parse_clients, clients))
            except (ValueError, IndexError) as e:
                raise ParseError(f'Failed to parse client logs: {e}')
            self.size, self.rate, self.start, misses, self.sent_samples \
                = zip(*results)
            self.misses = sum(misses)
        else:
            self.size = (1,)
            self.rate = (0,)
            self.start = tuple()
            self.sent_samples = tuple()
            self.misses = 0

        # Parse the nodes logs.
        try:
            results = list(map(self._parse_nodes, nodes))
        except (ValueError, IndexError) as e:
            raise ParseError(f'Failed to parse node logs: {e}')
        proposals, commits, sizes, self.received_samples, timeouts, self.configs \
            = zip(*results)
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.commits = self._merge_results([x.items() for x in commits])
        self.sizes = {
            k: v for x in sizes for k, v in x.items() if k in self.commits
        }
        if not clients:
            tx_size = next(
                (
                    c['consensus']['tx_size']
                    for c in self.configs
                    if c['consensus']['tx_size']
                ),
                self.size[0]
            )
            self.size = (tx_size,)
            if not self.sizes:
                header_size = next(
                    (
                        c['consensus']['header_size']
                        for c in self.configs
                        if c['consensus']['header_size']
                    ),
                    0
                )
                self.sizes = {k: header_size for k in self.commits}
        self.timeouts = max(timeouts)

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(
                f'Clients missed their target rate {self.misses:,} time(s)'
            )

        # Check whether the nodes timed out.
        # Note that nodes are expected to time out once at the beginning.
        if self.timeouts > 2:
            Print.warn(f'Nodes timed out {self.timeouts:,} time(s)')

    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or merged[k] > v:
                    merged[k] = v
        return merged

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        size = int(search(r'Transactions size: (\d+)', log).group(1))
        rate = int(search(r'Transactions rate: (\d+)', log).group(1))

        tmp = search(r'\[(.*Z) .* Start ', log).group(1)
        start = self._to_posix(tmp)

        misses = len(findall(r'rate too high', log))

        tmp = findall(r'\[(.*Z) .* sample transaction (\d+)', log)
        samples = {int(s): self._to_posix(t) for t, s in tmp}

        return size, rate, start, misses, samples

    def _parse_nodes(self, log):
        if search(r'panic', log) is not None:
            raise ParseError('Node(s) panicked')

        tmp = findall(r'\[(.*Z) .* Created ([^ ]+)\n', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])

        tmp = findall(r'\[(.*Z) .* Committed ([^ ]+)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])

        tmp = findall(r'(?:Batch|Block|Header) ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        tmp = findall(r'Batch ([^ ]+) contains sample tx (\d+)', log)
        samples = {int(s): d for d, s in tmp}

        tmp = findall(r'.* WARN .* Timeout', log)
        timeouts = len(tmp)

        configs = {
            'consensus': {
                'timeout_delay': self._extract_int(r'Timeout delay .* (\d+)', log),
                'sync_retry_delay': self._extract_int(
                    r'consensus.* Sync retry delay .* (\d+)', log
                ),
                'header_size': self._extract_int(r'Header size .* (\d+)', log),
                'tx_size': self._extract_int(
                    r'Transaction size .* (\d+)', log, self.size[0]
                ),
                'rs_block_size': self._extract_int(r'RS block size .* (\d+)', log),
                'rs_block_threads': self._extract_int(r'RS block threads .* (\d+)', log),
            },
            'mempool': {
                'gc_depth': 0,
                'sync_retry_delay': 0,
                'sync_retry_nodes': 0,
                'batch_size': 0,
                'max_batch_delay': 0,
            }
        }

        return proposals, commits, sizes, samples, timeouts, configs

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _extract_int(self, pattern, log, default=0):
        match = search(pattern, log)
        return int(match.group(1)) if match else default

    def _consensus_throughput(self):
        if not self.commits:
            return 0, 0, 0
        if not self.proposals:
            return 0, 0, 0
        start, end = min(self.proposals.values()), max(self.commits.values())
        duration = end - start
        if duration <= 0:
            return 0, 0, 0
        bytes = sum(self.sizes.values())
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _consensus_latency(self):
        latency = [
            c - self.proposals[d]
            for d, c in self.commits.items()
            # if d in self.proposals
        ]
        return mean(latency) if latency else 0

    def _end_to_end_throughput(self):
        if not self.start:
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
        if not self.sent_samples:
            return 0
        latency = []
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, batch_id in received.items():
                if batch_id in self.commits:
                    assert tx_id in sent  # We receive txs that we sent.
                    start = sent[tx_id]
                    end = self.commits[batch_id]
                    latency += [end-start]
        return mean(latency) if latency else 0

    def result(self):
        header_size = self.configs[0]['consensus']['header_size']
        consensus_latency = self._consensus_latency() * 1000
        consensus_tps, consensus_bps, _ = self._consensus_throughput()
        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1000

        consensus_timeout_delay = self.configs[0]['consensus']['timeout_delay']
        consensus_sync_retry_delay = self.configs[0]['consensus']['sync_retry_delay']
        mempool_gc_depth = self.configs[0]['mempool']['gc_depth']
        mempool_sync_retry_delay = self.configs[0]['mempool']['sync_retry_delay']
        mempool_sync_retry_nodes = self.configs[0]['mempool']['sync_retry_nodes']
        mempool_batch_size = self.configs[0]['mempool']['batch_size']
        mempool_max_batch_delay = self.configs[0]['mempool']['max_batch_delay']

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            # f' Faults: {self.faults} nodes\n'
            f' Committee size: {self.committee_size} nodes\n'
            # f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Header size: {header_size:,} B\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            # f' Consensus timeout delay: {consensus_timeout_delay:,} ms\n'
            # f' Consensus sync retry delay: {consensus_sync_retry_delay:,} ms\n'
            # f' Mempool GC depth: {mempool_gc_depth:,} rounds\n'
            # f' Mempool sync retry delay: {mempool_sync_retry_delay:,} ms\n'
            # f' Mempool sync retry nodes: {mempool_sync_retry_nodes:,} nodes\n'
            # f' Mempool batch size: {mempool_batch_size:,} B\n'
            # f' Mempool max batch delay: {mempool_max_batch_delay:,} ms\n'
            # '\n'
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
    def process(cls, directory, faults):
        assert isinstance(directory, str)

        clients = []
        for filename in sorted(glob(join(directory, 'client-*.log'))):
            with open(filename, 'r') as f:
                clients += [f.read()]
        nodes = []
        for filename in sorted(glob(join(directory, 'node-*.log'))):
            with open(filename, 'r') as f:
                log = f.read()
                if log.strip():
                    nodes += [log]

        return cls(clients, nodes, faults)
