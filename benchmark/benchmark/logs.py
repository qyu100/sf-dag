# Copyright(C) Facebook, Inc. and its affiliates.
from datetime import datetime
from glob import glob
import json
from os.path import join
from re import findall, search
from statistics import mean, median
import csv
from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self, clients, primaries, consensus_only=False, debug=False):
        inputs = [primaries]

        if not consensus_only:
            inputs += [clients]

        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert all(x for x in inputs)

        self.consensus_only = consensus_only
        self.debug = debug

        # Parse the primaries logs.
        try:
            # Header is the same for all nodes.
            self.config = self._parse_config(primaries[0])

            if consensus_only:
                self.committee_size = len(primaries) + self.config['faults']
            else:
                self.committee_size = len(primaries) + self.config['faults']

            if debug and self.committee_size > 100:
                # Use a ThreadPool if we need to parse debug info for very large
                # networks. Process pools fail when the data that needs to be
                # passed between them is large enough to cause 'broken pipe' errors.
                from multiprocessing.pool import ThreadPool as Pool
            else:
                from multiprocessing import Pool

            with Pool() as p:
                results = p.map(self._parse_primary, primaries)
        except (ValueError, IndexError, AttributeError) as e:
            raise Exception(f'Failed to parse nodes\' logs: {e}')
        
        primary_ips, \
            block_proposals, \
            block_commits, \
            self.block_receipts, \
            self.block_send_ends, \
            self.ack_to_receipt_delays, \
            self.vote_creations, \
            self.vote_receipts, \
            header_proposals, \
            header_dispatches, \
            header_commits, \
            self.received_samples, \
            sizes = zip(*results)
        all_sizes = {k: v for x in sizes for k, v in x.items()}

        if not consensus_only:            
            committed_headers = [x.items() for x in header_commits]
            self.header_proposals = self._representative_results_by_digest([x.items() for x in header_proposals], True)
            self.header_dispatches = self._representative_results_by_digest([x.items() for x in header_dispatches], True)
            self.header_first_commits = self._representative_results_by_digest(committed_headers, True)
            self.header_last_commits = self._representative_results_by_digest(committed_headers, False)
            
            self.sizes = {k: v for k, v in all_sizes.items() if k in self.header_first_commits}

            # Parse the clients logs.
            try:
                with Pool() as p:
                    results = p.map(self._parse_clients, clients)
            except (ValueError, IndexError, AttributeError) as e:
                raise Exception(f'Failed to parse clients\' logs: {e}')
            self.size, self.rate, self.start, misses, self.sent_samples, self.burst \
                = zip(*results)
            self.misses = sum(misses)

            # Check whether clients missed their target rate.
            if self.misses != 0:
                Print.warn(
                    f'Clients missed their target rate {self.misses:,} time(s)'
                )

            self.collocate = True

        committed_blocks = [x.items() for x in block_commits]
        self.block_proposals = self._representative_results_by_digest([x.items() for x in block_proposals], True)
        self.block_first_commits = self._representative_results_by_digest(committed_blocks, True)
        self.block_last_commits = self._representative_results_by_digest(committed_blocks, False)
        if consensus_only:
            self.sizes = {k: v for k, v in all_sizes.items() if k in self.block_first_commits}

    # Filters the given list of results for each node (where each result
    # set is itself a list of (digest, timestamp) pairs), keeping the 
    # representative timestamp for each digest in the result set. This
    # timestamp is the least in keep_least is true, otherwise it is the
    # 2f+1th greatest (i.e. the greatest honest timestamp -- we assume that
    # Byzantine nodes want to report high values).
    def _representative_results_by_digest(self, input, keep_least):
        merged = {}
        filtered = {}
        f = (self.committee_size - 1) // 3

        # Collect all results by digest
        for node_results in input:
            for digest, timestamp in node_results:
                if not digest in merged:
                    merged[digest] = [timestamp]
                else:
                    merged[digest].append(timestamp)
        
        for digest in merged:
            # Sort the results for each digest by timestamp
            sorted_timestamps = sorted(merged[digest])
            # Consider the first 2f+1 readings honest
            honest_timestamps = sorted_timestamps[0:2*f+1]

            if keep_least:
                filtered[digest] = honest_timestamps[0]
            else:
                filtered[digest] = honest_timestamps[-1]
        
        return filtered

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise Exception('Client(s) panicked')

        size = int(search(r'Transactions size: (\d+)', log).group(1))
        rate = int(search(r'Transactions rate: (\d+)', log).group(1))
        burst = int(search(r'Burst duration (\d+)', log).group(1))

        tmp = search(r'\[(.*Z) .* Start ', log).group(1)
        start = self._to_posix(tmp)

        misses = len(findall(r'rate too high', log))

        tmp = findall(r'\[(.*Z) .* sample transaction (\d+)', log)
        samples = {int(s): self._to_posix(t) for t, s in tmp}
        

        return size, rate, start, misses, samples, burst
    
    def _map_timestamps_to_digests(self, regex, log):
        return { d: self._to_posix(t) for t, d in findall(regex, log) }
    
    def _parse_primary(self, log):
        if search(r'(?:panicked|Error)', log) is not None:
            raise Exception('Primary(s) panicked')
        
        # Consensus (SupraBFT) data
        block_proposals, block_commits = [], []
        # Consensus debug data
        block_receipts, block_send_ends, ack_to_receipt_delays, vote_creations, vote_receipts \
            = [], [], [], [], []
        # Delivery (Narwhal) data
        header_proposals, header_dispatches, header_commits, \
            ip = [], [], [], "" 
        samples, sizes = {}, {}       

        if self.debug:
            ack_times = self._map_timestamps_to_digests(
                r'\[(.*Z) .* Acking Proposal: .* Block ([^ ]+):', log)
            block_receipts = self._map_timestamps_to_digests(
                r'\[(.*Z) .* Received Normal Proposal .* Block ([^ ]+):', log)
            block_send_ends = self._map_timestamps_to_digests(r'\[(.*Z) .* Finished sending .* Block ([^ ]+):', log)
            
            ack_to_receipt_delays = {}
            for block, ack in ack_times.items():
                # The last block acked might not be processed due to forced shutdown
                if block in block_receipts:
                    ack_to_receipt_delays[block] = block_receipts[block] - ack
            
            # Vote Creations. 
            # NOTE: This produces a very large structure and is the reason why we need to 
            # use a ThreadPool instead of a process Pool when parsing debug info for
            # large networks.
            matches = findall(r'\[(.*Z) .* Created V\(([^ ]+), .*, ([^ ]+)\)', log)
            vote_creations = {}
            # Timestamp, author, digest
            for t, a, d in matches:
                if d not in vote_creations:    
                    vote_creations[d] = {a: self._to_posix(t)}
                else:
                    vote_creations[d][a] = self._to_posix(t)
            
            # Vote Receipts
            # NOTE: This produces a very large structure and is the reason why we need to 
            # use a ThreadPool instead of a process Pool when parsing debug info for
            # large networks.
            matches = findall(r'\[(.*Z) .* Received V\(([^ ]+), .*, ([^ ]+)\)', log)
            vote_receipts = {}
            # Timestamp, author, digest
            for t, a, d in matches:
                if d not in vote_receipts:    
                    vote_receipts[d] = {a: self._to_posix(t)}
                else:
                    vote_receipts[d][a] = self._to_posix(t)

        # Consensus block creation. Prefer the Lionfish-style compact line
        # ("Created <digest>") but keep the old Hydrangea CMB line compatible.
        block_proposals = self._map_timestamps_to_digests(
            r'\[(.*Z) .* Created ([^ ]+)\n', log)
        block_proposals.update(self._map_timestamps_to_digests(
            r'\[(.*Z) .* Created ([^ ]+): CMB\(.*\)', log))

        # Consensus block commit. Prefer the Lionfish-style compact line
        # ("Committed <digest> Leader|NonLeader") but keep the old CMB line compatible.
        block_commits = self._map_timestamps_to_digests(
            r'\[(.*Z) .* Committed ([^ ]+)(?: Leader| NonLeader)?\n', log)
        block_commits.update(self._map_timestamps_to_digests(
            r'\[(.*Z) .* Committed ([^ ]+): CMB\(.*\)', log))

        tmp = findall(r'Header ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        if not self.consensus_only:
            ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

            # Narwhal header creation
            header_proposals = self._map_timestamps_to_digests(
                r'\[(.*Z) .* Created Header ([^ ]+)\n', log)
            
            # Narwhal header sent to consensus
            header_dispatches = self._map_timestamps_to_digests(
                r'\[(.*Z) .* Sending Certificate for Header ([^ ]+)', log)
            
            header_commits = self._map_timestamps_to_digests(
                r'\[(.*Z) .* Committed Header ([^ ]+)\n', log)
            
            tmp = findall(r'Header ([^ ]+) contains sample tx (\d+)', log)
            samples = {int(s): d for d, s in tmp}

            sizes.update({d: int(s) for d, s in findall(r'Header ([^ ]+) contains (\d+) B', log)})

        return ip, block_proposals, block_commits, block_receipts, block_send_ends, \
            ack_to_receipt_delays, vote_creations, vote_receipts, header_proposals, \
            header_dispatches, header_commits, samples, sizes
    
    def _parse_config(self, header):
        if search(r'Timeout delay .* (\d+)', header) is None:
            with open('.parameters.json', 'r') as f:
                params = json.load(f)
            return {
                'timeout_delay': int(params['timeout_delay']),
                'header_size': int(params['header_size']),
                'tx_size': int(params.get('tx_size', 512)),
                'max_header_delay': int(params['max_header_delay']),
                'gc_depth': int(params['gc_depth']),
                'sync_retry_delay': int(params['sync_retry_delay']),
                'sync_retry_nodes': int(params['sync_retry_nodes']),
                'batch_size': int(params['batch_size']),
                'block_size': int(params['max_block_size']),
                'max_batch_delay': int(params['max_batch_delay']),
                'rs_block_size': int(params['rs_block_size']),
                'rs_block_threads': int(params['rs_block_threads']),
                'faults': 0,
                'leader_elector': str(params['leader_elector']),
                'f': str(params['f']),
                'c': str(params['c']),
                'k': str(params['k']),
            }
        return {
            'timeout_delay': int(
                search(r'Timeout delay .* (\d+)', header).group(1)
            ),
            'header_size': int(
                search(r'Header size .* (\d+)', header).group(1)
            ),
            'tx_size': int(
                search(r'Transaction size .* (\d+)', header).group(1)
            ) if search(r'Transaction size .* (\d+)', header) else 512,
            'max_header_delay': int(
                search(r'Max header delay .* (\d+)', header).group(1)
            ),
            'gc_depth': int(
                search(r'Garbage collection depth .* (\d+)', header).group(1)
            ),
            'sync_retry_delay': int(
                search(r'Sync retry delay .* (\d+)', header).group(1)
            ),
            'sync_retry_nodes': int(
                search(r'Sync retry nodes .* (\d+)', header).group(1)
            ),
            'batch_size': int(
                search(r'Batch size .* (\d+)', header).group(1)
            ),
            'block_size': int(
                search(r'Block size .* (\d+)', header).group(1)
            ),
            'max_batch_delay': int(
                search(r'Max batch delay .* (\d+)', header).group(1)
            ),
            'rs_block_size': int(
                search(r'Reed-Solomon block size .* (\d+)', header).group(1)
            ) if search(r'Reed-Solomon block size .* (\d+)', header) else 0,
            'rs_block_threads': int(
                search(r'Reed-Solomon block threads .* (\d+)', header).group(1)
            ) if search(r'Reed-Solomon block threads .* (\d+)', header) else 0,
            # TODO: Old logs will not have the below two entries so parsing
            # will throw an exception. Set an appropriate default value.
            'faults': int(
                search(r'With (\d+) faulty nodes in the network', header).group(1)
            ),
            'leader_elector': str(
                search(r'Using (.*) leader elector', header).group(1)
            ),
            'f': str(
                search(r'F value set to (\d+)', header).group(1)
            ),
            'c': str(
                search(r'C value set to (\d+)', header).group(1)
            ),
            'k': str(
                search(r'K value set to (\d+)', header).group(1)
            ),
        }
        
    def _merge_maps(self, ms):
        merged = {}
        for m in ms:
            for k in m.keys():
                if k not in merged:
                    merged[k] = {}

                for l in m[k].keys():
                    merged[k][l] = m[k][l]
        return merged
                
    def _log_debug_stats(self):
        print('Debug Stats:')
        
        block_receipts = {}
        for node_receipts in self.block_receipts:
            for block in node_receipts.keys():
                if block not in self.block_proposals:
                    continue
                if block not in block_receipts:
                    block_receipts[block] = [node_receipts[block] - self.block_proposals[block]]
                else:
                    block_receipts[block].append(node_receipts[block] - self.block_proposals[block])

        all_block_receipt_stats = {}
        for block, receipt_delays in block_receipts.items():
            all_block_receipt_stats[block] = {
                'average': mean(receipt_delays),
                'median': median(receipt_delays),
                'min': min(receipt_delays),
                'max': max(receipt_delays)
            }
        
        averages = [ stats['average'] for stats in all_block_receipt_stats.values() ]
        medians = [ stats['median'] for stats in all_block_receipt_stats.values() ]
        mins = [ stats['min'] for stats in all_block_receipt_stats.values() ]
        maxs = [ stats['max'] for stats in all_block_receipt_stats.values() ]
        block_receipt_stats = {
            'average': mean(averages) if averages else 0,
            'median': mean(medians) if medians else 0,
            'min': mean(mins) if mins else 0,
            'max': mean(maxs) if maxs else 0
        }
        
        print('Block receipt delay (ms): ' + str(block_receipt_stats))

        vote_creations = {}
        for node_creations in self.vote_creations:
            for block in node_creations.keys():
                if block not in vote_creations:
                    vote_creations[block] = {}

                for id in node_creations[block].keys():
                    vote_creations[block][id] = node_creations[block][id]

        # { vote_creator: { block_voted_for: [ delays_to_receipt... ] } }
        vote_receipt_delays = {}
        for node_receipts in self.vote_receipts:
            for block in node_receipts.keys():
                if block not in vote_creations:
                    continue
                for id in node_receipts[block].keys():
                    if id not in vote_creations[block]:
                        continue
                    delivery_time = node_receipts[block][id] - vote_creations[block][id]

                    if id not in vote_receipt_delays:
                        vote_receipt_delays[id] = {}
                    
                    if block not in vote_receipt_delays[id]:
                        vote_receipt_delays[id][block] = [delivery_time]
                    else:
                        vote_receipt_delays[id][block].append(delivery_time)

        all_vote_receipt_stats = {}
        averages = []
        medians = []
        mins = []
        maxs = []
        for vote_creator in vote_receipt_delays.keys():
            for block, receipt_delays in vote_receipt_delays[vote_creator].items():
                avg = mean(receipt_delays)
                med = median(receipt_delays)
                l = min(receipt_delays)
                h = max(receipt_delays)
                averages.append(avg)
                medians.append(med)
                mins.append(l)
                maxs.append(h)

                if vote_creator not in all_vote_receipt_stats:
                    all_vote_receipt_stats[vote_creator] = {}

                all_vote_receipt_stats[vote_creator][block] = {
                    'average': avg,
                    'median': med,
                    'min': l,
                    'max': h
                }
        
        vote_receipt_stats = {
            'average': mean(averages) if averages else 0,
            'median': mean(medians) if medians else 0,
            'min': mean(mins) if mins else 0,
            'max': mean(maxs) if maxs else 0
        }

        print('Vote receipt delay (ms): ' + str(vote_receipt_stats))

        ack_aggregates = {}
        for node_delays in self.ack_to_receipt_delays:
            for block, delay in node_delays.items():
                if block in ack_aggregates:
                    ack_aggregates[block].append(delay)
                else:
                    ack_aggregates[block] = [delay]

        averages = {}
        medians = {}
        mins = {}
        maxs = {}
        for block, agg_delays in ack_aggregates.items():
            averages[block] = mean(agg_delays)
            medians[block] = median(agg_delays)
            mins[block] = min(agg_delays)
            maxs[block] = max(agg_delays)

        ack_to_receipt_delay_stats = {
            'average': mean(averages.values()) if averages else 0,
            'median': mean(medians.values()) if medians else 0,
            'min': mean(mins.values()) if mins else 0,
            'max': mean(maxs.values()) if maxs else 0
        }
        # Time between a node sending ACK for a Block and when the Core actually starts
        # processing the Block. If this is non-zero then it indicates that the node has
        # a backlog of messages to process, which is undesirable.
        print('ACK to start of Block processing (ms): ' + str(ack_to_receipt_delay_stats))

    def _parse_workers(self, log):
        if search(r'(?:panic|Error)', log) is not None:
            raise Exception('Worker(s) panicked')

        tmp = findall(r'Batch ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        tmp = findall(r'Batch ([^ ]+) contains sample tx (\d+)', log)
        samples = {int(s): d for d, s in tmp}

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        return sizes, samples, ip

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _latency(self, proposals, commits: map):
        latency = [c - proposals[d] for d, c in commits.items() if d in proposals]
        if not latency:
            return 0, 0
        return mean(latency) * 1000, median(latency) * 1000

    def _narwhal_throughput(self, start, commits: map):
        if not commits:
            return 0, 0, 0
        end = max(commits.values())
        batches_committed = len(commits.keys())
        duration = end - start
        bytes = sum(self.sizes.values())
        bps = bytes / duration
        tps = bps / self.size[0]
        return batches_committed, tps, bps

    def _throughput(self, start, commits):
        if not commits:
            return 0, 0, 0
        end = max(commits.values())
        duration = end - start
        if duration <= 0:
            return len(commits.keys()), 0, 0
        total_commits = len(commits.keys())
        commits_per_second = total_commits / duration
        return total_commits, commits_per_second, duration

    def _consensus_tps(self, start, commits):
        if not commits:
            return 0
        end = max(commits.values())
        duration = end - start
        if duration <= 0:
            return 0

        committed = [digest for digest in commits.keys() if digest in self.block_proposals]
        if self.sizes:
            tx_size = self.config.get('tx_size', 512)
            total_tx = sum(self.sizes.get(digest, 0) for digest in committed) / tx_size
        else:
            total_tx = len(committed) * self.config['block_size']
        return total_tx / duration

    # Latency from the time a client sent a transaction to that the header 
    # containing that transaction was committed.
    def _end_to_end_latency(self, commits):
        latency = []
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, header_id in received.items():
                if header_id in commits:
                    assert tx_id in sent  # We receive txs that we sent.
                    start = sent[tx_id]
                    end = commits[header_id]
                    latency += [end-start]
        if not latency:
            return 0, 0
        return mean(latency) * 1000, median(latency) * 1000

    def _config_output(self):
        block_size = self.config['block_size']
        header_size = self.config['header_size']
        tx_size = self.config.get('tx_size', 512)
        timeout_delay = self.config['timeout_delay']
        sync_retry_delay = self.config['sync_retry_delay']
        sync_retry_nodes = self.config['sync_retry_nodes']
        rs_block_size = self.config.get('rs_block_size', 0)
        rs_block_threads = self.config.get('rs_block_threads', 0)
        faults = self.config['faults']
        leader_elector = self.config['leader_elector']

        if self.consensus_only:
            return (
                ' + CONFIG:\n'
                f' Consensus run in isolation\n'
                f' Leader elector: {leader_elector}\n'
                f' Faults: {faults} node(s)\n'
                f' Committee size: {self.committee_size} node(s)\n'
                f" F: {self.config['f']}\n"
                f" C: {self.config['c']}\n"
                f" K: {self.config['k']}\n"
                '\n'
                f' Header size: {header_size:,} B\n'
                f' Transaction size: {tx_size:,} B\n'
                f' Block size: {block_size:,} Certificates\n'
                f' Timeout delay: {timeout_delay:,} ms\n'
                f' Sync retry delay: {sync_retry_delay:,} ms\n'
                f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
                f' Reed-Solomon block size: {rs_block_size:,} B\n'
                f' Reed-Solomon block threads: {rs_block_threads:,}\n'
                '\n'
            )
        else:
            header_size = self.config['header_size']
            max_header_delay = self.config['max_header_delay']
            gc_depth = self.config['gc_depth']
            batch_size = self.config['batch_size']
            max_batch_delay = self.config['max_batch_delay']

            return (
                ' + CONFIG:\n'
                f' Leader elector: {leader_elector}\n'
                f' Faults: {faults} node(s)\n'
                f' Committee size: {self.committee_size} node(s)\n'
                f' Collocate primary and workers: {self.collocate}\n'
                f' Burst tx: {sum(self.rate)/20:,} tx\n'
                f' Transaction size: {self.size[0]:,} B\n'
                f' Burst: {self.burst[0]} \n'
                '\n'
                f' Block size: {block_size:,} Certificates\n'
                f' Timeout delay: {timeout_delay:,} ms\n'
                f' Header size: {header_size:,} B\n'
                f' Max header delay: {max_header_delay:,} ms\n'
                f' GC depth: {gc_depth:,} round(s)\n'
                f' Sync retry delay: {sync_retry_delay:,} ms\n'
                f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
                f' batch size: {batch_size:,} B\n'
                f' Max batch delay: {max_batch_delay:,} ms\n'
                '\n'
            )

    def _block_consensus_output(self):
        if not self.block_proposals:
            return (
                ' Execution time: 0 s\n'
                '\n'
                f' Consensus BLPS: 0 Block/s\n'
                f' Consensus TPS: 0 tx/s\n'
                f' Consensus latency: 0 ms\n'
            )

        first_proposal_time = min(self.block_proposals.values())

        committed, blps, duration = \
            self._throughput(first_proposal_time, self.block_first_commits)
        consensus_latency, _ = \
            self._latency(self.block_proposals, self.block_first_commits)
        consensus_tps = self._consensus_tps(first_proposal_time, self.block_first_commits)
         
        csv_file_path = f'benchmark_{self.committee_size}_{self.config["header_size"]}_{self.config["block_size"]}.csv'

        write_consensus_to_csv(round(consensus_latency), round(consensus_latency), round(blps), round(consensus_latency), round(consensus_latency), round(blps), csv_file_path)
        
        return (
            f' Execution time: {round(duration):,} s\n'
            f'\n'
            f' Consensus BLPS: {round(blps):,} Block/s\n'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n'
            f' Total Blocks Committed: {round(committed):,}\n'
        )
    
    def _narwhal_output(self):
        first_proposal_time = min(self.header_proposals.values())
        first_client_init = min(self.start)

        # Latency between transaction creation and header dispatch.
        tdl_mean, tdl_median = \
                self._end_to_end_latency(self.header_dispatches)

        # Latency between header creation and dispatch to consensus
        hdl_mean, hdl_median = \
                self._latency(self.header_proposals, self.header_dispatches)

        headers_dispatched, tps_first, bps_first = \
            self._throughput(first_proposal_time, self.header_dispatches)

        _, tps_first, bps_first = \
            self._narwhal_throughput(first_proposal_time, self.header_first_commits)
        _, tps_last, bps_last = \
            self._narwhal_throughput(first_proposal_time, self.header_last_commits)

        # Throughput and latency measurements from the boot of the first client to
        # the last commit. For shorter runs these will deviate from the other metrics
        # by a larger margin given the network often takes a few rounds to synchronize
        # due to the various processes coming online at slightly different times across
        # the different machines.
        _, end_to_end_tps_first, end_to_end_bps_first = \
            self._narwhal_throughput(first_client_init, self.header_last_commits)
        batches_committed, end_to_end_tps_last, end_to_end_bps_last = \
            self._narwhal_throughput(first_client_init, self.header_last_commits)
        e2el_mean_first, e2el_median_first = self._end_to_end_latency(self.header_first_commits)
        e2el_mean_last, e2el_median_last = self._end_to_end_latency(self.header_last_commits)

        csv_file_path = f'benchmark_{self.committee_size}_{self.config["header_size"]}_{self.config["block_size"]}.csv'
        
        bcl_mean_first, bcl_median_first = \
            self._latency(self.block_proposals, self.block_first_commits)
        bcl_mean_last, bcl_median_last = \
            self._latency(self.block_proposals, self.block_last_commits)  

        write_to_csv(round(bcl_mean_first), round(bcl_median_first), round(bcl_mean_last), round(bcl_median_last), round(e2el_mean_first), round(e2el_median_first), round(e2el_mean_last), round(e2el_median_last), round(end_to_end_tps_last), round(end_to_end_bps_last), self.burst[0], csv_file_path)

        return (
            f' Header Dispatch to Consensus:\n'
            f'   From Tx Creation:\n'
            f'     Mean Latency: {round(tdl_mean):,} ms\n'
            f'     Median Latency: {round(tdl_median):,} ms\n'
            f'   From Header Creation:\n'
            f'     Mean Latency: {round(hdl_mean):,} ms\n'
            f'     Median Latency: {round(hdl_median):,} ms\n'
            f'   Total Headers Dispatched: {round(headers_dispatched):,}\n'
            '\n'
            f' End-To-End:\n'
            f'   To First Commit:\n'
            f'     Mean Latency: {round(e2el_mean_first):,} ms\n'
            f'     Median Latency: {round(e2el_median_first):,} ms\n'
            f'     TPS: {round(end_to_end_tps_first):,} tx/s\n'
            f'     BPS: {round(end_to_end_bps_first):,} B/s\n'
            f'   To Last Commit:\n'
            f'     Mean Latency: {round(e2el_mean_last):,} ms\n'
            f'     Median Latency: {round(e2el_median_last):,} ms\n'
            f'     TPS: {round(end_to_end_tps_last):,} tx/s\n'
            f'     BPS: {round(end_to_end_bps_last):,} B/s\n'
        )

    def result(self):
        if self.debug:
            self._log_debug_stats()

        config_output = self._config_output()
        block_consensus_output = self._block_consensus_output()
        result = (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            f'Logs generated at: {datetime.now()}\n'
            '\n'
            f'{config_output}'
            ' + RESULTS:\n'
            f'{block_consensus_output}'
        )

        if self.consensus_only:
            return (
                f'{result}'
                '-----------------------------------------\n'
            )
        else:
            narwhal_output = self._narwhal_output()
            return (
                f'{result}'
                '\n'
                f'{narwhal_output}'
                '-----------------------------------------\n'
            )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, consensus_only=False, debug=False):
        assert isinstance(directory, str)
        clients = []
        primaries = []
        workers = []

        for filename in sorted(glob(join(directory, 'primary-*.log'))):
            with open(filename, 'r') as f:
                primaries += [f.read()]

        if not consensus_only:
            for filename in sorted(glob(join(directory, 'client-*.log'))):
                with open(filename, 'r') as f:
                    clients += [f.read()]

        return cls(clients, primaries, consensus_only=consensus_only, debug=debug)


def write_to_csv(mean_latency_commit_first, median_latency_commit_first, mean_latency_commit_last, median_latency_commit_last, e2e_mean_latency_first_commit, e2e_median_latency_first_commit, e2e_mean_latency_last_commit,e2e_median_latency_last_commit, end_to_end_tps_last, end_to_end_bps_last, burst, csv_file_path):
# Open the CSV file in append mode
    with open(csv_file_path, mode='a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        column_names = ['Block First Commit Mean Latency', 'Block First Commit Median Latency', 'Block Last Commit Mean Latency', 'block Last Commit Mean Latency', 'E2E First Commit Mean Latency', 'E2E First Commit Median Latency', 'E2E Last Commit Mean Latency', 'E2E Last Commit Median Latency', 'TPS', 'BPS', 'Burst']
        # If the file is empty, write the header
        if csv_file.tell() == 0:
            writer.writerow(column_names)

        # Write the extracted data to the CSV file
        writer.writerow([mean_latency_commit_first, median_latency_commit_first, mean_latency_commit_last, median_latency_commit_last, e2e_mean_latency_first_commit, e2e_median_latency_first_commit, e2e_mean_latency_last_commit, e2e_median_latency_last_commit, end_to_end_tps_last, end_to_end_bps_last, burst])


def write_consensus_to_csv(mean_latency_commit_first, median_latency_commit_first, blps_first, mean_latency_commit_last, median_latency_commit_last, blps_last, csv_file_path):
# Open the CSV file in append mode
    with open(csv_file_path, mode='a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        column_names = ['Block First Commit Mean Latency', 'Block First Commit Median Latency', 'BLPS_first', 'Block Last Commit Mean Latency', 'block Last Commit Mean Latency', 'BLPS_last']
        # If the file is empty, write the header
        if csv_file.tell() == 0:
            writer.writerow(column_names)

        # Write the extracted data to the CSV file
        writer.writerow([mean_latency_commit_first, median_latency_commit_first, blps_first, mean_latency_commit_last, median_latency_commit_last, blps_last])
