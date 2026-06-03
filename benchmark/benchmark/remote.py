# Copyright(C) Facebook, Inc. and its affiliates.
from collections import OrderedDict
from datetime import datetime
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from os import listdir, makedirs
from os.path import basename, exists, isfile, join, splitext
from shutil import copy2
from time import sleep
from math import ceil
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

from benchmark.config import (
    Committee,
    Key,
    NodeParameters,
    BenchParameters,
    ConfigError,
)
from benchmark.utils import BenchError, Print, PathMaker, progress_bar
from benchmark.commands import CommandMaker
from benchmark.logs import LogParser, ParseError
from benchmark.gcp_instance import InstanceManager


class FabricError(Exception):
    """Wrapper for Fabric exception with a meaningfull error message."""

    def __init__(self, error):
        assert isinstance(error, GroupException)
        message = list(error.result.values())[-1]
        super().__init__(message)


class ExecutionError(Exception):
    pass


class Bench:
    MAX_PARALLEL_SSH = 32

    def __init__(self, ctx):
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        try:
            ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(
                self.manager.settings.key_path
            )
            self.connect = ctx.connect_kwargs
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError("Failed to load SSH key", e)

    def _check_stderr(self, output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)

    def install(self):
        Print.info("Installing rust and cloning the repo...")
        cmd = [
            "sudo apt-get update",
            "sudo apt-get -y upgrade",
            "sudo apt-get -y autoremove",
            # The following dependencies prevent the error: [error: linker `cc` not found].
            "sudo apt-get -y install build-essential",
            "sudo apt-get -y install cmake",
            # Install rust (non-interactive).
            'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
            "source $HOME/.cargo/env",
            "rustup default stable",
            # This is missing from the Rocksdb installer (needed for Rocksdb).
            "sudo apt-get install -y clang",
            # Clone the repo.
            f"(git clone {self.settings.repo_url} || (cd {self.settings.repo_name} ; git pull))",
        ]
        hosts = self.manager.hosts(flat=True)
        print(hosts)
        try:
            g = Group(*hosts, user=self.settings.username, connect_kwargs=self.connect)
            g.run(" && ".join(cmd), hide=True)
            Print.heading(f"Initialized testbed of {len(hosts)} nodes")
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError("Failed to install repo on testbed", e)

    def kill(self, hosts=[], delete_logs=False):
        assert isinstance(hosts, list)
        assert isinstance(delete_logs, bool)
        hosts = hosts if hosts else self.manager.hosts(flat=True)
        delete_logs = CommandMaker.clean_logs() if delete_logs else "true"
        cmd = [delete_logs, f"({CommandMaker.kill()} || true)"]
        try:
            g = Group(*hosts, user=self.settings.username, connect_kwargs=self.connect)
            g.run(" && ".join(cmd), hide=True)
        except GroupException as e:
            raise BenchError("Failed to kill nodes", FabricError(e))

    def _select_hosts(self, bench_parameters):
        # Collocate the primary and its workers on the same machine.
        if bench_parameters.collocate:
            nodes = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.hosts()
            if sum(len(x) for x in hosts.values()) < nodes:
                return []

            # Select the hosts in different data centers.
            ordered = zip(*hosts.values())
            ordered = [x for y in ordered for x in y]
            return ordered[:nodes]

        # Spawn the primary and each worker on a different machine. Each
        # authority runs in a single data center.
        else:
            primaries = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.hosts()
            if len(hosts.keys()) < primaries:
                return []
            for ips in hosts.values():
                if len(ips) < bench_parameters.workers + 1:
                    return []

            # Ensure the primary and its workers are in the same region.
            selected = []
            for region in list(hosts.keys())[:primaries]:
                ips = list(hosts[region])[: bench_parameters.workers + 1]
                selected.append(ips)
            return selected

    def _select_hosts_config(self, bench_parameters):
        # Collocate the primary and its workers on the same machine.
        if bench_parameters.collocate:
            nodes = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.internal_hosts()
            if sum(len(x) for x in hosts.values()) < nodes:
                return []

            # Select the hosts in different data centers.
            ordered = zip(*hosts.values())
            ordered = [x for y in ordered for x in y]
            return ordered[:nodes]

        # Spawn the primary and each worker on a different machine. Each
        # authority runs in a single data center.
        else:
            primaries = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.internal_hosts()
            if len(hosts.keys()) < primaries:
                return []
            for ips in hosts.values():
                if len(ips) < bench_parameters.workers + 1:
                    return []

            # Ensure the primary and its workers are in the same region.
            selected = []
            for region in list(hosts.keys())[:primaries]:
                ips = list(hosts[region])[: bench_parameters.workers + 1]
                selected.append(ips)
            return selected

    def _background_run(self, host, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'tmux new -d -s "{name}" "{command} |& tee {log_file}"'
        c = Connection(host, user=self.settings.username, connect_kwargs=self.connect)
        output = c.run(cmd, hide=True)
        self._check_stderr(output)

    def _run_parallel(self, action, items, label):
        items = list(items)
        if not items:
            return

        workers = min(self.MAX_PARALLEL_SSH, len(items))
        Print.info(f"{label} ({len(items)} task(s), up to {workers} parallel)...")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(action, item) for item in items]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    raise ExecutionError(f"{label} failed: {e}") from e

    def _upload_config_one(self, item):
        ip, key_file = item
        c = Connection(ip, user=self.settings.username, connect_kwargs=self.connect)
        c.run(f"{CommandMaker.cleanup()} || true", hide=True)
        c.put(PathMaker.committee_file(), ".")
        c.put(key_file, ".")
        c.put(PathMaker.parameters_file(), ".")

    def _download_log_one(self, item):
        host, remote, local = item
        c = Connection(host, user=self.settings.username, connect_kwargs=self.connect)
        c.get(remote, local=local)

    def _update(self, hosts, collocate):
        if collocate:
            ips = list(set(hosts))
        else:
            ips = list(set([x for y in hosts for x in y]))

        Print.info(f'Updating {len(ips)} machines (branch "{self.settings.branch}")...')
        cmd = [
            f"(cd {self.settings.repo_name} && git fetch -f)",
            f"(cd {self.settings.repo_name} && git checkout -f {self.settings.branch})",
            f"(cd {self.settings.repo_name} && git pull -f)",
            "source $HOME/.cargo/env",
            f"(cd {self.settings.repo_name}/node && {CommandMaker.compile_shell()})",
            CommandMaker.alias_binaries(f"./{self.settings.repo_name}/target/release/"),
        ]
        g = Group(*ips, user=self.settings.username, connect_kwargs=self.connect)
        g.run(" && ".join(cmd), hide=True)

    def _config(self, hosts, node_parameters, bench_parameters):
        Print.info("Generating configuration files...")

        # Cleanup all local configuration files.
        cmd = CommandMaker.cleanup()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Recompile the latest code.
        cmd = CommandMaker.compile().split()
        subprocess.run(
            cmd,
            check=True,
            cwd=PathMaker.node_crate_path(),
            env=CommandMaker.compile_env(),
        )

        # Create alias for the client and nodes binary.
        cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
        subprocess.run([cmd], shell=True)

        # Generate configuration files.
        keys = []
        key_files = [PathMaker.key_file(i) for i in range(len(hosts))]
        for filename in key_files:
            cmd = CommandMaker.generate_key(filename).split()
            subprocess.run(cmd, check=True)
            keys += [Key.from_file(filename)]

        names = [x.name for x in keys]

        if bench_parameters.collocate:
            workers = bench_parameters.workers
            addresses = OrderedDict(
                (x, [y] * (workers + 1)) for x, y in zip(names, hosts)
            )
        else:
            addresses = OrderedDict((x, y) for x, y in zip(names, hosts))
        committee = Committee(addresses, self.settings.base_port)
        committee.print(PathMaker.committee_file())

        node_parameters.print(PathMaker.parameters_file())

        # Cleanup all nodes and upload configuration files.
        names = names[: len(names) - bench_parameters.faults]
        upload_tasks = []
        for i, name in enumerate(names):
            for ip in committee.ips(name):
                upload_tasks.append((ip, PathMaker.key_file(i)))
        self._run_parallel(self._upload_config_one, upload_tasks, "Uploading config files")

        return committee

    def _run_single(self, rate, committee, bench_parameters, debug=False):
        faults = bench_parameters.faults

        # Kill any potentially unfinished run and delete logs.
        hosts = committee.ips()
        self.kill(hosts=hosts, delete_logs=True)

        # Run the clients (they will wait for the nodes to be ready).
        # Filter all faulty nodes from the client addresses (or they will wait
        # for the faulty nodes to be online).
        workers_addresses = committee.workers_addresses(faults)
        rate_share = ceil(rate / committee.workers())
        client_tasks = []
        for i, addresses in enumerate(workers_addresses):
            for id, address in addresses:
                host = Committee.ip(address)
                cmd = CommandMaker.run_client(
                    address,
                    bench_parameters.tx_size,
                    rate_share,
                    [x for y in workers_addresses for _, x in y],
                )
                print(cmd)
                log_file = PathMaker.client_log_file(i, id)
                client_tasks.append((host, cmd, log_file))
        self._run_parallel(
            lambda item: self._background_run(*item),
            client_tasks,
            "Booting clients",
        )

        # Run the primaries (except the faulty ones).
        primary_tasks = []
        for i, address in enumerate(committee.primary_addresses(faults)):
            host = Committee.ip(address)
            cmd = CommandMaker.run_primary(
                PathMaker.key_file(i),
                PathMaker.committee_file(),
                PathMaker.db_path(i),
                PathMaker.parameters_file(),
                debug=debug,
            )
            print(cmd)
            log_file = PathMaker.primary_log_file(i)
            primary_tasks.append((host, cmd, log_file))
        self._run_parallel(
            lambda item: self._background_run(*item),
            primary_tasks,
            "Booting primaries",
        )

        # Run the workers (except the faulty ones).
        worker_tasks = []
        for i, addresses in enumerate(workers_addresses):
            for id, address in addresses:
                host = Committee.ip(address)
                cmd = CommandMaker.run_worker(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i, id),
                    PathMaker.parameters_file(),
                    id,  # The worker's id.
                    debug=debug,
                )
                print(cmd)
                log_file = PathMaker.worker_log_file(i, id)
                worker_tasks.append((host, cmd, log_file))
        self._run_parallel(
            lambda item: self._background_run(*item),
            worker_tasks,
            "Booting workers",
        )

        # Wait for all transactions to be processed.
        duration = bench_parameters.duration
        for i in progress_bar(range(20), prefix=f"Running benchmark ({duration} sec):"):
            tick_size = ceil(duration / 20)
            # print(tick_size, i, bench_parameters.partition_start, bench_parameters.simulate_partition)
            if (
                bench_parameters.simulate_partition
                and i * tick_size == bench_parameters.partition_start
            ):
                print("simulating partition")
                self._simulate_partition(bench_parameters, committee, faults)

            if (
                bench_parameters.simulate_partition
                and i * tick_size
                == bench_parameters.partition_start
                + bench_parameters.partition_duration
            ):
                print("deleting partition")
                self._delete_partition(bench_parameters, committee, faults)

            sleep(ceil(duration / 20))
        self.kill(hosts=hosts, delete_logs=False)

    def _simulate_partition(self, bench_parameters, committee, faults):
        partition_ips = []
        for i, address in enumerate(committee.primary_addresses(faults)):
            if i < bench_parameters.partition_nodes:
                print(i, address)
                cmd = []
                # cmd = ['sudo tc qdisc del dev ens4 root']
                cmd.append("sudo tc qdisc add dev ens4 root handle 1: htb")
                cmd.append(
                    "sudo tc class add dev ens4 parent 1: classid 1:1 htb rate 10gibps"
                )
                idx = 2
                for j, addr in enumerate(committee.primary_addresses(faults)):
                    if i == j:
                        continue
                    cmd.append(
                        "sudo tc class add dev ens4 parent 1:1 classid 1:"
                        + str(idx)
                        + " htb rate 10gibps"
                    )
                    cmd.append(
                        "sudo tc qdisc add dev ens4 handle "
                        + str(idx)
                        + ": parent 1:"
                        + str(idx)
                        + " netem delay 5000ms"
                    )
                    cmd.append(
                        "sudo tc filter add dev ens4 pref "
                        + str(idx)
                        + " protocol ip u32 match ip dst "
                        + Committee.ip(addr)
                        + " flowid 1:"
                        + str(idx)
                    )
                    idx = idx + 1
                ip = [Committee.ip(address)]
                g = Group(*ip, user=self.settings.username, connect_kwargs=self.connect)
                g.run(" && ".join(cmd), hide=True)

        # hosts = committee.ips()
        # cmd = ['sudo iptables -A OUTPUT -d ' + ip + ' -j DROP' for ip in partition_ips]
        # cmd = ['sudo tc qdisc add dev ens4 root netem delay 5000ms']

        # g = Group(*partition_ips, user='neilgiridharan', connect_kwargs=self.connect)
        # g.run(' && '.join(cmd), hide=True)

        # for i, address in enumerate(committee.primary_addresses(faults)):

        # host = Committee.ip(address)
        # for partition_ip in partition_ips:
        # cmd = 'sudo iptables -A OUTPUT -d ' + partition_ip + '-j DROP'

        ##log_file = PathMaker.primary_log_file(i)
        # self._background_run(host, cmd, log_file)

    def _delete_partition(self, bench_parameters, committee, faults):
        partition_ips = []
        for i, address in enumerate(committee.primary_addresses(faults)):
            if i < bench_parameters.partition_nodes:
                partition_ips = [Committee.ip(address)]
                cmd = ["sudo tc qdisc del dev ens4 root"]
                g = Group(
                    *partition_ips,
                    user=self.settings.username,
                    connect_kwargs=self.connect,
                )
                g.run(" && ".join(cmd), hide=True)

        # hosts = committee.ips()
        # cmd = ['sudo iptables -F']
        # cmd = ['sudo tc qdisc del dev ens4 root']
        # g = Group(*partition_ips, user='neilgiridharan', connect_kwargs=self.connect)
        # g.run(' && '.join(cmd), hide=True)

        # for i, address in enumerate(committee.primary_addresses(faults)):
        #    host = Committee.ip(address)
        #    cmd = 'sudo iptables -F'
        #    log_file = PathMaker.primary_log_file(i)
        #    self._background_run(host, cmd, log_file)

    def _download_logs(self, committee, faults):
        # Delete local logs (if any).
        cmd = CommandMaker.clean_logs()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Download log files.
        download_tasks = []
        workers_addresses = committee.workers_addresses(faults)
        for i, addresses in enumerate(workers_addresses):
            for id, address in addresses:
                host = Committee.ip(address)
                client_log = PathMaker.client_log_file(i, id)
                worker_log = PathMaker.worker_log_file(i, id)
                download_tasks.append((host, client_log, client_log))
                download_tasks.append((host, worker_log, worker_log))

        primary_addresses = committee.primary_addresses(faults)
        for i, address in enumerate(primary_addresses):
            host = Committee.ip(address)
            primary_log = PathMaker.primary_log_file(i)
            download_tasks.append((host, primary_log, primary_log))
        self._run_parallel(self._download_log_one, download_tasks, "Downloading logs")

    def _parse_logs(self, faults):
        # Parse logs and return the parser.
        Print.info("Parsing logs and computing performance...")
        return LogParser.process(PathMaker.logs_path(), faults=faults)

    def _logs(self, committee, faults):
        self._download_logs(committee, faults)
        return self._parse_logs(faults)

    def _backup_logs(self, faults, nodes, workers, run, rate, tx_size, status, summary=None):
        log_path = PathMaker.logs_path()
        if not exists(log_path):
            return

        log_files = [
            name
            for name in sorted(listdir(log_path))
            if isfile(join(log_path, name))
        ]
        if not log_files:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
        branch = str(self.settings.branch).replace("/", "_")
        status = str(status).replace(" ", "_")
        backup_dir = join(
            PathMaker.backup_logs_path(),
            f"{timestamp}-{branch}-{nodes}nodes-{workers}workers-run{run}-rate{rate}-tx{tx_size}-{status}",
        )
        makedirs(backup_dir, exist_ok=True)

        for name in log_files:
            copy2(join(log_path, name), join(backup_dir, name))

        with open(join(backup_dir, "run-info.txt"), "w") as f:
            f.write(f"status: {status}\n")
            f.write(f"branch: {self.settings.branch}\n")
            f.write(f"faults: {faults}\n")
            f.write(f"nodes: {nodes}\n")
            f.write(f"workers: {workers}\n")
            f.write(f"run: {run}\n")
            f.write(f"rate: {rate}\n")
            f.write(f"tx_size: {tx_size}\n")

        if summary:
            with open(join(backup_dir, "summary.txt"), "w") as f:
                f.write(summary)

        Print.info(f"Backed up logs to {backup_dir}")

    def run(self, bench_parameters_dict, node_parameters_dict, debug=False, update=True):
        assert isinstance(debug, bool)
        assert isinstance(update, bool)
        Print.heading("Starting remote benchmark")
        try:
            bench_parameters = BenchParameters(bench_parameters_dict)
            node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError("Invalid nodes or bench parameters", e)

        # Select which hosts to use.
        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn("There are not enough instances available")
            return

        # Update nodes.
        print(selected_hosts)
        if update:
            try:
                self._update(selected_hosts, bench_parameters.collocate)
            except (GroupException, ExecutionError) as e:
                e = FabricError(e) if isinstance(e, GroupException) else e
                raise BenchError("Failed to update nodes", e)
        else:
            Print.info("Skipping remote update/build (--no-update)")

        # Upload all configuration files.
        try:
            committee = self._config(selected_hosts, node_parameters, bench_parameters)
        except (subprocess.SubprocessError, GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError("Failed to configure nodes", e)

        # Run benchmarks.
        for n in bench_parameters.nodes:
            committee_copy = deepcopy(committee)
            committee_copy.remove_nodes(committee.size() - n)

            for r in bench_parameters.rate:
                Print.heading(f"\nRunning {n} nodes (input rate: {r:,} tx/s)")

                # Run the benchmark.
                for i in range(bench_parameters.runs):
                    Print.heading(f"Run {i+1}/{bench_parameters.runs}")
                    faults = bench_parameters.faults
                    logs_downloaded = False
                    try:
                        self._run_single(r, committee_copy, bench_parameters, debug)

                        self._download_logs(committee_copy, faults)
                        logs_downloaded = True
                        logger = self._parse_logs(faults)
                        summary = logger.result()
                        with open(
                            PathMaker.result_file(
                                faults,
                                n,
                                bench_parameters.workers,
                                bench_parameters.collocate,
                                r,
                                bench_parameters.tx_size,
                            ),
                            "a",
                        ) as f:
                            f.write(summary)
                        self._backup_logs(
                            faults,
                            n,
                            bench_parameters.workers,
                            i + 1,
                            r,
                            bench_parameters.tx_size,
                            "success",
                            summary,
                        )
                    except (
                        subprocess.SubprocessError,
                        GroupException,
                        ExecutionError,
                        ParseError,
                    ) as e:
                        self.kill(hosts=selected_hosts)
                        if isinstance(e, GroupException):
                            e = FabricError(e)
                        if logs_downloaded:
                            try:
                                self._backup_logs(
                                    faults,
                                    n,
                                    bench_parameters.workers,
                                    i + 1,
                                    r,
                                    bench_parameters.tx_size,
                                    "failed",
                                    f"Benchmark failed: {type(e).__name__}: {e}\n",
                                )
                            except Exception as backup_error:
                                Print.warn(f"Failed to back up logs: {backup_error}")
                        Print.error(BenchError("Benchmark failed", e))
                        continue
