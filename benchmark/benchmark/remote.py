# Copyright(C) Facebook, Inc. and its affiliates.
import asyncio
import shlex
import subprocess
import traceback
from math import ceil
from os.path import basename, splitext
from subprocess import SubprocessError
from time import sleep

import asyncssh
from paramiko.ssh_exception import PasswordRequiredException, SSHException

from benchmark.commands import CommandMaker
from benchmark.config import BenchParameters, Committee, ConfigError, Key, NodeParameters
from benchmark.instance import InstanceManager
from benchmark.logs import LogParser, ParseError
from benchmark.utils import BenchError, PathMaker, Print, progress_bar


class Bench:
    def __init__(self, ctx):
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        self.hosts_to_connections = {}
        try:
            self.connect_options = {
                "client_keys": [self.manager.settings.key_path],
                "connect_timeout": 30,
                "keepalive_interval": 10,
                "keepalive_count_max": 60,
                "known_hosts": None,
                "login_timeout": 30,
                "username": "ubuntu",
            }
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError("Failed to load SSH key", e)

    def _parse_task_results(self, func, hosts_and_results, verbose=False):
        for host, result in hosts_and_results:
            if isinstance(result, Exception):
                print(f"{func} failed on {host}: {result}")
                raise result
            if verbose and getattr(result, "exit_status", 0):
                print(f"{func} exited with status {result.exit_status} on {host}")
                print(result.stderr, end="")

    async def _gather_and_parse(self, tasks, func, verbose=False):
        hosts_and_results = await asyncio.gather(*tasks, return_exceptions=True)
        self._parse_task_results(func, hosts_and_results, verbose)
        return hosts_and_results

    async def _try_connect(self, host):
        failures = 0
        retries = 5
        while failures < retries:
            try:
                return host, await asyncssh.connect(host, **self.connect_options)
            except Exception:
                failures += 1
                await asyncio.sleep(2)
        return host, Exception("Failed to connect to host")

    async def _try_connect_all(self, hosts):
        tasks = [self._try_connect(host) for host in hosts]
        return await self._gather_and_parse(tasks, "Connect")

    def install(self):
        asyncio.get_event_loop().run_until_complete(self._install())

    async def _install_one(self, host, connection):
        deploy_key = self.settings.key_name
        repo = self.settings.repo_name
        repo_url = self.settings.repo_url
        branch = self.settings.branch
        try:
            async with connection.start_sftp_client() as sftp:
                await sftp.put(self.settings.key_path, f"/home/ubuntu/{deploy_key}", preserve=True)

            git_ssh = (
                f"GIT_SSH_COMMAND='ssh -i /home/ubuntu/{deploy_key} "
                "-o StrictHostKeyChecking=no'"
            )
            cmd = " && ".join(
                [
                    "cd /home/ubuntu",
                    f"chmod 600 {deploy_key}",
                    f"(test -d {repo} || {git_ssh} git clone {repo_url} {repo})",
                    f"cd {repo}",
                    f"git checkout {branch}",
                    f"{git_ssh} git pull --ff-only",
                    "cd node",
                    CommandMaker.compile(),
                    "cd ../benchmark",
                    CommandMaker.alias_binaries(PathMaker.binary_path()),
                ]
            )
            result = await connection.run(cmd, check=True)
            return host, result
        except Exception as e:
            return host, Exception(f"Failed to install on {host} because of {e}")

    async def _install(self):
        Print.info("Installing and compiling the repo...")
        hosts = self.manager.hosts(flat=True)
        hosts_and_connections = await self._try_connect_all(hosts)
        tasks = [self._install_one(h, c) for h, c in hosts_and_connections]
        await self._gather_and_parse(tasks, "Install")
        Print.heading(f"Initialized testbed of {len(hosts)} nodes")

    def kill(self):
        asyncio.get_event_loop().run_until_complete(self._kill())

    async def _kill_one(self, host, connection, cmd):
        try:
            result = await connection.run(cmd)
            return host, result
        except asyncssh.ChannelOpenError:
            try:
                print(f"SSH connection to {host} closed. Attempting to reconnect...")
                connection = await asyncssh.connect(host, **self.connect_options)
                self.hosts_to_connections[host] = connection
                result = await connection.run(cmd)
                return host, result
            except Exception as e:
                return host, Exception(f"Failed to reconnect to {host} because of {e}")
        except Exception as e:
            return host, Exception(f"Failed to kill {host} because of {e}")

    async def _kill(self, hosts_to_connections=None, delete_logs=False):
        if hosts_to_connections is None:
            hosts_to_connections = {}
        assert isinstance(hosts_to_connections, dict)
        assert isinstance(delete_logs, bool)

        if not hosts_to_connections:
            hosts = self.manager.hosts(flat=True)
            hosts_and_connections = await self._try_connect_all(hosts)
            hosts_to_connections = {h: c for h, c in hosts_and_connections}

        repo = self.settings.repo_name
        remote_dir = f"/home/ubuntu/{repo}/benchmark"
        delete_logs = CommandMaker.clean_logs() if delete_logs else "true"
        cmd = (
            f"((cd {remote_dir} && {delete_logs}) || true) && "
            f"({CommandMaker.kill()} || true)"
        )
        tasks = [self._kill_one(h, c, cmd) for h, c in hosts_to_connections.items()]
        await self._gather_and_parse(tasks, "Kill")

    def _select_hosts(self, bench_parameters):
        nodes = max(bench_parameters.nodes)
        hosts_by_region = self.manager.hosts()
        if sum(len(x) for x in hosts_by_region.values()) < nodes:
            return []

        ordered = zip(*hosts_by_region.values())
        ordered = [x for group in ordered for x in group]
        remaining = [x for xs in hosts_by_region.values() for x in xs if x not in ordered]
        return (ordered + remaining)[:nodes]

    async def _run_on_host(self, host, cmd, log, connection):
        try:
            name = splitext(basename(log))[0]
            quoted = shlex.quote(f"{cmd} |& tee {log}")
            tmux = f'tmux new -d -s "{name}" {quoted}'
            result = await connection.create_process(tmux)
            return host, result
        except asyncssh.ChannelOpenError:
            try:
                print(f"SSH connection to {host} closed. Attempting to reconnect...")
                connection = await asyncssh.connect(host, **self.connect_options)
                self.hosts_to_connections[host] = connection
                result = await connection.create_process(tmux)
                return host, result
            except Exception as e:
                return host, Exception(f"Failed to reconnect to {host} because of {e}")
        except Exception as e:
            return host, Exception(f"Failed to run {cmd} on {host} because of {e}")

    async def _update_one(self, host, connection):
        deploy_key = self.settings.key_name
        repo = self.settings.repo_name
        repo_url = self.settings.repo_url
        branch = self.settings.branch
        git_ssh = (
            f"GIT_SSH_COMMAND='ssh -i /home/ubuntu/{deploy_key} "
            "-o StrictHostKeyChecking=no'"
        )
        cmd = " && ".join(
            [
                "cd /home/ubuntu",
                f"chmod 600 {deploy_key} || true",
                f"(test -d {repo} || {git_ssh} git clone {repo_url} {repo})",
                f"cd {repo}",
                f"git checkout {branch}",
                f"{git_ssh} git pull --ff-only",
                "cd node",
                CommandMaker.compile(),
                "cd ../benchmark",
                CommandMaker.alias_binaries(PathMaker.binary_path()),
            ]
        )
        try:
            result = await connection.run(cmd, check=True)
            return host, result
        except Exception as e:
            return host, Exception(f"Failed to update {host} because of {e}")

    @staticmethod
    def _format_remote_error(result):
        stderr = getattr(result, "stderr", "")
        stdout = getattr(result, "stdout", "")
        status = getattr(result, "exit_status", None)
        parts = []
        if status is not None:
            parts.append(f"exit status {status}")
        if stderr:
            parts.append(stderr.strip())
        if stdout:
            parts.append(stdout.strip())
        return "; ".join(parts) if parts else str(result)

    async def _upload_config(self, connection, node_id):
        repo = self.settings.repo_name
        remote_dir = f"/home/ubuntu/{repo}/benchmark"
        result = await connection.run(f"test -d {remote_dir}")
        if result.exit_status:
            raise Exception(
                f"Remote benchmark directory is missing: {remote_dir}. "
                "Run fab install or check repo.name/repo.branch. "
                f"Remote error: {self._format_remote_error(result)}"
            )
        await connection.run(f"cd {remote_dir} && ({CommandMaker.cleanup()} || true)", check=True)
        async with connection.start_sftp_client() as sftp:
            await sftp.put(PathMaker.committee_file(), remote_dir, preserve=True)
            await sftp.put(PathMaker.key_file(node_id), remote_dir, preserve=True)
            await sftp.put(PathMaker.parameters_file(), remote_dir, preserve=True)

    def _generate_config(self, hosts, node_parameters):
        Print.info("Generating configuration files...")

        subprocess.run(CommandMaker.cleanup(), shell=True, stderr=subprocess.DEVNULL)

        cmd = CommandMaker.compile()
        subprocess.run(cmd, shell=True, check=True, cwd=PathMaker.node_crate_path())

        cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
        subprocess.run(cmd, shell=True, check=True)

        keys = []
        key_files = [PathMaker.key_file(i) for i in range(len(hosts))]
        for filename in key_files:
            cmd = CommandMaker.generate_key(filename).split()
            subprocess.run(cmd, check=True)
            keys.append(Key.from_file(filename))

        names = [x.name for x in keys]
        consensus = [f"{host}:{self.settings.consensus_port}" for host in hosts]
        front = [f"{host}:{self.settings.front_port}" for host in hosts]
        mempool = [f"{host}:{self.settings.mempool_port}" for host in hosts]
        committee = Committee(names, consensus, front, mempool)
        committee.print(PathMaker.committee_file())
        node_parameters.print(PathMaker.parameters_file())
        return committee

    async def _configure_one(self, host, node_id, connection, update=True):
        try:
            if update:
                updated = await self._update_one(host, connection)
                if isinstance(updated[1], Exception):
                    return updated
            await self._upload_config(connection, node_id)
            return host, None
        except Exception as e:
            return host, Exception(f"Failed to configure {host} because of {e}")

    async def _configure(self, committee_hosts, active_hosts, node_parameters, update=True):
        try:
            committee = self._generate_config(committee_hosts, node_parameters)
        except SubprocessError as e:
            traceback.print_exc()
            raise BenchError("Failed to configure nodes", e)

        msg = "Uploading configuration files"
        if update:
            msg += f" and updating {self.settings.repo_name}:{self.settings.branch}"
        Print.info(msg + f" on {len(active_hosts)} machines...")

        tasks = [
            self._configure_one(host, i, self.hosts_to_connections[host], update)
            for i, host in enumerate(active_hosts)
        ]
        await self._gather_and_parse(tasks, "Configure")
        Print.info(f"Successfully configured {len(active_hosts)} machines")
        return committee

    async def _run_nodes(self, hosts, debug=False):
        Print.info("Booting nodes...")
        repo = self.settings.repo_name
        remote_dir = f"/home/ubuntu/{repo}/benchmark"
        tasks = []
        for i, host in enumerate(hosts):
            cmd = "cd {} && {}".format(
                remote_dir,
                CommandMaker.run_node(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i),
                    PathMaker.parameters_file(),
                    debug=debug,
                ),
            )
            log_file = f"{remote_dir}/{PathMaker.node_log_file(i)}"
            connection = self.hosts_to_connections[host]
            tasks.append(self._run_on_host(host, cmd, log_file, connection))

        await self._gather_and_parse(tasks, "Boot Nodes")

    async def _run_single(
        self,
        committee_hosts,
        active_hosts,
        bench_parameters,
        node_parameters,
        debug=False,
        update=True,
    ):
        await self._kill(hosts_to_connections=self.hosts_to_connections, delete_logs=True)
        committee = await self._configure(committee_hosts, active_hosts, node_parameters, update)
        await self._run_nodes(active_hosts, debug)

        Print.info("Waiting for the nodes to synchronize...")
        sleep(2 * node_parameters.timeout_delay / 1000)

        duration = bench_parameters.duration
        for _ in progress_bar(range(20), prefix=f"Running benchmark ({duration} sec):"):
            sleep(ceil(duration / 20))

        await self._kill(hosts_to_connections=self.hosts_to_connections)
        await self._download_logs(active_hosts)
        return committee

    async def _download_log(self, host, connection, src, dest):
        try:
            async with connection.start_sftp_client() as sftp:
                result = await sftp.get(src, localpath=dest)
                return host, result
        except Exception as e:
            return host, Exception(f"Failed to download {src} from {host} because of {e}")

    async def _download_logs(self, hosts):
        subprocess.run(CommandMaker.clean_logs(), shell=True, stderr=subprocess.DEVNULL)
        repo = self.settings.repo_name
        remote_dir = f"/home/ubuntu/{repo}/benchmark"

        Print.info("Downloading node logs...")
        tasks = []
        for i, host in enumerate(hosts):
            src = f"{remote_dir}/{PathMaker.node_log_file(i)}"
            dest = PathMaker.node_log_file(i)
            connection = self.hosts_to_connections[host]
            tasks.append(self._download_log(host, connection, src, dest))
        await self._gather_and_parse(tasks, "Download Logs")

    async def _run(self, hosts, bench_parameters, node_parameters, debug=False, update=True):
        hosts_and_connections = await self._try_connect_all(hosts)
        self.hosts_to_connections = {host: connection for host, connection in hosts_and_connections}

        for n in bench_parameters.nodes:
            committee_hosts = hosts[:n]
            active_hosts = hosts[: n - bench_parameters.faults]
            rate = bench_parameters.rate[0]
            Print.heading(f"\nRunning {n} nodes (input rate: {rate:,} tx/s)")

            for i in range(bench_parameters.runs):
                Print.heading(f"Run {i + 1}/{bench_parameters.runs}")
                try:
                    await self._run_single(
                        committee_hosts,
                        active_hosts,
                        bench_parameters,
                        node_parameters,
                        debug,
                        update,
                    )
                    Print.info("Parsing logs and computing performance...")
                    logger = LogParser.process(PathMaker.logs_path(), faults=bench_parameters.faults)
                    logger.print(
                        PathMaker.result_file(
                            bench_parameters.faults,
                            n,
                            rate,
                            bench_parameters.tx_size,
                        )
                    )
                except (subprocess.SubprocessError, ParseError) as e:
                    await self._kill(hosts_to_connections=self.hosts_to_connections)
                    Print.error(BenchError("Benchmark failed", e))

    def run(self, bench_parameters_dict, node_parameters_dict, debug=False, update=True):
        assert isinstance(debug, bool)
        Print.heading("Starting remote benchmark")
        try:
            bench_parameters = BenchParameters(bench_parameters_dict)
            node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError("Invalid nodes or benchmark parameters", e)

        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn("There are not enough instances available")
            return

        asyncio.get_event_loop().run_until_complete(
            self._run(selected_hosts, bench_parameters, node_parameters, debug, update)
        )
