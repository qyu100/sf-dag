# Copyright(C) Facebook, Inc. and its affiliates.
from botocore.exceptions import ClientError
from collections import defaultdict
from google.cloud import compute_v1
from google.api_core.extended_operation import ExtendedOperation

from benchmark.utils import Print, BenchError, progress_bar
from benchmark.settings import Settings, SettingsError


class GCPError(Exception):
    def __init__(self, error):
        assert isinstance(error, ClientError)
        self.message = error.response["Error"]["Message"]
        self.code = error.response["Error"]["Code"]
        super().__init__(self.message)


class InstanceManager:
    INSTANCE_NAME = "autobahn-node"
    SECURITY_GROUP_NAME = "autobahn"

    def __init__(self, settings):
        assert isinstance(settings, Settings)
        self.settings = settings
        self.client = compute_v1.InstancesClient()

    @classmethod
    def make(cls, settings_file="settings.json"):
        try:
            return cls(Settings.load(settings_file))
        except SettingsError as e:
            raise BenchError("Failed to load settings", e)

    def _get(self, state):
        # Possible states are: 'pending', 'running', 'shutting-down',
        # 'terminated', 'stopping', and 'stopped'.
        ids, ips = defaultdict(list), defaultdict(list)
        filter = ""

        for status in state:
            filter = '(status eq "' + status + '")'
            filter += " "
            # filter by machine prefix
            filter += '(name eq "' + self.INSTANCE_NAME + '.*")'
            request = compute_v1.AggregatedListInstancesRequest(filter=filter)
            request.project = self.settings.project_id
            agg_list = self.client.aggregated_list(request=request)
            print(request)
            for zone, response in agg_list:
                # Removes the zones/ prefix from the zone name
                zone = zone[6:]
                for instance in response.instances:
                    if instance.name == "autobahn-instance-template":
                        continue
                    ids[zone] += [instance.name]
                    ips[zone] += [
                        instance.network_interfaces[0].access_configs[0].nat_i_p
                    ]
        return ids, ips

    def _wait(self, operation, state="operation", timeout=3600):
        result = operation.result(timeout=timeout)

        if operation.error_code:
            Print.info(
                "Error during "
                + str(state)
                + ": Code: "
                + str(operation.error_code)
                + "Error message is: "
                + str(operation.error_message)
            )
            Print.info("Operation ID: " + str(operation.name))
            raise operation.exception() or RuntimeError(operation.error_message)

        if operation.warnings:
            Print.info("Warnings during " + str(state))
            for warning in operation.warnings:
                Print.info(str(warning.code) + ":" + str(warning.message))

        return result

    def _create_security_group(self, client):
        client.create_security_group(
            Description="HotStuff node",
            GroupName=self.SECURITY_GROUP_NAME,
        )

        client.authorize_security_group_ingress(
            GroupName=self.SECURITY_GROUP_NAME,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": "Debug SSH access",
                        }
                    ],
                    "Ipv6Ranges": [
                        {
                            "CidrIpv6": "::/0",
                            "Description": "Debug SSH access",
                        }
                    ],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": self.settings.base_port,
                    "ToPort": self.settings.base_port + 2_000,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": "Dag port",
                        }
                    ],
                    "Ipv6Ranges": [
                        {
                            "CidrIpv6": "::/0",
                            "Description": "Dag port",
                        }
                    ],
                },
            ],
        )

    def _get_ami(self, client):
        # The AMI changes with regions.
        response = client.describe_images(
            Filters=[
                {
                    "Name": "description",
                    "Values": [
                        "Canonical, Ubuntu, 20.04 LTS, amd64 focal image build on 2020-10-26"
                    ],
                }
            ]
        )
        return response["Images"][0]["ImageId"]

    def create_instances(self, instances):
        assert isinstance(instances, int) and instances > 0

        try:
            # Create all instances.
            size = instances * self.settings.gcp_zones
            progress = progress_bar(
                self.settings.gcp_zones, prefix=f"Creating {size} instances"
            )

            # Wait for instances to boot
            Print.info("Waiting for all instances to boot...")
            i = 0

            ops = []
            for zone in progress:
                for instance in range(instances):
                    instance_insert_request = compute_v1.InsertInstanceRequest()
                    instance_insert_request.project = self.settings.project_id
                    instance_insert_request.zone = zone
                    instance_insert_request.instance_resource.name = (
                        self.INSTANCE_NAME + str(instance) + "-" + str(zone)
                    )
                    instance_insert_request.source_instance_template = (
                        self.settings.templates[i]
                    )
                    print(self.settings.templates[i])
                    operation = self.client.insert(instance_insert_request)
                    ops.append((operation, str(instance), zone))
                i += 1

            for operation, instance, zone in ops:
                Print.info(
                    f"Waiting for instance {instance} in zone {zone} to be in STAGING"
                )
                self._wait(operation, "RUNNING")
            Print.heading(f"Successfully created {size} new instances")
        except ClientError as e:
            raise BenchError("Failed to create AWS instances", GCPError(e))

    def terminate_instances(self):
        try:
            ids, _ = self._get(
                [
                    "STAGING",
                    "RUNNING",
                    "REPAIRING",
                    "STOPPING",
                    "SUSPENDED",
                    "SUSPENDING",
                ]
            )
            size = sum(len(x) for x in ids.values())
            if size == 0:
                Print.heading(f"All instances are shut down")
                return

            # Terminate instances.
            ops = []
            for zone, id_list in ids.items():
                for id in id_list:
                    print(self.settings.project_id)
                    print(zone)
                    print(id)
                    operation = self.client.delete(
                        project=self.settings.project_id, zone=zone, instance=id
                    )
                    ops.append((operation, id, zone))

            for operation, id, zone in ops:
                Print.info(
                    f"Waiting for instance {id} in zone {zone} to be in STOPPING"
                )
                self._wait(operation, "STOPPING")

            # Wait for all instances to properly shut down.
            Print.info("Waiting for all instances to shut down...")
            Print.heading(f"Testbed of {size} instances destroyed")
        except ClientError as e:
            raise BenchError("Failed to terminate instances", GCPError(e))

    def start_instances(self, max):
        size = 0
        try:
            ids, _ = self._get(["SUSPENDED"])
            # Resume a suspended instance.
            ops = []
            for zone, id_list in ids.items():
                target = 0
                for id in id_list:
                    if (
                        target < max
                        and self.client.get(
                            project=self.settings.project_id, zone=zone, instance=id
                        ).status
                        == compute_v1.Instance.Status.SUSPENDED
                    ):
                        operation = self.client.resume(
                            project=self.settings.project_id, zone=zone, instance=id
                        )
                        ops.append((operation, id, zone))
                target += 1
            for operation, id, zone in ops:
                Print.info(f"Waiting for instance {id} in zone {zone} to be in RUNNING")
                self._wait(operation, "RUNNING")
            Print.heading(f"Starting {size} instances")
        except ClientError as e:
            raise BenchError("Failed to start instances", GCPError(e))

    def stop_instances(self):
        try:
            ids, _ = self._get(["RUNNING", "REPAIRING"])
            for zone, id_list in ids.items():
                for id in id_list:
                    self.client.suspend(
                        project=self.settings.project_id, zone=zone, instance=id
                    )
            size = sum(len(x) for x in ids.values())
            Print.heading(f"Stopping {size} instances")
        except ClientError as e:
            raise BenchError("Failed to stop instances", GCPError(e))

    def hosts(self, flat=False):
        try:
            _, ips = self._get(["STAGING", "RUNNING"])
            if not flat:
                return ips
            else:
                return [x for y in ips.values() for x in y]
        except ClientError as e:
            raise BenchError("Failed to gather instances IPs", GCPError(e))

    def print_info(self):
        hosts = self.hosts(False)
        key = self.settings.key_path
        text = ""
        for zone, ips in hosts.items():
            text += f"\n Zone: {zone.upper()}\n"
            for i, ip in enumerate(ips):
                new_line = "\n" if (i + 1) % 6 == 0 else ""
                text += f"{new_line} {i}\tssh -i {key} {self.settings.username}@{ip}\n"
        print(
            "\n"
            "----------------------------------------------------------------\n"
            " INFO:\n"
            "----------------------------------------------------------------\n"
            f" Available machines: {sum(len(x) for x in hosts.values())}\n"
            f"{text}"
            "----------------------------------------------------------------\n"
        )
