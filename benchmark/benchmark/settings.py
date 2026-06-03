# Copyright(C) Facebook, Inc. and its affiliates.
from json import load, JSONDecodeError
from os.path import abspath, dirname, isabs, join


class SettingsError(Exception):
    pass


class Settings:
    def __init__(self, key_name, key_path, base_port, repo_name, repo_url,
                 branch, instance_type, zones, project_id, username, gcp_key_path,
                 boot_disk_size_gb=300, source_image=None):
        inputs_str = [
            key_name, key_path, repo_name, repo_url, branch, instance_type,
            project_id, username, gcp_key_path
        ]
        if isinstance(zones, list):
            zones = zones
        else:
            zones = [zones]
        inputs_str += zones
        ok = all(isinstance(x, str) for x in inputs_str)
        ok &= isinstance(base_port, int)
        ok &= isinstance(boot_disk_size_gb, int)
        ok &= len(zones) > 0
        if not ok:
            raise SettingsError('Invalid settings types')

        self.key_name = key_name
        self.key_path = key_path

        self.base_port = base_port

        self.repo_name = repo_name
        self.repo_url = repo_url
        self.branch = branch

        self.instance_type = instance_type
        self.gcp_zones = zones
        self.project_id = project_id
        self.username = username
        self.gcp_key_path = gcp_key_path
        self.boot_disk_size_gb = boot_disk_size_gb
        self.source_image = (
            source_image
            or 'projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts'
        )

    @staticmethod
    def _resolve_path(settings_file, path):
        if isabs(path):
            return path
        return join(dirname(abspath(settings_file)), path)

    @staticmethod
    def _path_from_setting(value, default):
        if value is None:
            path = default
        elif isinstance(value, str):
            path = value
        elif isinstance(value, dict):
            path = value.get('path', default)
        elif isinstance(value, list):
            if not value:
                path = default
            elif isinstance(value[0], str):
                path = value[0]
            elif isinstance(value[0], dict):
                path = value[0].get('path', default)
            else:
                raise SettingsError('Malformed settings: invalid gcp_key entry')
        else:
            raise SettingsError('Malformed settings: gcp_key must be an object, string, or list')

        if not isinstance(path, str):
            raise SettingsError('Malformed settings: gcp_key path must be a string')
        return path

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as f:
                data = load(f)
            instances = data['instances']
            if not isinstance(instances, dict):
                raise SettingsError('Malformed settings: instances must be an object')
            zones = instances.get('zones', instances.get('regions'))
            gcp_key_path = cls._path_from_setting(
                data.get('gcp_key'),
                'benchmark/key.json',
            )

            return cls(
                data['key']['name'],
                data['key']['path'],
                data['port'],
                data['repo']['name'],
                data['repo']['url'],
                data['repo']['branch'],
                instances.get('machine_type', instances.get('type')),
                zones,
                data['project_id'],
                data['username'],
                cls._resolve_path(filename, gcp_key_path),
                instances.get('boot_disk_size_gb', 300),
                instances.get('source_image'),
            )
        except (OSError, JSONDecodeError) as e:
            raise SettingsError(str(e))

        except KeyError as e:
            raise SettingsError(f'Malformed settings: missing key {e}')
