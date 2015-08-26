# stdlib
import os

# 3rd party
from docker import Client

class MountException(Exception):
    pass

def get_client(**kwargs):
    return Client(**kwargs)

def find_cgroup(hierarchy, docker_root):
        """Find the mount point for a specified cgroup hierarchy.

        Works with old style and new style mounts.
        """
        with open(os.path.join(docker_root, "/proc/mounts"), 'r') as fp:
            mounts = map(lambda x: x.split(), fp.read().splitlines())
        cgroup_mounts = filter(lambda x: x[2] == "cgroup", mounts)
        if len(cgroup_mounts) == 0:
            raise Exception(
                "Can't find mounted cgroups. If you run the Agent inside a container,"
                " please refer to the documentation.")
        # Old cgroup style
        if len(cgroup_mounts) == 1:
            return os.path.join(docker_root, cgroup_mounts[0][1])

        candidate = None
        for _, mountpoint, _, opts, _, _ in cgroup_mounts:
            if hierarchy in opts:
                if mountpoint.startswith("/host/"):
                    return os.path.join(docker_root, mountpoint)
                candidate = mountpoint
        
        if candidate is not None:
            return os.path.join(docker_root, candidate)
        raise Exception("Can't find mounted %s cgroups." % hierarchy)

def find_cgroup_filename_pattern(mountpoints):
    # We try with different cgroups so that it works even if only one is properly working
    for mountpoint in mountpoints.itervalues():
        stat_file_path_lxc = os.path.join(mountpoint, "lxc")
        stat_file_path_docker = os.path.join(mountpoint, "docker")
        stat_file_path_coreos = os.path.join(mountpoint, "system.slice")

        if os.path.exists(stat_file_path_lxc):
            return os.path.join('%(mountpoint)s/lxc/%(id)s/%(file)s')
        elif os.path.exists(stat_file_path_docker):
            return os.path.join('%(mountpoint)s/docker/%(id)s/%(file)s')
        elif os.path.exists(stat_file_path_coreos):
            return os.path.join('%(mountpoint)s/system.slice/docker-%(id)s.scope/%(file)s')

    raise MountException("Cannot find Docker cgroup directory. Be sure your system is supported.")

