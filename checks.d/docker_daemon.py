# stdlib
import os
import re
import requests
import time
import socket
import urllib2
from collections import defaultdict, Counter, deque

# project
from checks import AgentCheck
from config import _is_affirmative
from utils.dockerutil import find_cgroup, find_cgroup_filename_pattern, get_client, MountException 
from utils.platform import Platform

EVENT_TYPE = 'docker'
SERVICE_CHECK_NAME = 'docker.service_up'
SIZE_REFRESH_RATE = 5 # Collect container sizes every 5 iterations of the check

CGROUP_METRICS = [
    {
        "cgroup": "memory",
        "file": "memory.stat",
        "metrics": {
            "cache": ("docker.mem.cache", "gauge"),
            "rss": ("docker.mem.rss", "gauge"),
            "swap": ("docker.mem.swap", "gauge"),
        }
    },
    {
        "cgroup": "cpuacct",
        "file": "cpuacct.stat",
        "metrics": {
            "user": ("docker.cpu.user", "rate"),
            "system": ("docker.cpu.system", "rate"),
        },
    },
    {
        "cgroup": "blkio",
        "file": 'blkio.throttle.io_service_bytes',
        "metrics": {
            "io_read": ("docker.io.read_bytes", "monotonic_count"),
            "io_write": ("docker.io.write_bytes", "monotonic_count"),
        },
    },
]

TAG_EXTRACTORS = {
    "docker_image": lambda c: c["Image"],
    "image_name": lambda c: c["Image"].split(':', 1)[0] if 'Image' in c else c["RepoTags"][0].split(':', 1)[0],
    "image_tag": lambda c: c["Image"].split(':', 1)[1] if 'Image' in c else c["RepoTags"][0].split(':', 1)[1],
    "container_command": lambda c: c["Command"],
    "container_name": lambda c: c['Names'][0].lstrip("/") if c["Names"] else c['Id'][:11],
}


"""WIP for a new docker check

TODO:
 - Support a global "extra_tags" configuration, adding tags to all the metrics/events --> OK, need to test
 - Write tests
 - Test on all the platforms
"""


def get_mountpoints(docker_root):
    mountpoints = {}
    for metric in CGROUP_METRICS:
        mountpoints[metric["cgroup"]] = find_cgroup(metric["cgroup"], docker_root)
    return mountpoints

def get_filters(instance):
    # The reasoning is to check exclude first, so we can skip if there is no exclude
    if not instance.get("exclude"):
        instance["filtering_enabled"] = False
        return

    filtered_tag_names = []
    exclude_patterns = []
    include_patterns = []

    # Compile regex
    for rule in instance.get("exclude", []):
        exclude_patterns.append(re.compile(rule))
        filtered_tag_names.append(rule.split(':')[0])
    for rule in instance.get("include", []):
        include_patterns.append(re.compile(rule))
        filtered_tag_names.append(rule.split(':')[0])

    return set(exclude_patterns), set(include_patterns), set(filtered_tag_names)


class DockerDaemon(AgentCheck):
    """Collect metrics and events from Docker API and cgroups."""

    def __init__(self, name, init_config, agentConfig, instances=None):
        if instances is not None and len(instances) > 1:
            raise Exception("Docker check only supports one configured instance.")
        AgentCheck.__init__(self, name, init_config,
                            agentConfig, instances=instances)

        timeout = int(init_config.get('timeout', '5'))

        # We configure the check with the right cgroup settings for this host
        # Just needs to be done once
        instance = instances[0]
        self.client = get_client(base_url=instance.get("url"), timeout=timeout)
        self._mountpoints = get_mountpoints(init_config.get('docker_root', '/'))
        self._cgroup_filename_pattern = find_cgroup_filename_pattern(self._mountpoints)
        
        self.cgroup_listing_retries = 0
        self._latest_size_query = 0

        # At first run we'll just collect the events from the latest 60 secs
        self._last_event_collection_ts = int(time.time()) - 60

        # Set filtering settings
        if not instance.get("exclude"):
            self._filtering_enabled = False
        else:
            self._filtering_enabled = True
            self._exclude_patterns, self._include_patterns, self._filtered_tag_names = get_filters(instance)


    def check(self, instance):
        """Run the Docker check for one instance."""

        # Report image metrics
        if _is_affirmative(instance.get('collect_images_stats', True)):
            self._count_and_weight_images(instance)

        # Get the list of containers and the index of their names
        containers_by_id = self._get_and_count_containers(instance)
        containers_by_id = self._crawl_container_pids(containers_by_id)

        # Report performance container metrics (cpu, mem, net, io)
        self._report_performance_metrics(instance, containers_by_id)
        # TODO: report container sizes (and image sizes?) --> OK - need to test
        if _is_affirmative(instance.get('collect_container_size', True)):
            self._report_container_size(instance, containers_by_id)

        # TODO: bring events back --> OK - need to test
        # Send events from Docker API
        if _is_affirmative(instance.get('collect_events', True)):
            self._process_events(instance, containers_by_id)



    # Containers

    def _count_and_weight_images(self, instance):
        try:
            extra_tags = instance.get('tags', [])
            active_images = self.client.images(all=False)
            active_images_len = len(active_images)
            all_images_len = len(self.client.images(quiet=True, all=True))
            self.gauge("docker.images.available", active_images_len, tags=extra_tags)
            self.gauge("docker.images.intermediate", (all_images_len - active_images_len), tags=extra_tags)

            if _is_affirmative(instance.get('collect_image_size', True)):
                self._report_image_size(instance, active_images)

        except Exception, e:
            # It's not an important metric, keep going if it fails
            self.warning("Failed to count Docker images. Exception: {0}".format(e))

    def _get_and_count_containers(self, instance):
        """List all the containers from the API, filter and count them."""
        
        # Querying the size of containers is slow, we don't do it at each run
        must_query_size = _is_affirmative(instance.get('collect_container_size', False)) and self._latest_size_query == 0
        self._latest_size_query = (self._latest_size_query + 1) % SIZE_REFRESH_RATE

        containers_running_count = Counter()
        containers_stopped_count = Counter()

        try:
            containers = self.client.containers(all=True, size=must_query_size)
        except Exception, e:
            message = "Unable to list Docker containers: {0}".format(e)
            self.service_check(SERVICE_CHECK_NAME, AgentCheck.CRITICAL,
                               message=message)
            raise Exception(message)

        else:
            self.service_check(SERVICE_CHECK_NAME, AgentCheck.OK)

        # Filter containers according to the exclude/include rules
        self._filter_containers(instance, containers)

        containers_by_id = {}

        # Dict of container ids and a list of their Amazon ECS task tags
        ecs_tags = None
        if Platform.is_ecs_instance() and instance.get('ecs_tags', True):
            ecs_tags = self._get_ecs_tags()
            
        for container in containers:
            custom_tags = []
            if ecs_tags:
                custom_tags += ecs_tags.get(container['Id'], [])
            container_name = container['Names'][0].strip('/')
            tag_names = instance.get("container_tags", ["image_name"])
            container_tags = self._get_tags(container, tag_names) + instance.get('tags', []) + custom_tags
            # Check if the container is included/excluded via its tags
            if self._is_container_running(container):
                containers_running_count[tuple(sorted(container_tags))] += 1
            else:
                containers_stopped_count[tuple(sorted(container_tags))] += 1

            if self._is_container_excluded(container):
                self.log.debug("Container {0} is excluded".format(container_name))
                continue



            containers_by_id[container['Id']] = container

        for tags, count in containers_running_count.iteritems():
            self.gauge("docker.containers.running", count, tags=list(tags))

        for tags, count in containers_stopped_count.iteritems():
            self.gauge("docker.containers.stopped", count, tags=list(tags))

        return containers_by_id

    def _is_container_running(self, container):
        """Tell if a container is running, according to its status.

        There is no "nice" API field to figure it out. We just look at the "Status" field, knowing how it is generated.
        See: https://github.com/docker/docker/blob/v1.6.2/daemon/state.go#L35
        """
        return container["Status"].startswith("Up") or container["Status"].startswith("Restarting")

    def _get_tags(self, entity, tag_names):
        """Generate the tags for a given entity (container or image) according to a list of tag names."""
        tags = []
        for tag_name in tag_names:
            tags.append('%s:%s' % (tag_name, self._extract_tag_value(entity, tag_name)))

        return tags

    def _extract_tag_value(self, entity, tag_name):
        """Extra tag information from the API result (containers or images).

        Cache extracted tags inside the entity object.
        """
        if tag_name not in TAG_EXTRACTORS:
            self.warning("{0} isn't a supported tag".format(tag_name))
            return
        # Check for already extracted tags
        if "_tag_values" not in entity:
            entity["_tag_values"] = {}
        if tag_name not in entity["_tag_values"]:
            entity["_tag_values"][tag_name] = TAG_EXTRACTORS[tag_name](entity).strip()

        return entity["_tag_values"][tag_name]

    def _get_ecs_tags(self):
        ecs_config = self.client.inspect_container('ecs-agent')
        net_conf = ecs_config['NetworkSettings'].get('Ports', {})
        net_conf = net_conf.get(net_conf.keys()[0], [])
        container_tags = {}
        if net_conf:
            net_conf = net_conf[0] if isinstance(net_conf, list) else net_conf
            ip, port = net_conf.get('HostIp'), net_conf.get('HostPort')
            tasks = requests.get('http://%s:%s' % (ip, port)).json()
            for task in tasks.get('Tasks', []):
                for container in task.get('Containers', []):
                    tags = ['task_name:%s' % task['Family'], 'task_version:%s' % task['Version']]
                    container_tags[container['DockerId']] = tags
        return container_tags

    def _filter_containers(self, instance, containers):
        if not self._filtering_enabled:
            return

        for container in containers:
            container_tags = self._get_tags(container, self._filtered_tag_names)
            container['_is_filtered'] = self._are_tags_filtered(instance, container_tags) 
                
            if container['_is_filtered']:
                self.log.debug("Container {0} is filtered".format(container["Names"][0]))

    def _are_tags_filtered(self, instance, tags):
        if self._tags_match_patterns(tags, self._exclude_patterns):
            if self._tags_match_patterns(tags, self._include_patterns):
                return False
            return True
        return False

    def _tags_match_patterns(self, tags, filters):
        for rule in filters:
            for tag in tags:
                if re.match(rule, tag):
                    return True
        return False

    def _is_container_excluded(self, container):
        """Check if a container is excluded according to the filter rules.

        Requires _filter_containers to run first.
        """
        return container.get('_is_filtered', False)

    def _report_container_size(self, instance, containers_by_id):
        container_list_with_size = None
        for container in containers_by_id.itervalues():
            if self._is_container_excluded(container):
                continue
            elif 'SizeRw' not in container or 'SizeRootFs' not in container:
                continue
            tag_names = instance.get("performance_tags", ["image_name", "container_name"])
            container_tags = self._get_tags(container, tag_names) + instance.get('tags', [])
            self.gauge('docker.container.size_rw', container['SizeRw'], tags=container_tags)
            self.gauge('docker.container.size_rootfs', container['SizeRootFs'], tags=container_tags)

    def _report_image_size(self, instance, images):
        for image in images:
            tag_names = instance.get('image_tags', ['image_name', 'image_tag'])
            image_tags = self._get_tags(image, tag_names) + instance.get('tags', [])
            if 'VirtualSize' in image:
                self.gauge('docker.image.virtual_size', image['VirtualSize'], tags=image_tags)
            if 'Size' in image:
                self.gauge('docker.image.size', image['Size'], tags=image_tags)

    # Performance metrics

    def _report_performance_metrics(self, instance, containers_by_id):
        for container in containers_by_id.itervalues():
            if self._is_container_excluded(container) or not self._is_container_running(container):
                continue

            tag_names = instance.get("performance_tags", ["image_name", "container_name"])
            container_tags = self._get_tags(container, tag_names) + instance.get('tags', [])

            self._report_cgroup_metrics(container, container_tags)
            self._report_net_metrics(container, container_tags)

    def _report_cgroup_metrics(self, container, tags):
        try:
            for cgroup in CGROUP_METRICS:
                stat_file = self._get_cgroup_file(cgroup["cgroup"], container['Id'], cgroup['file'])
                stats = self._parse_cgroup_file(stat_file)
                if stats:
                    for key, (dd_key, metric_type) in cgroup['metrics'].iteritems():
                        if key in stats:
                            getattr(self, metric_type)(dd_key, int(stats[key]), tags=tags)
        except MountException as ex:
            if self.cgroup_listing_retries > 3:
                raise ex
            else:
                self.warning("Couldn't find the cgroup files. Skipping the CGROUP_METRICS for now."
                             "Will retry a few times before failing.")
                self.cgroup_listing_retries += 1
        else:
            self.cgroup_listing_retries = 0

    def _report_net_metrics(self, container, tags):
        """Find container network metrics by looking at /proc/$PID/net/dev of the container process."""
        proc_net_file = os.path.join(container['_proc_root'], 'net/dev')

        fp = None
        try:
            with open(proc_net_file, 'r') as fp:
                lines = fp.readlines()
                """Two first lines are headers:
                Inter-|   Receive                                                |  Transmit
                 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
                """
                for l in lines[2:]:
                    cols = l.split(':', 1)
                    interface_name = cols[0].strip()
                    if interface_name == 'eth0':
                        x = cols[1].split()
                        self.rate("docker.net.bytes_rcvd", long(x[0]), tags)
                        self.rate("docker.net.bytes_sent", long(x[8]), tags)
                        break
        except Exception, e:
            # It is possible that the container got stopped between the API call and now
            self.warning("Failed to report IO metrics from file {0}. Exception: {1}".format(proc_net_file, e))

    def _process_events(self, instance, containers_by_id):
        try:
            api_events = self._get_events(instance)
            aggregated_events = self._pre_aggregate_events(api_events, containers_by_id)
            events = self._format_events(aggregated_events, containers_by_id)
        except (socket.timeout, urllib2.URLError):
            self.warning('Timeout when collecting events. Events will be missing.')
            return
        except Exception, e:
            self.warning("Unexpected exception when collecting events: {0}. "
                "Events will be missing".format(e))
            return

        for ev in events:
            self.log.debug("Creating event: %s" % ev['msg_title'])
            self.event(ev)

    def _get_events(self, instance):
        """Get the list of events."""
        now = int(time.time())
        events = []
        event_generator = self.client.events(since=self._last_event_collection_ts,
            until=now, decode=True)
        for event in event_generator:
            if event != '':
                events.append(event)
        self._last_event_collection_ts = now
        return events

    def _pre_aggregate_events(self, api_events, containers_by_id):
        # Aggregate events, one per image. Put newer events first.
        events = defaultdict(deque)
        for event in api_events:
            # Skip events related to filtered containers
            if self._is_container_excluded(containers_by_id.get(event['id'], {})):
                self.log.debug("Excluded event: container {0} status changed to {1}".format(
                    event['id'], event['status']))
                continue
            # Known bug: from may be missing
            if 'from' in event:
                events[event['from']].appendleft(event)
        return events

    def _format_events(self, aggregated_events, containers_by_id):
        events = []
        for image_name, event_group in aggregated_events.iteritems():
            max_timestamp = 0
            status = defaultdict(int)
            status_change = []
            for event in event_group:
                max_timestamp = max(max_timestamp, int(event['time']))
                status[event['status']] += 1
                container_name = event['id'][:11]
                if event['id'] in containers_by_id:
                    container_name = containers_by_id[event['id']]['Names'][0].strip('/')
                status_change.append([container_name, event['status']])

            status_text = ", ".join(["%d %s" % (count, st) for st, count in status.iteritems()])
            msg_title = "%s %s on %s" % (image_name, status_text, self.hostname)
            msg_body = (
                "%%%\n"
                "{image_name} {status} on {hostname}\n"
                "```\n{status_changes}\n```\n"
                "%%%"
            ).format(
                image_name=image_name,
                status=status_text,
                hostname=self.hostname,
                status_changes="\n".join(
                    ["%s \t%s" % (change[1].upper(), change[0]) for change in status_change])
            )
            events.append({
                'timestamp': max_timestamp,
                'host': self.hostname,
                'event_type': EVENT_TYPE,
                'msg_title': msg_title,
                'msg_text': msg_body,
                'source_type_name': EVENT_TYPE,
                'event_object': 'docker:%s' % image_name,
            })

        return events

    # Cgroups

    def _get_cgroup_file(self, cgroup, container_id, filename):
        """Find a specific cgroup file, containing metrics to extract."""
        params = {
            "mountpoint": self._mountpoints[cgroup],
            "id": container_id,
            "file": filename,
        }
        return self._cgroup_filename_pattern % (params)

    def _parse_cgroup_file(self, stat_file):
        """Parse a cgroup pseudo file for key/values."""
        self.log.debug("Opening cgroup file: %s" % stat_file)
        try:
            with open(stat_file, 'r') as fp:
                if 'blkio' in stat_file:
                    return self._parse_blkio_metrics(fp.read().splitlines())
                else:
                    return dict(map(lambda x: x.split(' ', 1), fp.read().splitlines()))
        except IOError:
            # It is possible that the container got stopped between the API call and now
            self.log.info("Can't open %s. Metrics for this container are skipped." % stat_file)

    def _parse_blkio_metrics(self, stats):
        """Parse the blkio metrics."""
        metrics = {
            'io_read': 0,
            'io_write': 0,
        }
        for line in stats:
            if 'Read' in line:
                metrics['io_read'] += int(line[2])
            if 'Write' in line:
                metrics['io_write'] += int(line[2])
        return metrics

    # proc files
    def _crawl_container_pids(self, container_dict):
        """Crawl `/proc` to find container PIDs and add them to `containers_by_id`."""
        for folder in os.listdir('/proc'):
            try:
                int(folder)
            except ValueError:
                continue
            try:
                path = '/proc/%s/cgroup' % folder
                with open(path, 'r') as f:
                    content = [line.strip().split(':') for line in f.readlines()]
            except Exception, e:
                self.warning("Cannot read %s : %s" % (path, str(e)))
                continue

            try:
                content = dict((line[1], line[2]) for line in content)
                if 'docker/' in content.get('cpuacct'):
                    container_id = content['cpuacct'].split('docker/')[1]
                    container_dict[container_id]['_pid'] = folder
                    container_dict[container_id]['_proc_root'] = '/proc/%s/' % folder
            except Exception, e:
                self.warning("Cannot parse %s content: %s" % (path, str(e)))
                continue
        return container_dict
