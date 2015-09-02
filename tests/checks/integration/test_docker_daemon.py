# stdlib
from nose.plugins.attrib import attr

# project
from checks import AgentCheck
from tests.checks.common import AgentCheckTest

# 3rd party
from utils.dockerutil import get_client

CONTAINERS_TO_RUN = [
    "nginx",
    "redis:latest",

]

@attr(requires='docker_daemon')
class TestCheckDockerDaemon(AgentCheckTest):
    CHECK_NAME = 'docker_daemon'

    def setUp(self):
        self.docker_client = get_client()
        for c in CONTAINERS_TO_RUN:
            images = [i["RepoTags"][0] for i in self.docker_client.images(c.split(":")[0]) if i["RepoTags"][0].startswith(c)]
            if len(images) == 0:
                for line in self.docker_client.pull(c, stream=True):
                    print line
            
        self.containers = [self.docker_client.create_container(c, detach=True) for c in CONTAINERS_TO_RUN]
        for c in self.containers:
            self.docker_client.start(c)

    def tearDown(self):
        for c in self.containers:
            self.docker_client.remove_container(c, force=True)


    def test_find_cgroup(self):
        config = {
                "init_config": {
                    "docker_root": "/host"
                },
                "instances": [{
                    "url": "unix://var/run/docker.sock"
                },
            ],
        }

        self.run_check_twice(config)
        print self.metrics