# WhaleGuard

WhaleGuard discovers docker to open dynamically your `ip6tables` firewall for your containers.
The approach is to use the native v6 addresses of the container for inbound traffic without opening your whole subnet to the world.

The containers are required to have an global ipv6 address.

As the main focus is protecting the native `ipv6` subnet, ipv4 is currently not supported.

## Usage

```
-chain string   Set name of iptables chain to manage (default "WHALEGUARD")
-defaults       Add some default deny rules
-iface string   Incoming network interface on host (default "eth0")
-label string   Discovery only container attached with this label (default "whaleguard=true")
-network string Created chain just cares about this subnet
```

The docker client has some extra env variables you can set: `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `DOCKER_HOST`


### Run in a docker container
[Image DockerHub](https://hub.docker.com/r/project0de/whaleguard)

The container requires some extended privileges (given by CAP_NET_ADMIN) and needs to be run on the host network.
Obviously docker socket is required for api calls to docker.

```bash
docker run -ti --cap-add=NET_ADMIN --net host -v /var/run/docker.sock:/var/run/docker.sock project0de/whaleguard -iface eth0 -defaults -network 2001:1:1:/65
```


## Docker Labels

To prevent automatic creation of unwanted rules, container needs to be labeled:

### whaleguard

The label `whaleguard` enables this container for whaleguard to use
The value needs to be set to `true`

### whaleguard.port

The label `whaleguard.port` is optional to use.
Per default whaleguard tries to open ports which are defined in the port mapping, if you dont want this behaviour use this label.

In some situations its necessary to control better which ports needs to be opened, so you can define exactly which ports should be opened

Setting the label like this `--labels="whaleguard.port=2003"` will open port 2003 to the containers v6 address.

Multiple ports are allowed to define:  `--labels="whaleguard.port=2003,2004,2006"`

If you want to specify the protocol (default is tcp):  `--labels="whaleguard.port=2003/tcp,2004,2006/udp"`
