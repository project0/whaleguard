package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

func main() {
	IncomingInterface := flag.String("iface", "eth0", "Incoming network interface on host")
	Subnet := flag.String("network", "::/0", "Created chain just cares about this subnet")
	DefaultDenyRules := flag.Bool("defaults", false, "Add some default deny rules")
	ChainName := flag.String("chain", "WHALEGUARD", "Set name of iptables chain to manage")
	DockerLabelFilter := flag.String("label", "whaleguard=true", "Discovery only container attached with this label")
	flag.Parse()

	// check interface exists before starting
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	interfaceError := true
	for _, i := range interfaces {
		if i.Name == *IncomingInterface {
			interfaceError = false
		}
	}

	if interfaceError {
		log.Fatal(fmt.Sprintf("Network interface not found: %s", *IncomingInterface))
	}

	_, ipnet, err := net.ParseCIDR(*Subnet)
	if err != nil {
		log.Fatal(fmt.Sprintf("Could not parse network %s", *Subnet))
	}

	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		panic(err)
	}

	fw := Firewall{
		IPTables:  ipt,
		ChainName: *ChainName,
		Table:     "filter",
		Interface: *IncomingInterface, // incoming interface before routing
		Network:   ipnet,
	}

	// enforce older api version
	// os.Setenv("DOCKER_API_VERSION", "1.26")
	cl, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	containerFilterArgs := filters.NewArgs()
	if *DockerLabelFilter != "" {
		containerFilterArgs.Add("label", *DockerLabelFilter)
	}

	if err = fw.InitializeChain(*DefaultDenyRules); err != nil {
		panic(err)
	}
	log.Println("Synchronize with docker host")
	container, err := cl.ContainerList(context.Background(), types.ContainerListOptions{
		Filters: containerFilterArgs,
	})
	if err != nil {
		panic(err)
	}
	for _, c := range container {
		err := fw.AddContainer(c.ID, cl)
		if err != nil {
			log.Println(err)
		}
	}

	ctx := context.Background()

	containerFilterArgs.Add("event", "start")
	containerFilterArgs.Add("event", "die")
	containerFilterArgs.Add("type", "container")
	chanEvents, chanErrors := cl.Events(ctx, types.EventsOptions{
		Filters: containerFilterArgs,
	})
	log.Println("Watch for container events")

	for {
		select {
		case event := <-chanEvents:

			logInfo := fmt.Sprintf("container_id=%s event_action=%s", event.Actor.ID, event.Action)

			switch event.Action {
			case "start":
				err := fw.AddContainer(event.ID, cl)
				if err != nil {
					log.Printf("Failed to add container: %v %s\n", err, logInfo)
				}
			case "die":
				log.Printf("Remove rules for container %s\n", logInfo)
				err := fw.DropRules(event.Actor.ID)
				if err != nil {
					log.Printf("Failed to remove container: %v %s\n", err, logInfo)
				}
			default:
				log.Printf("Unhandled event action %s\n", logInfo)
			}
		case errors := <-chanErrors:
			log.Panic(errors.Error())
			return
		}
	}
}

// PortProto represents a Port with Protocol (udp/tcp)
type PortProto struct {
	Port  string
	Proto string
}

// ParsePortProto parses a string combination (Port/Protocol) to create a new PortProto
// Examples: 123/udp, 123
func ParsePortProto(p string) (*PortProto, error) {
	ppraw := strings.SplitN(p, "/", 2)
	proto := "tcp"
	if len(ppraw) == 2 {
		proto = strings.ToLower(strings.TrimSpace(ppraw[1]))
	}

	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("unsupported protocol provided in label: %s", proto)
	}
	// ensure we got an integer
	pi, err := strconv.Atoi(strings.TrimSpace(ppraw[0]))
	if err != nil {
		return nil, fmt.Errorf("could not parse port '%s' in label: %v", p, err)
	}

	return &PortProto{
		Port:  strconv.Itoa(pi),
		Proto: proto,
	}, nil
}

// Firewall represents an iptables chain
type Firewall struct {
	IPTables  *iptables.IPTables
	ChainName string
	Table     string
	Interface string
	Network   *net.IPNet
}

// InitializeChain ensures the working chain is correctly setuped and clears old rules in the working chain
func (f *Firewall) InitializeChain(defaults bool) error {
	var err error
	chains, err := f.IPTables.ListChains(f.Table)
	if err != nil {
		return err
	}

	exists := false
	for _, a := range chains {
		if a == f.ChainName {
			exists = true
		}
	}
	if !exists {
		if err = f.IPTables.NewChain(f.Table, f.ChainName); err != nil {
			return err
		}
	} else {
		// Cleanup the chain to start fresh
		if err = f.IPTables.ClearChain(f.Table, f.ChainName); err != nil {
			return err
		}
	}

	rulespec := []string{"-j", f.ChainName, "-i", f.Interface}
	if f.Network != nil {
		rulespec = append(rulespec, "--dst", f.Network.String())
	}

	// Ensure new chain will be used as first
	err = f.InsertUnique("INPUT", rulespec...)
	if err != nil {
		return err
	}

	// Attach to FORWARD to catch routed packets
	err = f.InsertUnique("FORWARD", rulespec...)
	if err != nil {
		return err
	}

	// initialize some default deny rules here?
	if defaults {
		// allow related traffic
		err := f.IPTables.Append(f.Table, f.ChainName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
		if err != nil {
			return err
		}
		// allow v6 icmp packages
		err = f.IPTables.Append(f.Table, f.ChainName, "-p", "ipv6-icmp", "-j", "ACCEPT")
		if err != nil {
			return err
		}
		// last but not least, reject everything else
		err = f.IPTables.Append(f.Table, f.ChainName, "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited")
		if err != nil {
			return err
		}
	}
	return nil
}

// AddContainer retrieves the container information (ip and ports) and adds the specific allow rules
func (f *Firewall) AddContainer(containerID string, client *client.Client) error {
	info, err := client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return err
	}

	var ports []PortProto

	if labelports, ok := info.Config.Labels["whaleguard.port"]; ok {
		for _, p := range strings.Split(labelports, ",") {
			pp, err := ParsePortProto(p)
			if err != nil {
				log.Print(err.Error())
				continue
			}
			ports = append(ports, *pp)
		}
	} else {
		// use exposed port
		for k := range info.NetworkSettings.Ports {
			ports = append(ports, PortProto{
				Port:  k.Port(),
				Proto: k.Proto(),
			})
		}
	}

	var ips []string

	if info.NetworkSettings.GlobalIPv6Address != "" {
		ips = append(ips, info.NetworkSettings.GlobalIPv6Address)
	}

	// add additional networks
	for _, network := range info.NetworkSettings.Networks {
		if network.GlobalIPv6Address != "" {
			ips = append(ips, network.GlobalIPv6Address)
		}
	}

	if len(ports) < 1 || len(ips) < 1 {
		log.Printf("No Ipv6 address or port assigned to container '%s', '%v', '%v'", containerID, ips, ports)
		return nil
	}

	for _, ip := range ips {
		for _, pp := range ports {
			err := f.AddRule(info.ID, ip, pp)
			if err != nil {
				log.Print(err)
			}
		}
	}
	return nil
}

// InsertUnique acts like IPTables.Insert except that it won't add a duplicate
func (f *Firewall) InsertUnique(chain string, rulespec ...string) error {
	exists, err := f.IPTables.Exists(f.Table, chain, rulespec...)
	if err != nil {
		return err
	}
	if !exists {
		return f.IPTables.Insert(f.Table, chain, 1, rulespec...)
	}
	return nil
}

// AddRule adds a new allow rule for an container
func (f *Firewall) AddRule(containerID string, ip string, pp PortProto) error {
	rulespec := []string{
		"-j", "ACCEPT",
		"-p", pp.Proto,
		"-d", ip,
		"--dport", pp.Port,
		"-m", "comment", "--comment", containerID,
	}

	log.Printf("Ensure rule: %v", rulespec)
	return f.InsertUnique(f.ChainName, rulespec...)
}

// DropRules removes all allow rules for this container in the chain
func (f *Firewall) DropRules(containerID string) error {
	rules, err := f.IPTables.List(f.Table, f.ChainName)
	if err != nil {
		return err
	}

	failed := []string{}

	for _, r := range rules {
		// just grep for the correct container
		if strings.Contains(r, containerID) {
			// lets make an rulespec out of it, first to parts is "-A Chainname"
			rulespec := strings.Split(r, " ")
			rulespec = rulespec[2:]

			log.Printf("Delete rule: %v", rulespec)
			err := f.IPTables.Delete(f.Table, f.ChainName, rulespec...)
			if err != nil {
				failed = append(failed, err.Error())
			}
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("iptables delete failed with errors: %s", strings.Join(failed, ","))
	}
	return nil
}
