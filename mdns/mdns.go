package mdns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

const Service = "_openscreen._udp"

type Device struct {
	Names     []string
	Address   net.IP
	Port      int
	AuthToken string
}

type Config struct {
	UseIpv6 bool
}

type Client struct {
	config  Config
	devices []Device
	logger  *slog.Logger
}

func NewClient(logger *slog.Logger) *Client {
	dv := make([]Device, 0)
	c := Client{
		devices: dv,
		logger:  logger,
	}
	return &c
}

func FindTxtKey(key string, record []string) (string, bool) {
	for _, r := range record {
		kv := strings.Split(r, "=")
		if kv[0] == key {
			if len(kv) > 1 {
				return kv[1], true
			}
			return "", true
		}
	}

	return "", false
}

func (c *Client) FindDevices() {
	resultChan := make(chan *mdns.ServiceEntry)
	go c.addDevices(resultChan)
	c.deviceDiscovery(context.Background(), resultChan)
}

func (c *Client) FindDevice(name string) *Device {
	resultChan := make(chan *mdns.ServiceEntry)
	ctx, cancel := context.WithCancel(context.Background())
	var result *mdns.ServiceEntry
	go func() {
		for r := range resultChan {
			if name == r.Name || name == strings.Split(r.Name, ".")[0] {
				result = r
				cancel()
				return
			}
		}
	}()
	c.deviceDiscovery(ctx, resultChan)
	if result == nil {
		return nil
	}

	d := c.ServiceEntryToDevice(result)
	return &d
}

func (c *Client) addDevices(resultChan chan *mdns.ServiceEntry) {
	for r := range resultChan {
		c.addDevice(r)
	}
}

func (c *Client) GetAddress(hostName string) net.IP {
	for _, d := range c.devices {
		for _, n := range d.Names {
			if hostName == n || hostName == strings.TrimSuffix(n, Service) {
				return d.Address
			}
		}
	}
	return nil
}

func (c *Client) deviceDiscovery(ctx context.Context, resultChan chan *mdns.ServiceEntry) {
	param := mdns.QueryParam{
		Service:     Service,
		DisableIPv6: !c.config.UseIpv6,
		Entries:     resultChan,
		Timeout:     10 * time.Second,
	}

	err := mdns.QueryContext(ctx, &param)
	if err != nil {
		c.logger.Error(fmt.Sprintf("Querry error %s", err))
	}
}

func (c *Client) addDevice(s *mdns.ServiceEntry) {
	i := c.findDevice(s)
	if i == -1 {
		c.logger.Info(fmt.Sprintf("Service %s with name %s not found yet, adding", c.getAddress(s).String(), s.Name))
		d := c.ServiceEntryToDevice(s)
		c.devices = append(c.devices, d)
	} else {
		c.logger.Info(fmt.Sprintf("Service %s already found, adding additional name %s", c.getAddress(s).String(), s.Name))

		c.devices[i].Names = append(c.devices[i].Names, s.Name)
	}
}

func (c *Client) ServiceEntryToDevice(s *mdns.ServiceEntry) Device {
	names := []string{s.Name}
	address := c.getAddress(s)
	at, exists := FindTxtKey("at", s.InfoFields)
	if !exists {
		at = ""
	}

	return Device{
		Names:     names,
		Address:   address,
		Port:      s.Port,
		AuthToken: at,
	}
}

func (c *Client) findDevice(entry *mdns.ServiceEntry) int {
	for i, d := range c.devices {
		if c.getAddress(entry).Equal(d.Address) {
			return i
		}
	}

	return -1
}

func (c *Client) getAddress(s *mdns.ServiceEntry) net.IP {
	if c.config.UseIpv6 {
		return s.AddrV6IPAddr.IP
	}
	return s.AddrV4
}

func (c *Client) Devices() []Device {
	return c.devices
}
