package mdns

import (
	"log"
	"net"
	"time"

	"github.com/hashicorp/mdns"
)

const Service = "_googlecast._tcp"

type Config struct {
	UseIpv6 bool
}

type Client struct {
	config    Config
	CloseChan chan struct{}
	devices   []Device
}

func NewClient() *Client {
	ch := make(chan struct{}, 1)
	dv := make([]Device, 0)
	c := Client{
		CloseChan: ch,
		devices:   dv,
	}
	return &c
}

func (c *Client) Close() {
	c.CloseChan <- struct{}{}
}

func (c *Client) FindDevices() {
	resultChan := make(chan *mdns.ServiceEntry, 5)
	go c.AddDevices(resultChan)
	go c.DeviceDiscovery(resultChan)
}

func (c *Client) AddDevices(resultChan chan *mdns.ServiceEntry) {
	for {
		select {
		case <-c.CloseChan:
			return
		case s := <-resultChan:
			c.addDevice(s)
		}
	}
}

func (c *Client) DeviceDiscovery(resultChan chan *mdns.ServiceEntry) {
	param := mdns.QueryParam{
		Service:     Service,
		DisableIPv6: !c.config.UseIpv6,
		Entries:     resultChan,
		Timeout:     time.Hour,
	}

	err := mdns.Query(&param)
	if err != nil {
		log.Printf("Querry error %s", err)
		c.Close()
	}
}

func (c *Client) addDevice(s *mdns.ServiceEntry) {
	i := c.findDevice(s)
	if i == -1 {
		log.Printf("Service %s with name %s not found yet, adding", c.getAddress(s).String(), s.Name)
		names := []string{s.Name}
		address := c.getAddress(s)
		d := Device{
			Names:   names,
			Address: address,
		}
		c.devices = append(c.devices, d)
	} else {
		log.Printf("Service %s already found, adding additional name %s", c.getAddress(s).String(), s.Name)

		c.devices[i].Names = append(c.devices[i].Names, s.Name)
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

type Device struct {
	Names   []string
	Address net.IP
}
