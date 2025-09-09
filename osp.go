package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/ValiantChip/osp/cmd/cast"
	"github.com/ValiantChip/osp/mdns"
	"github.com/ValiantChip/osp/open_screen"
	cmnd "github.com/ValiantChip/uniCommands"
)

func main() {
	os.Exit(ReturnWithExitCode())
}

func GetLevel(l int) slog.Level {
	return slog.Level((l - 1) * 4)
}

type Client struct {
	caster         cast.Caster
	doneChan       chan error
	exitChan       chan struct{}
	commandHandler *cmnd.Handler
}

func NewClient() *Client {
	c := new(Client)
	c.caster = cast.Caster{}
	c.doneChan = make(chan error, 1)
	c.exitChan = make(chan struct{}, 1)
	c.commandHandler = cmnd.NewHandler(cmnd.HandlerArg{
		Name:        "cast",
		Description: "Usage: cast <hostname> <filename>\nCasts the file at <filename> to the open screen agent at <hostname>",
		Runner: func(args []string) error {
			if c.caster.GetClient() != nil {
				fmt.Println("already casting")
				return nil
			}
			if len(args) < 3 {
				fmt.Println("not enough arguments to call cast need: cast <hostname> <filename>")
			}

			hostName := args[1]
			filename := args[2]
			client := mdns.NewClient(slog.Default())
			client.FindDevices()
			var ip net.IP
			var port int
			var at string

			success := false

			if addr, err := net.ResolveUDPAddr("udp", hostName); err == nil {
				ip = addr.IP
				port = addr.Port

				for _, d := range client.Devices() {
					if d.Address.Equal(ip) {
						success = true
						at = d.AuthToken
						break
					}
				}
			} else {
				for _, d := range client.Devices() {
					for _, n := range d.Names {
						split := strings.Split(n, `.`)
						name := split[0]
						if hostName == n || hostName == name {
							ip = d.Address
							port = d.Port
							success = true
							at = d.AuthToken
							break
						}
					}
				}

			}

			if !success {
				fmt.Println("casting failed - device not found")
				return nil
			}

			go func() { c.doneChan <- c.caster.Cast(ip, port, 7938, 9567, filename, at) }()

			return nil
		},
	}, cmnd.HandlerArg{
		Name:        "discover",
		Description: "list all available openscreen agents on the local network",
		Runner: func(args []string) error {
			fmt.Println("searching for devices...")
			client := mdns.NewClient(slog.Default())
			client.FindDevices()
			devices := client.Devices()
			if len(devices) == 0 {
				fmt.Println("no devices found")
				return nil
			}
			fmt.Println("devices found:")
			for _, d := range devices {
				fmt.Print("	")
				split := strings.Split(d.Names[0], `.`)
				name := split[0]
				fmt.Print(name)
				if len(d.Names) > 1 {
					fmt.Print(" ; other Names: ")
					for _, n := range d.Names[1:] {
						split := strings.Split(n, `.`)
						name := split[0]
						fmt.Print(name + " ")
					}
				}
				fmt.Print("\n")
			}
			return nil
		},
	},
		cmnd.HandlerArg{
			Name:        "agent",
			Description: "Usage: agent <command> (args)...\nSends a command to the currently casting agent\ntype \"agent help\" for more information",
			Runner: func(args []string) error {
				if c.caster.GetClient() == nil {
					fmt.Println("no agent is currently casting")
					return nil
				}

				if len(args) < 2 {
					fmt.Println("not enough arguments to call agent need: agent <command> (args)...")
				}

				err := c.caster.GetClient().HandleControl(args[1:])
				if err != nil {
					fmt.Println(err.Error())
				}

				return nil
			},
		}, cmnd.HandlerArg{
			Name:        "quit",
			Description: "exit the program",
			Runner: func(args []string) error {
				if c.caster.GetClient() != nil {
					c.caster.GetClient().Terminate(open_screen.UserTerminatedViaController)
				}
				c.exitChan <- struct{}{}
				return nil
			},
		}, cmnd.HandlerArg{
			Name:        "help",
			Description: "print this message",
			Runner: func(args []string) error {
				fmt.Print("Available Commands:\n")
				fmt.Print(c.commandHandler.GetDescription())
				return nil
			},
		})

	return c
}

func ReturnWithExitCode() int {
	level := flag.Int("l", 3, "log level: 0 - debug, 1 - info, 2 - warning, 3 - error, 4 - none")
	help := flag.Bool("h", false, "print this message and exit")
	flag.Parse()

	if *help {
		flag.CommandLine.Usage()
		return 0
	}

	if *level < 0 || *level > 4 {
		fmt.Println("Invalid log level")
		return 1
	}

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: GetLevel(*level),
	})

	slog.SetDefault(slog.New(handler))
	fmt.Print("type help for a list of available commands\n")

	client := NewClient()
	inputChan := make(chan string)
	go func() {
		buff := make([]byte, 1000)
		for {
			n, err := os.Stdin.Read(buff)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				slog.Error("error reading from stdin", "error", err)
				return
			}

			inputChan <- string(buff[:n-1])
		}
	}()
	for {
		select {
		case input := <-inputChan:
			args := strings.Split(input, " ")
			client.HandleCommand(args)
		case err := <-client.doneChan:
			fmt.Println("client exited")
			if err != nil {
				slog.Error("error while casting", "error", err)
			}
		}
	}
}

func (c *Client) HandleCommand(args []string) bool {
	_, ok := c.commandHandler.HandleArgs(args)
	if !ok {
		fmt.Print(c.commandHandler.GetDescription())
	}
	return false
}
