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
	"sync"
	"time"

	"github.com/CzarJoti/osp/cmd/cast"
	"github.com/CzarJoti/osp/mdns"
	cmnd "github.com/CzarJoti/uniCommands"
)

var clientPort = 7938
var videoPort = 9567
var verifyTimeout = 2 * time.Second

func main() {
	os.Exit(ReturnWithExitCode())
}

func GetLevel(l int) slog.Level {
	return slog.Level((l - 1) * 4)
}

type Client struct {
	caster         *cast.Caster
	doneChan       chan error
	exitChan       chan struct{}
	commandHandler *cmnd.Handler
	agentHandler   *cmnd.Handler
}

func NewClient() *Client {
	c := new(Client)
	c.caster = cast.NewCaster(clientPort, slog.Default())
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
				return nil
			}

			hostName := args[1]
			filename := args[2]
			var ip net.IP
			var port int
			var at string

			if addr, err := net.ResolveUDPAddr("udp", hostName); err == nil {
				ip = addr.IP
				port = addr.Port
			} else {
				client := mdns.NewClient(slog.Default())
				d := client.FindDevice(hostName)
				if d == nil {
					fmt.Println("casting failed - device not found")
					return nil
				}
				ip = d.Address
				port = d.Port
				at = d.AuthToken
			}

			go func() { c.doneChan <- c.caster.Cast(ip, port, videoPort, filename, at) }()

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
			validDevices := make([]mdns.Device, 0)
			devicesChan := make(chan mdns.Device)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				var dg sync.WaitGroup
				for _, d := range devices {
					dg.Add(1)
					go func() {
						err := c.caster.VerifyDevice(d.Address, d.Port, verifyTimeout)
						if err == nil {
							devicesChan <- d
						}
						dg.Done()
					}()
				}
				dg.Wait()
				close(devicesChan)
				wg.Done()
			}()
			wg.Add(1)
			go func() {
				for d := range devicesChan {
					slog.Debug("device found", "ip", d.Address.String(), "port", d.Port)
					validDevices = append(validDevices, d)
				}
				wg.Done()
			}()

			wg.Wait()
			if len(validDevices) == 0 {
				fmt.Println("no devices found")
				return nil
			}
			fmt.Println("devices found:")
			for _, d := range validDevices {
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
				if len(args) < 2 {
					fmt.Println("not enough arguments to call agent need: agent <command> (args)...")
				}

				c.agentHandler.HandleArgs(args[1:])

				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "quit",
			Description: "exit the program",
			Runner: func(args []string) error {
				if c.caster.GetClient() != nil {
					c.caster.GetClient().TermEnd()
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

	c.agentHandler = cmnd.NewHandler(
		cmnd.HandlerArg{
			Name:        "toggle_pause",
			Description: "toggles if the player is paused",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "toggle_mute",
			Description: "toggles if the player is muted",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "seek",
			Description: "Usage: seek <time>\nseek to a specific time in the media: Use HH:MM:SS",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "current_position",
			Description: "print the current position of the player that is playing the cast media",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "media_duration",
			Description: "print the duration of the media that is casting",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "set_volume",
			Description: "Usage: set_volume <0-100>\nsets the volume of the media player",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "quit",
			Description: "terminate the player and stop casting",
			Runner: func(args []string) error {
				SendAgentCommand(args, c)
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "help",
			Description: "print this message",
			Runner: func(args []string) error {
				fmt.Println("Available commands:")
				fmt.Print(c.agentHandler.GetDescription())
				return nil
			},
		},
	)
	return c
}

func SendAgentCommand(args []string, c *Client) {
	if c.caster == nil {
		fmt.Println("no agent is casting")
		return
	}
	client := c.caster.GetClient()
	if client == nil {
		fmt.Println("no agent is casting")
		return
	}

	handler := client.ControlsHandler()
	if handler == nil {
		fmt.Println("no handler available")
		return
	}

	handler.HandleArgs(args)
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
	defer client.caster.Transport.Close()
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
		case <-client.caster.AuthenticationRequest:
			fmt.Println("Input password:")
			fmt.Print("    ")
			go client.commandHandler.ForceResponse(func(args []string) error {
				client.caster.AuthenticationChan <- []byte(args[0])
				return nil
			})
		case input := <-inputChan:
			args := strings.Split(input, " ")
			client.HandleCommand(args)
		case err := <-client.doneChan:
			fmt.Println("client exited")
			if err != nil {
				slog.Error("error while casting", "error", err)
			}
		case <-client.exitChan:
			return 0
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
