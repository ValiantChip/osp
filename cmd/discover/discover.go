package main

import (
	"github.com/ValiantChip/osp/mdns"
)

func PrintDevices() {
	client := mdns.NewClient()
	client.FindDevices()

	devices := client.Devices()

	for _, d := range devices {
		print("Device: " + d.Address.String() + " Names: ")
		for _, n := range d.Names {
			print(n)
		}
		print("\n")
	}

	if len(devices) == 0 {
		println("No devices found")
	}
}

func main() {
	PrintDevices()
}
