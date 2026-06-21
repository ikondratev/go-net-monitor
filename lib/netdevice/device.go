package netdevice

import "github.com/google/gopacket/pcap"

func FindActiveDevice() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, d := range devices {
		if len(d.Addresses) > 0 {
			for _, addr := range d.Addresses {
				if !addr.IP.IsLoopback() {
					return d.Name, nil
				}
			}
		}
	}
	return "eth0", nil
}
