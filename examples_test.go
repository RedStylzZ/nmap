package nmap

import (
	"context"
	"fmt"
	"log"
	"net"
)

// A scanner can be instantiated with options to set the arguments
// that are given to nmap.
func ExampleScanner_simple() {
	s, err := NewScanner(
		context.Background(),
		WithTargets("google.com", "facebook.com", "youtube.com"),
		WithCustomDNSServers("8.8.8.8", "8.8.4.4"),
		WithTimingTemplate(TimingFastest),
		WithTCPScanFlags(FlagACK, FlagNULL, FlagRST),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	scanResult, _, err := s.Run()
	if err != nil {
		log.Fatalf("nmap encountered an error: %v", err)
	}

	fmt.Printf(
		"Scan successful: %d hosts up\n",
		scanResult.Stats.Hosts.Up,
	)
	// Output: Scan successful: 3 hosts up
}

func startServer(ctx context.Context, host string) error {
	listener, err := net.Listen("tcp", host)
	if err != nil {
		return err
	}
	defer listener.Close()

	<-ctx.Done()

	return nil
}

//func startServers(ctx context.Context, hosts ...string) error {
//	ctx, cancel := context.WithCancel(ctx)
//	defer cancel()
//
//	var errs []error
//	for i, host := range hosts {
//		go func() {
//			err := startServer(ctx, host, i%2 == 0)
//			if err != nil {
//				errs = append(errs, err)
//				cancel()
//			}
//		}()
//	}
//
//	<-ctx.Done()
//
//	return errors.Join(append(errs, ctx.Err())...)
//}

// A scanner can be given custom idiomatic filters for both hosts
// and ports.
func ExampleScanner_filters() {
	ports := []string{"8976", "8977"}
	s, err := NewScanner(
		context.Background(),
		WithTargets("localhost"),
		WithPorts(ports...),
		WithFilterPort(func(port Port) bool { return port.Status() == Closed }),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		err := startServer(ctx, ":"+ports[0])
		if err != nil {
			log.Fatalf("unable to start server: %s", err)
		}
	}()

	scanResult, _, err := s.Run()
	if err != nil {
		log.Fatalf("nmap encountered an error: %s", err)
	}

	fmt.Printf(
		"Filtered out ports: %d / Original number of ports: %d\n",
		len(scanResult.Hosts[0].Ports),
		len(ports),
	)
	// Output: Filtered out ports: 1 / Original number of ports: 2
}
