package main

import (
	"ebpfcontroller/demo/pkg/ebpfmap"
	"flag"
	"fmt"
	"log"
	"os"

	gokitlog "github.com/go-kit/kit/log"
)

func init() {
	logger := gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(os.Stderr))
	logger = gokitlog.With(logger, "ts", gokitlog.DefaultTimestampUTC, "caller", gokitlog.DefaultCaller)
	logger = gokitlog.With(logger, "pid", os.Getpid())
	log.SetOutput(gokitlog.NewStdlibAdapter(logger))
}

func init() {
	logger := gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(os.Stderr))
	logger = gokitlog.With(logger, "ts", gokitlog.DefaultTimestampUTC, "caller", gokitlog.DefaultCaller)
	logger = gokitlog.With(logger, "pid", os.Getpid())
	log.SetOutput(gokitlog.NewStdlibAdapter(logger))
}

func main() {
	err := <-parseFlag().run()
	log.Fatalf("boot lbmap server error: %s", err)
}

type server struct {
	addr    string
	mapName string
}

func (s *server) run() <-chan error {
	mapper := ebpfmap.New()
	err := mapper.Load(s.mapName)
	if err != nil {
		c := make(chan error)
		go func() <-chan error {
			c <- fmt.Errorf("load mapper for %s error :%s", s.mapName, err)
			return c
		}()
		return c
	}
	_, err = mapper.Get()
	if err != nil {
		c := make(chan error)
		go func() <-chan error {
			c <- fmt.Errorf("get map item error :%s", err)
			return c
		}()
		return c
	}
	// err = mapper.BatchInsert()
	// if err != nil {
	// 	c := make(chan error)
	// 	go func() <-chan error {
	// 		c <- fmt.Errorf("batch insert map item error :%s", err)
	// 		return c
	// 	}()
	// 	return c
	// }
	c := make(chan error)
	return c
}

func parseFlag() *server {
	addr := flag.String("address", ":9091", "Listen address of api server")
	mapName := flag.String("map", "/sys/fs/bpf/ens5/forward_params", "name of ebpf map")
	flag.Parse()
	return &server{*addr, *mapName}
}
