package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"ebpfcontroller/demo/pkg/api"
	"ebpfcontroller/demo/pkg/ebpfmap"

	gokitlog "github.com/go-kit/kit/log"
)

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
	apiAddr          string
	mapName          string
	gsAddr           string
	gsPort           string
	ctlAction        string
	fingerprintToken string
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

	switch action := s.ctlAction; action {
	case "list":
		_, err = mapper.Get()
		if err != nil {
			c := make(chan error)
			go func() <-chan error {
				c <- fmt.Errorf("get map item error :%s", err)
				return c
			}()
			return c
		}
		os.Exit(0)
	case "batchinsert":
		err = mapper.BatchInsert()
		if err != nil {
			c := make(chan error)
			go func() <-chan error {
				c <- fmt.Errorf("batch insert map item error :%s", err)
				return c
			}()
			return c
		}
		os.Exit(0)
	case "insert":
		err = mapper.Insert(s.gsAddr, s.gsPort, s.fingerprintToken)
		if err != nil {
			c := make(chan error)
			go func() <-chan error {
				c <- fmt.Errorf("insert map item error :%s", err)
				return c
			}()
			return c
		}
		os.Exit(0)
	case "delete":
		err = mapper.Delete(s.fingerprintToken)
		if err != nil {
			c := make(chan error)
			go func() <-chan error {
				c <- fmt.Errorf("delete map item error :%s", err)
				return c
			}()
			return c
		}
		os.Exit(0)
	default:
		redirectRule := api.NewRedirectRule(mapper, s.apiAddr)
		return redirectRule.Run()
	}

	c := make(chan error)
	return c
}

func parseFlag() *server {
	apiAddr := flag.String("apiaddress", ":9091", "Listen address of api server")
	gameserverAddr := flag.String("gsaddress", "0.0.0.0", "Listen address of game server")
	gameserverPort := flag.String("gsport", "0", "Listen port of game server")
	mapName := flag.String("map", "/sys/fs/bpf/ens4/forward_params", "name of ebpf map")
	ctlAction := flag.String("action", "runapi", "insert: insert map entry, batchinsert: batch insert 4K entries, delete: delete all map entries, list: list all map entries")
	fingerprintToken := flag.String("token", "6161616161616161", "token encode in HEX byte")
	flag.Parse()
	return &server{*apiAddr, *mapName, *gameserverAddr, *gameserverPort, *ctlAction, *fingerprintToken}
}
