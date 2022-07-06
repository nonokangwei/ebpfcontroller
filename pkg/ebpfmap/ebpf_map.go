package ebpfmap

import (
	"fmt"
	"net"

	ebpf "github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

const (
	maxEntries = 4096
)

var (
	// ErrNoLoadPinnedMap represent pinned map isn't be loaded from userspace
	ErrNoLoadPinnedMap error = errors.New("load pinned map from userspace before you use")

	// ErrMapAlreadyLoaded represent a pinned map has already loaded, it can't be loaded twice
	ErrMapAlreadyLoaded error = errors.New("Map already loaded")
)

type (
	// RedirectMetaMap is a bpf map for golang to accessing
	RedirectMetaMap struct {
		SourceAddr uint32
		DestAddr   uint32
		Bytes      uint64
		Packages   uint64
		Mac        [6]uint8
		IfIndex    uint16
	}

	// ForwardMataMap is a bpf map for golang to accessing
	ForwardMetaMap struct {
		DestAddr uint32
		DestPort uint16
		Padding  uint16
	}

	// BackendServer represent the backend server for loadbalancer
	BackendServer struct {
		SourceAddr string
		DestAddr   string
		Mac        string
		Ifindex    uint16
	}

	// RedirectMetaBPFMapper provides methods to operation bpf mapper of xdp_lb
	RedirectMetaBPFMapper interface {
		Get() ([]ForwardMetaMap, error)
		Set(servers []BackendServer) error
		Load(name string) error
		Insert() error
		BatchInsert() error
	}

	bpfMapper struct {
		name   string
		bpfMap *ebpf.Map
	}
)

// New create a LoadBalanceBPFMapper object
func New() RedirectMetaBPFMapper {
	return &bpfMapper{}
}

func (m *bpfMapper) Load(name string) (err error) {
	if m.bpfMap != nil {
		return ErrMapAlreadyLoaded
	}

	ebpfLoadPinOption := ebpf.LoadPinOptions{}

	m.bpfMap, err = ebpf.LoadPinnedMap(name, &ebpfLoadPinOption)
	if err != nil {
		return errors.Wrapf(err, "Load pinned map %s", name)
	}
	return nil
}

func (m *bpfMapper) Insert() (err error) {
	if m.bpfMap == nil {
		return ErrNoLoadPinnedMap
	}

	daddr := InetAton("192.168.0.1")
	dport := IportAton("12345")

	entry := ForwardMetaMap{daddr, dport, 0}
	key := [8]uint8{1, 1, 1, 1, 1, 1, 1, 1}

	err = m.bpfMap.Put(key, entry)
	if err != nil {
		return errors.Wrapf(err, "Fail to insert entry")
	}

	return nil
}

func (m *bpfMapper) BatchInsert() (err error) {
	if m.bpfMap == nil {
		return ErrNoLoadPinnedMap
	}

	entry := ForwardMetaMap{65535, 4000, 0}
	key := [8]uint8{}

	for i := 0; i < 256; i++ {
		key[0] = uint8(i)
		for j := 0; j < 16; j++ {
			key[1] = uint8(j)
			err = m.bpfMap.Put(key, entry)
			if err != nil {
				return errors.Wrapf(err, "Fail to insert entry")
			}
			fmt.Println("success insert item!")
			fmt.Printf("key: %v, value: %d\n", key, entry)
		}
	}
	return nil
}

func (m *bpfMapper) Get() ([]ForwardMetaMap, error) {
	if m.bpfMap == nil {
		return nil, ErrNoLoadPinnedMap
	}
	// var i uint32 = 0
	var results []ForwardMetaMap

	var key [8]uint8
	var value ForwardMetaMap
	ForwardMetaMapEntries := m.bpfMap.Iterate()
	for ForwardMetaMapEntries.Next(&key, &value) {
		fmt.Printf("key: %v, value: %d\n", key, value)
		results = append(results, value)
	}
	// for ; i < maxEntries; i++ {
	// 	var lb RedirectMetaMap
	// 	err := m.bpfMap.Lookup(i, &lb)
	// 	if err != nil {
	// 		return nil, errors.Wrapf(err, "lookup map of key %d", i)
	// 	}

	// 	results = append(results, lb)
	// }
	return results, nil
}

func (m *bpfMapper) Set(servers []BackendServer) error {
	if m.bpfMap == nil {
		return ErrNoLoadPinnedMap
	}
	var serversNum uint32 = uint32(len(servers))
	if serversNum == 0 {
		return errors.New("servers can't be empty")
	}
	var i uint32 = 0
	for ; i < maxEntries; i++ {
		j := i % serversNum
		daddr := InetAton(servers[j].DestAddr)
		saddr := InetAton(servers[j].SourceAddr)
		mac, err := net.ParseMAC(servers[j].Mac)
		if err != nil {
			return errors.Wrapf(err, "Invalid mac %s address, convert error", servers[j].Mac)
		}

		var lb RedirectMetaMap = RedirectMetaMap{
			SourceAddr: saddr,
			DestAddr:   daddr,
			Bytes:      0,
			Packages:   0,
			IfIndex:    servers[j].Ifindex,
		}
		for i, m := range mac {
			lb.Mac[i] = m
		}
		err = m.bpfMap.Update(i, lb, ebpf.UpdateAny)
		if err != nil {
			return errors.Wrapf(err, "update key %d , value %+v", i, lb)
		}
	}
	return nil
}
