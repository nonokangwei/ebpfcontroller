package ebpfmap

import (
	"encoding/hex"
	"fmt"

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
	// ForwardMataMap is a bpf map for golang to accessing
	ForwardMetaMap struct {
		DestAddr uint32
		DestPort uint16
		Padding  uint16
	}

	// RedirectMetaBPFMapper provides methods to operation bpf mapper of xdp_lb
	RedirectMetaBPFMapper interface {
		Get() ([]ForwardMetaMap, error)
		Load(name string) error
		Insert(gsAddress string, gsPort string, fingerprintToken string) error
		BatchInsert() error
		Delete(fingerprintToken string) error
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
	m.name = name
	if err != nil {
		return errors.Wrapf(err, "Load pinned map %s", name)
	}
	return nil
}

func (m *bpfMapper) Insert(gsAddress string, gsPort string, fingerprintToken string) (err error) {
	if m.bpfMap == nil {
		return ErrNoLoadPinnedMap
	}

	daddr := InetAton(gsAddress)
	dport := IportAton(gsPort)

	var key []byte
	entry := ForwardMetaMap{daddr, dport, 0}
	key, err = hex.DecodeString(fingerprintToken)
	if err != nil {
		return errors.Wrapf(err, "Fail to convert token, please check token encoding with HEX")
	}

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

	// Set daddr, dport here
	// daddr := InetAton("")
	// dport := IportAton("")
	// entry := ForwardMetaMap{daddr, dport, 0}
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

	return results, nil
}

func (m *bpfMapper) Delete(fingerprintToken string) (err error) {
	if m.bpfMap == nil {
		return ErrNoLoadPinnedMap
	}

	var key []byte
	key, err = hex.DecodeString(fingerprintToken)
	if err != nil {
		return errors.Wrapf(err, "Fail to convert token, please check token encoding with HEX")
	}

	err = m.bpfMap.Delete(key)
	if err != nil {
		return errors.Wrapf(err, "Fail to delete entry")
	}

	return nil
}
