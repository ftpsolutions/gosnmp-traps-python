package gosnmp_traps_python

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ftpsolutions/gosnmp"
)

type multiResult struct {
	OID              string
	Type             string
	IsNull           bool
	IsUnknown        bool
	IsNoSuchInstance bool
	IsNoSuchObject   bool
	IsEndOfMibView   bool
	BoolValue        bool
	IntValue         int
	FloatValue       float64
	ByteArrayValue   []int
	StringValue      string
}

func buildMultiResult(oid string, valueType gosnmp.Asn1BER, value interface{}) (multiResult, error) {
	multiResult := multiResult{
		OID: oid,
	}

	switch valueType {

	case gosnmp.Null:
		fallthrough
	case gosnmp.UnknownType:
		fallthrough
	case gosnmp.NoSuchInstance:
		multiResult.Type = "noSuchInstance"
		multiResult.IsNoSuchInstance = true
		return multiResult, nil

	case gosnmp.NoSuchObject:
		multiResult.Type = "noSuchObject"
		multiResult.IsNoSuchObject = true
		return multiResult, nil

	case gosnmp.EndOfMibView:
		multiResult.Type = "endOfMibView"
		multiResult.IsEndOfMibView = true
		return multiResult, nil

	case gosnmp.Boolean:
		multiResult.Type = "bool"
		multiResult.BoolValue = value.(bool)
		return multiResult, nil

	case gosnmp.Counter32:
		fallthrough
	case gosnmp.Gauge32:
		fallthrough
	case gosnmp.Uinteger32:
		multiResult.Type = "int"
		multiResult.IntValue = int(value.(uint))
		return multiResult, nil

	case gosnmp.Counter64:
		multiResult.Type = "int"
		multiResult.IntValue = int(value.(uint64))
		return multiResult, nil

	case gosnmp.Integer:
		multiResult.Type = "int"
		multiResult.IntValue = value.(int)
		return multiResult, nil
	case gosnmp.TimeTicks:
		multiResult.Type = "int"
		multiResult.IntValue = int(value.(uint))
		return multiResult, nil

	case gosnmp.Opaque:
		multiResult.Type = "float"
		multiResult.FloatValue = value.(float64)
		return multiResult, nil

	case gosnmp.OctetString:
		multiResult.Type = "bytearray"

		valueAsBytes := value.([]byte)
		valueAsInts := make([]int, len(valueAsBytes), len(valueAsBytes))

		for i, c := range valueAsBytes {
			valueAsInts[i] = int(c)
		}

		multiResult.ByteArrayValue = valueAsInts
		return multiResult, nil

	case gosnmp.ObjectIdentifier:
		fallthrough
	case gosnmp.IPAddress:
		multiResult.Type = "string"
		multiResult.StringValue = value.(string)
		return multiResult, nil

	}

	return multiResult, fmt.Errorf("Unknown type; oid=%v, type=%v, value=%v", oid, valueType, value)
}

type receivedTrap struct {
	Time    time.Time
	Addr    net.UDPAddr
	Results []multiResult
}

type session struct {
	host          string
	port          int
	params        []*gosnmp.GoSNMP
	trapListener  *gosnmp.TrapListener
	quit          chan struct{}
	startWg       sync.WaitGroup
	stopWg        sync.WaitGroup
	receivedTraps chan receivedTrap
}

func handleListen(s *session) {
	s.stopWg.Add(1)

	if s.trapListener == nil {
		return
	}

	if s.trapListener.GetConn() != nil {
		return
	}

	s.startWg.Done()

	err := s.trapListener.Listen(fmt.Sprintf("%s:%d", s.host, s.port))
	if err != nil {
		log.Panic(err)
	}

	s.stopWg.Done()
}

func newSession(host string, port int, params []*gosnmp.GoSNMP) *session {
	s := session{
		host:          host,
		port:          port,
		params:        params,
		receivedTraps: make(chan receivedTrap, 524288),
	}

	return &s
}

func (s *session) trapHandler(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	receivedTrap := receivedTrap{
		Time: time.Now(),
		Addr: *addr,
	}

	for _, v := range packet.Variables {
		multiResult, err := buildMultiResult(v.Name, v.Type, v.Value)
		if err != nil {
			log.Fatal(err)
		}

		receivedTrap.Results = append(receivedTrap.Results, multiResult)
	}

	select {
	case s.receivedTraps <- receivedTrap:
	default:
		fmt.Println("error: ", fmt.Errorf("channel %+v full, throwing away %+v", s.receivedTraps, receivedTrap))
	}
}

func (s *session) connect() {
	if s.trapListener != nil {
		if s.trapListener.GetConn() != nil {
			return
		}
	}

	s.trapListener = gosnmp.NewTrapListener()
	s.trapListener.Params = s.params
	s.trapListener.OnNewTrap = s.trapHandler

	s.startWg.Add(1)

	go handleListen(s)

	s.startWg.Wait()
}

func (s *session) getNoWait() ([]receivedTrap, error) {
	receivedTraps := make([]receivedTrap, 0)

	for {
		select {
		case receivedTrap := <-s.receivedTraps:
			receivedTraps = append(receivedTraps, receivedTrap)
		default:
			if len(receivedTraps) == 0 {
				return receivedTraps, fmt.Errorf("receivedTraps empty in %+v", s)
			}

			return receivedTraps, nil
		}
	}
}

func (s *session) close() {
	if s.trapListener == nil {
		return
	}

	if s.trapListener.GetConn() == nil {
		return
	}

	s.trapListener.Close()

	s.trapListener = nil

	s.stopWg.Wait()
}
