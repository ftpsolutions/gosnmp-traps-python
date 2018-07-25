package gosnmp_traps_python

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ftpsolutions/gosnmp"
)

type MultiResult struct {
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

func BuildMultiResult(oid string, valueType gosnmp.Asn1BER, value interface{}) (MultiResult, error) {
	multiResult := MultiResult{
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

type ReceivedTrap struct {
	Time    time.Time
	Addr    net.UDPAddr
	Results []MultiResult
}

func handleListen(s *Session) {
	s.stopWg.Add(1)

	if s.trapListener == nil {
		fmt.Println("no tl")
		return
	}

	if s.trapListener.GetConn() != nil {
		fmt.Println("conn")
		return
	}

	s.startWg.Done()

	err := s.trapListener.Listen(fmt.Sprintf("%s:%d", s.host, s.port))
	if err != nil {
		log.Panic(err)
	}

	s.stopWg.Done()
}

type Session struct {
	host          string
	port          int
	params        []*gosnmp.GoSNMP
	trapListener  *gosnmp.TrapListener
	quit          chan struct{}
	startWg       sync.WaitGroup
	stopWg        sync.WaitGroup
	receivedTraps chan ReceivedTrap
}

func NewSession(host string, port int, params []*gosnmp.GoSNMP) *Session {
	s := Session{
		host:          host,
		port:          port,
		params:        params,
		receivedTraps: make(chan ReceivedTrap, 524288),
	}

	return &s
}

func (s *Session) trapHandler(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	receivedTrap := ReceivedTrap{
		Time: time.Now(),
		Addr: *addr,
	}

	for _, v := range packet.Variables {
		multiResult, err := BuildMultiResult(v.Name, v.Type, v.Value)
		if err != nil {
			log.Fatal(err)
		}

		receivedTrap.Results = append(receivedTrap.Results, multiResult)
	}

	select {
	case s.receivedTraps <- receivedTrap:
	default:
		err := fmt.Errorf("channel %+v full, throwing away %+v", s.receivedTraps, receivedTrap)
		fmt.Println("error: ", err)
	}
}

func (s *Session) Connect() {
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

func (s *Session) GetNoWait() ([]ReceivedTrap, error) {
	receivedTraps := make([]ReceivedTrap, 0)

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

func (s *Session) Close() {
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
