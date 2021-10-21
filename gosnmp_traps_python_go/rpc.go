package gosnmp_traps_python_go

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ftpsolutions/gosnmp"
	"os"
	"strconv"
)

var sessionMutex sync.Mutex
var sessions map[uint64]*session
var lastSessionID uint64

func init() {
	sessions = make(map[uint64]*session)

	time.Sleep(time.Second) // give the Python side a little time to settle
}

// this is used to ensure the Go runtime keeps operating in the event of strange errors
func handlePanic(extra string, sessionID uint64, s *session, err error) {
	log.Printf(
		fmt.Sprintf(
			"handlePanic() for %v()\n\tSessionID: %v\n\tSession: %+v\n\tError: %v\n\nStack trace follows:\n\n%v",
			extra,
			sessionID,
			&s,
			err,
			string(debug.Stack()),
		),
	)
}

type params struct {
	Community              string
	ContextName            string
	SecurityUsername       string
	SecurityLevel          string
	PrivacyPassword        string
	PrivacyProtocol        string
	AuthenticationPassword string
	AuthenticationProtocol string
	Timeout                int
}

func getSecurityLevel(securityLevel string) gosnmp.SnmpV3MsgFlags {
	securityLevel = strings.ToLower(securityLevel)
	actualSecurityLevel := gosnmp.NoAuthNoPriv

	switch securityLevel {
	case "authnopriv":
		actualSecurityLevel = gosnmp.AuthNoPriv
	case "authpriv":
		actualSecurityLevel = gosnmp.AuthPriv
	}

	return actualSecurityLevel
}

func getPrivacyDetails(privacyPassword, privacyProtocol string) (string, gosnmp.SnmpV3PrivProtocol) {
	if privacyProtocol == "" {
		privacyPassword = ""
	}

	actualPrivacyProtocol := gosnmp.NoPriv

	switch privacyProtocol {

	case "DES":
		actualPrivacyProtocol = gosnmp.DES
	case "AES":
		actualPrivacyProtocol = gosnmp.AES

	}

	return privacyPassword, actualPrivacyProtocol
}

func getAuthenticationDetails(AuthenticationPassword, AuthenticationProtocol string) (string, gosnmp.SnmpV3AuthProtocol) {
	if AuthenticationProtocol == "" {
		AuthenticationPassword = ""
	}

	actualAuthenticationProtocol := gosnmp.NoAuth

	switch AuthenticationProtocol {

	case "MD5":
		actualAuthenticationProtocol = gosnmp.MD5
	case "SHA":
		actualAuthenticationProtocol = gosnmp.SHA

	}

	return AuthenticationPassword, actualAuthenticationProtocol
}

func getLogger(snmpProtocol string, port int) *log.Logger {
	envDebug := os.Getenv("GOSNMP_TRAPS_PYTHON_DEBUG")
	if len(envDebug) <= 0 {
		return nil
	}

	debugEnabled, err := strconv.ParseBool(envDebug)
	if err != nil {
		return nil
	}

	if !debugEnabled {
		return nil
	}

	return log.New(
		os.Stdout,
		fmt.Sprintf("%v:%v\t", snmpProtocol, port),
		0,
	)
}

func handleParamsJSON(port, timeout int, paramsJSON string) ([]*gosnmp.GoSNMP, error) {
	handledParams := []params{}
	paramsGoSNMP := make([]*gosnmp.GoSNMP, 0)

	err := json.Unmarshal([]byte(paramsJSON), &handledParams)
	if err != nil {
		return paramsGoSNMP, err
	}

	for i, handledParam := range handledParams {
		paramGoSNMP := &gosnmp.GoSNMP{
			Port:    uint16(port),
			Timeout: time.Second * time.Duration(timeout),
			MaxOids: math.MaxInt32,
		}

		if len(handledParam.Community) != 0 {
			logger := getLogger("SNMPv2c", port)
			if logger != nil {
				paramGoSNMP.Logger = logger
			}

			paramGoSNMP.Version = gosnmp.Version2c
			paramGoSNMP.Community = handledParam.Community
		} else if len(handledParam.SecurityLevel) != 0 {
			logger := getLogger("SNMPv3", port)
			if logger != nil {
				paramGoSNMP.Logger = logger
			}

			paramGoSNMP.Version = gosnmp.Version3
			paramGoSNMP.SecurityModel = gosnmp.UserSecurityModel

			paramGoSNMP.MsgFlags = getSecurityLevel(handledParam.SecurityLevel)

			privacyPassword, privacyProtocol := getPrivacyDetails(
				handledParam.PrivacyPassword,
				handledParam.PrivacyProtocol,
			)

			authenticationPassword, authenticationProtocol := getAuthenticationDetails(
				handledParam.AuthenticationPassword,
				handledParam.AuthenticationProtocol,
			)

			paramGoSNMP.SecurityParameters = &gosnmp.UsmSecurityParameters{
				UserName:                 handledParam.SecurityUsername,
				AuthenticationPassphrase: authenticationPassword,
				AuthenticationProtocol:   authenticationProtocol,
				PrivacyPassphrase:        privacyPassword,
				PrivacyProtocol:          privacyProtocol,
			}
		} else {
			return paramsGoSNMP, fmt.Errorf(
				"entry %v params JSON of %v failed to return a useable SNMPv2 or SNMPv3 configuration",
				i, paramsJSON,
			)
		}

		paramsGoSNMP = append(paramsGoSNMP, paramGoSNMP)
	}

	return paramsGoSNMP, nil
}

// NewRPCSession creates a new Session and returns the sessionID
func NewRPCSession(hostname string, port, timeout int, paramsJSON string) (uint64, error) {
	tState := releaseGIL()
	defer reacquireGIL(tState)

	paramsGoSNMP, err := handleParamsJSON(port, timeout, paramsJSON)
	if err != nil {
		return 0, err
	}

	session := newSession(
		hostname,
		port,
		paramsGoSNMP,
	)

	sessionMutex.Lock()
	sessionID := lastSessionID
	lastSessionID++
	sessions[sessionID] = session
	sessionMutex.Unlock()

	return sessionID, nil
}

// RPCConnect calls .connect on the Session identified by the sessionID
func RPCConnect(sessionID uint64) error {
	tState := releaseGIL()
	defer reacquireGIL(tState)

	var err error

	sessionMutex.Lock()
	val, ok := sessions[sessionID]
	sessionMutex.Unlock()

	// permit recovering from a panic but return the error
	defer func(s *session) {
		if r := recover(); r != nil {
			if handledError, _ := r.(error); handledError != nil {
				handlePanic("connect", sessionID, val, handledError)
				err = handledError
			}
		}
	}(val)

	if ok {
		val.connect()
	} else {
		err = fmt.Errorf("sessionID %v does not exist", sessionID)
	}

	return err
}

// RPCGetNoWait calls .get on the Session identified by the sessionID
func RPCGetNoWait(sessionID uint64) (string, error) {
	tState := releaseGIL()
	defer reacquireGIL(tState)

	var err error
	var result string

	sessionMutex.Lock()
	val, ok := sessions[sessionID]
	sessionMutex.Unlock()

	// permit recovering from a panic but return the error
	defer func(s *session) {
		if r := recover(); r != nil {
			if handledError, _ := r.(error); handledError != nil {
				handlePanic("getNoWait", sessionID, val, handledError)
				err = handledError
			}
		}
	}(val)

	if !ok {
		return result, fmt.Errorf("sessionID %v does not exist", sessionID)
	}

	receivedTraps, err := val.getNoWait()
	if err != nil {
		return result, err
	}

	resultBytes, err := json.Marshal(receivedTraps)
	if err != nil {
		return result, err
	}

	result = string(resultBytes)

	return result, err
}

// RPCClose calls .close on the Session identified by the sessionID
func RPCClose(sessionID uint64) {
	tState := releaseGIL()
	defer reacquireGIL(tState)

	sessionMutex.Lock()
	val, ok := sessions[sessionID]
	sessionMutex.Unlock()

	if !ok {
		return
	}

	sessionMutex.Lock()
	delete(sessions, sessionID)
	sessionMutex.Unlock()

	// permit recovering from a panic silently (bury the error)
	defer func(s *session) {
		if r := recover(); r != nil {
			if handledError, _ := r.(error); handledError != nil {
				handlePanic("close", sessionID, val, handledError)
			}
		}
	}(val)

	val.close()
}
