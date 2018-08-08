## gosnmp-traps-python

The purpose of this module is to provide a Python interface to the Golang [gosnmp](https://github.com/soniah/gosnmp) module (but only for the SNMP traps side of that library and with a few tweaks).

It was made very easy with the help of the Golang [gopy](https://github.com/go-python/gopy) module.

#### Limitations

* Python command needs to be prefixed with GODEBUG=cgocheck=0 (or have that in the environment)
* I've not implemented walk (as I didn't need it for my use-case, I just use get_next with Python)
* Seems to have some odd memory problems with PyPy (via CFFI); lots of locks and stuff to try and alleviate that

#### How do I make use of this?

Right now I'm still working on how to put it all together as a Python module, so here are the raw steps.

#### Prerequisites

* Go 1.9 or Go 1.10
* Python 2.7+, Python 3.5+, PyPy 5.10+ or PyPy3 5.10+
* pip
* virtualenvwrapper
* pkgconfig/pkg-config

#### Setup (for dev)

* ```mkvirtualenvwrapper -p (/path/to/pypy) gosnmp-traps-python``` 
* ```pip install -r requirements-dev.txt```
* ```./build.sh```
* ```GODEBUG=cgocheck=0 py.test -v```

#### What's worth knowing if I want to further the development?

* gopy doesn't like Go interfaces; so make sure you don't have any public (exported) interfaces
    * this includes a struct with a public property that may eventually lead to an interface

#### Example Go RPCSession usage (simple session ID, calls return JSON)

The only reason you'd want to use this (in Golang) is if you wanted to listen on a single port for multiple different SNMP configurations.

```
package main

import (
	"bufio"
	"fmt"
	"gosnmp_traps_python"
	"log"
	"os"
)

func main() {
	// we need this because without it, we'll try and manipulate the Python GIL (which may not be present)
	gosnmp_traps_python.SetPyPy()

	// define both an SNMPv2c and SNMPv3 trap configurations
	paramsJSON := `
	[
		{
			"Community": "public"
		},
		{
			"SecurityLevel": "authPriv",
			"SecurityUsername": "some_username",
			"AuthenticationProtocol": "SHA",
			"AuthenticationPassword": "some_auth_password",
			"PrivacyProtocol": "AES",
			"PrivacyPassword": "some_priv_password"
		}
	]
	`

	sessionID, err := gosnmp_traps_python.NewRPCSession(
		"0.0.0.0",
		162,
		5,
		paramsJSON,
	)
	if err != nil {
		log.Fatal(err)
	}

	err = gosnmp_traps_python.RPCConnect(sessionID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("Press enter to quit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	result, err := gosnmp_traps_python.RPCGetNoWait(sessionID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)

	gosnmp_traps_python.RPCClose(sessionID)
}
```

#### Example Python usage (uses RPCSession underneath because of memory leaks between Go and Python with structs)

The example belows shows how to define the same two listeners we defined above (using the `SNMPv2cParams` and `SNMPv3Params`)

```
import pprint
import time

from gosnmp_traps_python.rpc_session import SNMPv2cParams, SNMPv3Params, create_session

session = create_session(
    params_list=[
        SNMPv2cParams(
            community_string='public',
        ),
        SNMPv3Params(
            security_username='some_username',
            security_level='authPriv',
            auth_protocol='SHA',
            auth_password='some_auth_password',
            privacy_protocol='AES',
            privacy_password='some_priv_password',
        )
    ]
)

session.connect()

print 'CTRL + C to quit'

while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        break

print ''

received_traps = session.get_nowait()

pprint.pprint(received_traps)

session.close()
```

If we run the above code and then send some SNMP traps to this listener (in my example, I configured a Cisco switch to export traps and ran the "conf t" command) then we'll get some output similar to the below:

```
[
    ReceivedTrap(
        timestamp=datetime.datetime(2018, 8, 8, 9, 57, 42, 574456, tzinfo=tzoffset(None, 28800)), 
        source_ip=u'10.10.0.2', 
        source_port=54199, 
        variables=[
            SNMPVariable(
                oid=u'.1.3.6.1.2.1.1.3', 
                oid_index=0, 
                snmp_type=u'int', 
                value=206412043
            ), 
            SNMPVariable(
                oid=u'.1.3.6.1.6.3.1.1.4.1', 
                oid_index=0, 
                snmp_type=u'string', 
                value=u'.1.3.6.1.4.1.9.9.43.2.0.1'
            ), 
            SNMPVariable(
                oid=u'.1.3.6.1.4.1.9.9.43.1.1.6.1.3', 
                oid_index=223, 
                snmp_type=u'int', 
                value=1
            ), 
            SNMPVariable(
                oid=u'.1.3.6.1.4.1.9.9.43.1.1.6.1.4', 
                oid_index=223, 
                snmp_type=u'int', 
                value=2
            ), 
            SNMPVariable(
                oid=u'.1.3.6.1.4.1.9.9.43.1.1.6.1.5', 
                oid_index=223, 
                snmp_type=u'int', 
                value=
            3)
        ]
    )
]
```
 
So to summarise, each call to `get_nowait()` will either raise `Queue.Empty` or return a list of `ReceivedTrap` objects.

The SNMPVariable object is meant to feel like [easysnmp](https://github.com/kamakazikamikaze/easysnmp).
