"""
Manual mem test.
1. Make a virtual env and install all deps
2. run `build.sh`
3. run `python mem_test.py`
4. Watch memory usage and make sure it doesn't get out of control
"""
from gosnmp_traps_python.rpc_session import SNMPv2cParams, SNMPv3Params, create_session
from gosnmp_traps_python.common import GoRuntimeError
import traceback
import subprocess
import Queue
import time
from guppy import hpy


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

print(hpy().heap())

err_count = 0
while True:
    try:
        send_trap = subprocess.Popen('snmptrap -v 2c -c public 127.0.0.1 '' 1.3.6.1.4.1.8072.2.3.0.1 1.3.6.1.4.1.8072.2.3.2.1',
                                             shell=True,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)

        out, err = send_trap.communicate()
        received_traps = session.get_nowait()
        print(received_traps)
    except Queue.Empty:
        pass
    except KeyboardInterrupt:
        break
    except (RuntimeError, GoRuntimeError):
        err_count += 1

print(hpy().heap())

print('done')


