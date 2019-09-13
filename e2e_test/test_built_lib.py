import time
import subprocess
from hamcrest import assert_that, equal_to
from gosnmp_traps_python.rpc_session import SNMPv2cParams, SNMPv3Params, create_session


def test_imports_work():
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

    try:
        session.connect()

        time.sleep(1)

        send_trap = subprocess.Popen('snmptrap -v 2c -c public 127.0.0.1 '' 1.3.6.1.4.1.8072.2.3.0.1 1.3.6.1.4.1.8072.2.3.2.1',
                                     shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

        out, err = send_trap.communicate()
        print(out, err)
        assert_that(send_trap.returncode, equal_to(0))

        time.sleep(1)

        received_traps = session.get_nowait()

        assert_that(len(received_traps), equal_to(1))
        assert_that(received_traps[0].variables[0].oid, equal_to('.1.3.6.1.6.3.1.1.4.1'))
    finally:
        session.close()
