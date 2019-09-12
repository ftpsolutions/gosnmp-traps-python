from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import json
from sys import version as python_version
from sys import version_info
from threading import RLock

from builtins import *
from builtins import object, str
from future import standard_library

from .common import (handle_exception, handle_received_traps,
                     handle_received_traps_json)

standard_library.install_aliases()

is_pypy = 'pypy' in python_version.lower()
version = version_info[:3]

# needed for CFFI under Python2
if version < (3, 0, 0):
    from past.types.oldstr import oldstr as str

if not is_pypy and version < (3, 0, 0):  # for Python2
    from .py2.gosnmp_traps_python_go import SetPyPy, NewRPCSession, RPCConnect, RPCGetNoWait, RPCClose
else:  # for all versions of PyPy and also Python3
    raise ValueError('PyPy and Python3 is not supported. Waiting for gopy CFFI support')
#     from .cffi.gosnmp_traps_python import SetPyPy, NewRPCSession, RPCConnect, RPCGetNoWait, RPCClose
#
#     SetPyPy()
#
#     print('WARNING: PyPy or Python3 detected, will use CFFI- be prepared for very odd behaviour')

_ = object
_ = str

_new_session_lock = RLock()


def _new_rpc_session(*args):
    with _new_session_lock:
        return handle_exception(
            NewRPCSession, args
        )


class RPCSession(object):
    def __init__(self, session_id, **kwargs):
        self._session_id = session_id
        self._kwargs = kwargs

    def __del__(self):
        try:
            self.close()
        except BaseException:
            pass

    def __repr__(self):
        return '{0}(session_id={1}, {2})'.format(
            self.__class__.__name__,
            repr(self._session_id),
            ', '.join('{0}={1}'.format(k, repr(v)) for k, v in list(self._kwargs.items()))
        )

    def connect(self):
        return handle_exception(RPCConnect, (self._session_id,), self)

    def get_nowait(self):
        return handle_received_traps(
            handle_received_traps_json(
                handle_exception(RPCGetNoWait, (self._session_id,), self),
                self,
            )
        )

    def close(self):
        return handle_exception(RPCClose, (self._session_id,), self)


_PARAMS_MAPPING = {
    'Community': 'community_string',
    'ContextName': 'context_name',
    'SecurityUsername': 'security_username',
    'SecurityLevel': 'security_level',
    'PrivacyPassword': 'privacy_password',
    'PrivacyProtocol': 'privacy_protocol',
    'AuthenticationPassword': 'auth_password',
    'AuthenticationProtocol': 'auth_protocol',
    'Timeout': 'timeout',
}


class _Params(object):
    def __init__(self):
        self.dict = {}

    def __str__(self):
        return json.dumps(self.dict)

    def __repr__(self):
        return '<{}({}) at {}>'.format(
            self.__class__.__name__,
            ', '.join(['{}={}'.format(_PARAMS_MAPPING[k], repr(v)) for k, v in self.dict.iteritems()]),
            hex(id(self))
        )

    def __iter__(self):
        return self.dict.iteritems()


class SNMPv2cParams(_Params):
    def __init__(self, community_string):
        super(SNMPv2cParams, self).__init__()

        self.dict.update({
            'Community': community_string
        })


class SNMPv3Params(_Params):
    def __init__(self, security_username, security_level, auth_password, auth_protocol, privacy_password,
                 privacy_protocol, context_name=None):
        super(SNMPv3Params, self).__init__()

        self.dict.update({
            'SecurityUsername': security_username,
            'SecurityLevel': security_level,
            'AuthenticationPassword': auth_password,
            'AuthenticationProtocol': auth_protocol,
            'PrivacyPassword': privacy_password,
            'PrivacyProtocol': privacy_protocol,
            'ContextName': context_name if context_name is not None else '',
        })


def create_session(params_list, hostname=None, port=162, timeout=5):
    hostname = hostname if hostname is not None else '0.0.0.0'

    params_json = json.dumps([dict(x) for x in params_list])

    session_id = _new_rpc_session(
        str(hostname),
        int(port),
        int(timeout),
        params_json,
    )

    kwargs = {
        'hostname': hostname,
        'params_list': params_list,
        'port': port,
        'timeout': timeout,
    }

    return RPCSession(
        session_id=session_id,
        **kwargs
    )
