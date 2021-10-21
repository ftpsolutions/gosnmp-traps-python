import datetime
import json
from collections import namedtuple

from dateutil.parser import parser

SNMPVariable = namedtuple("SNMPVariable", ["oid", "oid_index", "snmp_type", "value"])

MultiResult = namedtuple(
    "MultiResult",
    [
        "OID",
        "Type",
        "IsNull",
        "IsUnknown",
        "IsNoSuchInstance",
        "IsNoSuchObject",
        "IsEndOfMibView",
        "BoolValue",
        "IntValue",
        "FloatValue",
        "ByteArrayValue",
        "StringValue",
    ],
)

ReceivedTrap = namedtuple(
    "ReceivedTrap",
    [
        "is_snmpv1",
        "timestamp",
        "source_ip",
        "source_port",
        "variables",
        # SNMPv1 only
        "enterprise",
        "generic_trap",
        "specific_trap",
        "uptime",
    ],
)

_PARSER = parser()


class UnknownSNMPTypeError(Exception):
    pass


class GoRuntimeError(Exception):
    pass


def handle_exception(method, args, other=None):
    try:
        return method(*args)
    except Exception as e:
        e = e if not hasattr(e, "__cause__") and isinstance(e.__cause__, BaseException) else e.__cause__

        new_args = ("attempt to call {} on the Go side raised {}".format("{}(*{})".format(repr(method), repr(args)), repr(e)),)

        e.args = new_args

        raise GoRuntimeError(e)


def handle_received_traps_json(received_traps_json_string, session=None):
    try:
        received_traps_json = json.loads(received_traps_json_string)
    except ValueError as e:
        raise ValueError("{0} raised {1} while parsing {2}".format(session, e, repr(received_traps_json_string)))

    return received_traps_json


def handle_multi_result(multi_result):
    raw_oid = multi_result.OID.strip(". ")

    oid = ".{0}".format(".".join(raw_oid.split(".")[0:-1]).strip("."))
    oid_index = int(raw_oid.split(".")[-1])

    if multi_result.Type in ["noSuchInstance", "noSuchObject", "endOfMibView"]:
        return SNMPVariable(
            oid=oid,
            oid_index=oid_index,
            snmp_type=multi_result.Type,
            value=None,
        )
    elif multi_result.Type in ["bool"]:
        return SNMPVariable(
            oid=oid,
            oid_index=oid_index,
            snmp_type=multi_result.Type,
            value=multi_result.BoolValue,
        )
    elif multi_result.Type in ["int"]:
        return SNMPVariable(
            oid=oid,
            oid_index=oid_index,
            snmp_type=multi_result.Type,
            value=multi_result.IntValue,
        )
    elif multi_result.Type in ["float"]:
        return SNMPVariable(
            oid=oid,
            oid_index=oid_index,
            snmp_type=multi_result.Type,
            value=multi_result.FloatValue,
        )
    elif multi_result.Type in ["bytearray"]:
        return SNMPVariable(
            oid=oid,
            oid_index=oid_index,
            snmp_type=multi_result.Type,
            value="".join([chr(x) for x in multi_result.ByteArrayValue]),
        )
    elif multi_result.Type in ["string"]:
        return SNMPVariable(
            oid=oid,
            oid_index=oid_index,
            snmp_type=multi_result.Type,
            value=multi_result.StringValue,
        )

    raise UnknownSNMPTypeError("{0} represents an unknown SNMP type".format(multi_result))


def handle_received_traps(received_traps_json):
    return [
        ReceivedTrap(
            is_snmpv1=x["IsSNMPv1"],
            timestamp=_PARSER.parse(x["Time"]),
            source_ip=x["Addr"]["IP"],
            source_port=x["Addr"]["Port"],
            variables=[handle_multi_result(MultiResult(**y)) for y in (x["Results"] if x["Results"] is not None else [])],
            enterprise=x["Enterprise"] if x["IsSNMPv1"] else None,
            generic_trap=x["GenericTrap"] if x["IsSNMPv1"] else None,
            specific_trap=x["SpecificTrap"] if x["IsSNMPv1"] else None,
            uptime=datetime.timedelta(seconds=x["Uptime"] / 100.0) if x["IsSNMPv1"] else None,
        )
        for x in received_traps_json
    ]
