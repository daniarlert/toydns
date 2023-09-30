import socket
from dataclasses import dataclass, field
from enum import Enum
from random import randrange
from struct import Struct
from typing import Iterator, Self, Any

from utils import unpack_from, encode_name, decode_name


class DnsType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    RP = 17
    AAAA = 28
    SRV = 33


class DnsClass(Enum):
    IN = 1


@dataclass(slots=True)
class Question:
    name: str
    _type_: DnsType = DnsType.A
    _class_: DnsClass = DnsClass.IN

    _struct_ = Struct("!HH")

    def encode(self) -> Iterator[bytes]:
        yield from encode_name(self.name)
        yield self._struct_.pack(self._type_.value, self._class_.value)

    @classmethod
    def decode(cls, buffer: bytes, *, offset: int) -> tuple[Self, int]:
        name, offset = decode_name(buffer, offset)
        (typ, clas), offset = unpack_from(cls._struct_, buffer, offset)
        self = cls(name, DnsType(typ), DnsClass(clas))
        return self, offset


@dataclass(slots=True)
class Record:
    name: str
    ttl: int

    _struct_ = Struct("!HHIH")

    @staticmethod
    def decode(buffer: bytes, *, offset: int) -> tuple["Record", int]:
        name, offset = decode_name(buffer, offset)
        (typ, clas, ttl, data_len), offset = unpack_from(
            Record._struct_, buffer, offset
        )
        end = offset + data_len

        if clas == DnsClass.IN.value:
            if typ == DnsType.A.value and data_len == 4:
                addr = socket.inet_ntop(socket.AF_INET, buffer[offset:end])
                return RecordInetA(name, ttl, addr), end
            if typ == DnsType.AAAA.value and data_len == 16:
                addr = socket.inet_ntop(socket.AF_INET6, buffer[offset:end])
                return RecordInetAAAA(name, ttl, addr), end
            if typ == DnsType.CNAME.value:
                target, _ = decode_name(buffer, offset)
                return RecordInetCNAME(name, ttl, target), end
            if typ == DnsType.PTR.value:
                target, _ = decode_name(buffer, offset)
                return RecordInetPTR(name, ttl, target), end
            if typ == DnsType.SOA.value:
                fields, _ = RecordInetSOA.decode_fields(buffer, offset)
                return RecordInetSOA(name, ttl, *fields), end
            if typ == DnsType.SRV.value:
                fields, _ = RecordInetSRV.decode_fields(buffer, offset)
                return RecordInetSRV(name, ttl, *fields), end
            if typ == DnsType.TXT.value:
                strings = RecordInetTXT.decode_strings(buffer, offset, end)
                return RecordInetTXT(name, ttl, strings), end
            if typ == DnsType.MX.value:
                fields, _ = RecordInetMX.decode_fields(buffer, offset)
                return RecordInetMX(name, ttl, *fields), end

        self = RecordOther(name, ttl, DnsType(typ), DnsClass(clas), buffer[offset:end])
        return self, end


@dataclass(slots=True)
class RecordOther(Record):
    _type_: DnsType
    _class_: DnsClass
    data: bytes


@dataclass(slots=True)
class RecordInetA(Record):
    address: str


@dataclass(slots=True)
class RecordInetAAAA(Record):
    address: str


@dataclass(slots=True)
class RecordInetCNAME(Record):
    target: str


@dataclass(slots=True)
class RecordInetTXT(Record):
    text: list[str]

    @staticmethod
    def decode_strings(buffer: bytes, offset: int, end: int) -> list[str]:
        result = []
        while offset < end:
            start = offset + 1
            offset = start + buffer[offset]
            result.append(buffer[start:offset].decode("ascii"))

        return result


@dataclass(slots=True)
class RecordInetPTR(Record):
    target: str


@dataclass(slots=True)
class RecordInetSRV(Record):
    priority: int
    weight: int
    port: int
    target: str

    _struct_ = Struct("!HHH")

    @classmethod
    def decode_fields(cls, buffer: bytes, offset: int) -> tuple[list[str | Any], int]:
        fields, offset = unpack_from(cls._struct_, buffer, offset)
        target, offset = decode_name(buffer, offset)
        return [*fields, target], offset


@dataclass(slots=True)
class RecordInetMX(Record):
    exchange: str
    preference: int

    _struct_ = Struct("!H")

    @classmethod
    def decode_fields(cls, buffer: bytes, offset: int) -> tuple[tuple, int]:
        fields, offset = unpack_from(cls._struct_, buffer, offset)
        exchange, offset = decode_name(buffer, offset)
        return (exchange, *fields), offset


@dataclass(slots=True)
class RecordInetSOA(Record):
    master_name: str
    responsible_name: str
    serial_num: int
    refresh_num: int
    retry_num: int
    expire_num: int
    minimum_num: int

    _struct_ = Struct("!IIIII")

    @classmethod
    def decode_fields(cls, buffer: bytes, offset: int) -> tuple[tuple, int]:
        mname, offset = decode_name(buffer, offset)
        rname, offset = decode_name(buffer, offset)
        fields, offset = unpack_from(cls._struct_, buffer, offset)
        return (mname, rname, *fields), offset


RECURSION_DESIRED = 1 << 8


@dataclass(slots=True)
class Header:
    id: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    _struct_ = Struct("!HHHHHH")

    def encode(self) -> bytes:
        return b"".join(self._encode())

    def _encode(self) -> Iterator[bytes]:
        assert len(self.questions) == 1, "only one question supported by DNS"
        assert not self.answers
        assert not self.authorities
        assert not self.additionals

        yield self._struct_.pack(
            self.id,
            self.flags,
            len(self.questions),
            0,
            0,
            0,
        )

        for qn in self.questions:
            yield from qn.encode()

    @classmethod
    def decode(cls, buffer: bytes, offset: int) -> tuple[Self, int]:
        (
            id,
            flags,
            num_qns,
            num_ans,
            num_auth,
            num_extra,
        ), offset = unpack_from(cls._struct_, buffer, offset)

        self = cls(id, flags)
        for _ in range(num_qns):
            qn, offset = Question.decode(buffer, offset=offset)
            self.questions.append(qn)

        for _ in range(num_ans):
            ans, offset = Record.decode(buffer, offset=offset)
            self.answers.append(ans)

        for _ in range(num_auth):
            ans, offset = Record.decode(buffer, offset=offset)
            self.authorities.append(ans)

        for _ in range(num_extra):
            ans, offset = Record.decode(buffer, offset=offset)
            self.additionals.append(ans)

        return self, offset


def make_question(
    name: str,
    qtype: str = "A",
    *,
    id: int | None = None,
    flags: int = RECURSION_DESIRED,
) -> Header:
    if id is None:
        id = randrange(65536)
    qn = Question(
        name,
        _type_=getattr(DnsType, qtype),
    )
    return Header(id=id, flags=flags, questions=[qn])


def decode_response(buffer: bytes) -> Header:
    result, offset = Header.decode(buffer, 0)
    if offset != len(buffer):
        print("extra bytes after packet")

    return result


if __name__ == "__main__":
    qn = make_question("google.com", "A")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 53))
        sock.send(qn.encode())

        res = sock.recv(1024)

    for ans in decode_response(res).answers:
        print(ans)
