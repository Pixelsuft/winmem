import struct

from .imports import *


T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")


def make_repr(some_object: T, info: dict = None, delim: str = " ",) -> str:
    """Create a nice representation of an object.
    Parameters
    ----------
    some_object: ``T``
        Object to create ``repr()`` of.
    info: Optional[Dict[``K``, ``V``]]
        Additional information to add. If ``None`` or not given, no info is attached.
    delim: :class:`str`
        Delimiter to split parts of ``info`` with.
    Returns
    -------
    :class:`str`
        ``repr()`` of ``some_object``.
    """
    name = some_object.__class__.__name__

    if not info:
        return f"<{name}>"

    formatted_info = delim.join(f"{key}={value}" for key, value in info.items())

    return f"<{name} {formatted_info}>"


EMPTY_BYTES = bytes(0)
ENCODING = "utf-8"
NULL_BYTE = bytes(1)

T = TypeVar("T")


def read_until_terminator(data: bytes, terminator: int = 0) -> bytes:
    return bytes(itertools.takewhile(lambda char: char != terminator, data))


class ByteOrder(Enum):
    NATIVE = "="
    LITTLE_ENDIAN = "<"
    BIG_ENDIAN = ">"


class Data(Generic[T]):
    def __init__(self, name: str, format: str) -> None:
        self._name = name
        self._format = format
        self._size = struct.calcsize(format)

        cls = self.__class__

        if not hasattr(cls, name):
            setattr(cls, name, self)

    def __repr__(self) -> str:
        info = {"name": repr(self.name), "size": self.size}
        return make_repr(self, info)

    def __str__(self) -> str:
        return self.name

    def create_format(self, order: Union[str, ByteOrder] = ByteOrder.NATIVE) -> str:
        return ByteOrder.from_value(order).value + self.format

    def from_bytes(self, data: bytes, order: Union[str, ByteOrder] = ByteOrder.NATIVE) -> T:
        try:
            unpacked = struct.unpack(self.create_format(order), data)

        except struct.error as error1:
            raise ValueError(f"Can not convert data to {self.name}. Error: {error1}.")

        if len(unpacked) == 1:
            return cast(T, unpacked[0])

        return cast(T, unpacked)

    def to_bytes(self, value: T, order: Union[str, ByteOrder] = ByteOrder.NATIVE) -> bytes:
        try:
            return struct.pack(self.create_format(order), value)

        except struct.error as error1:
            raise ValueError(f"Can not convert {self.name} to data. Error: {error1}.")

    @property
    def name(self) -> str:
        return self._name

    @property
    def format(self) -> str:
        return self._format

    @property
    def size(self) -> int:
        return self._size

    @property
    def bytes(self) -> int:
        return self._size

    @property
    def bits(self):
        return bytes_to_bits(self._size)


class String(Data[str]):
    def __init__(self) -> None:
        super().__init__("string", "")

    def from_bytes(self=None, data: bytes = None, encoding: str = "utf-8", errors: str = "strict") -> str:
        return read_until_terminator(data).decode(encoding, errors)

    def to_bytes(
        self=None, value: str = '', terminate: bool = True
    ) -> bytes:

        data = value.encode()

        if terminate:
            data += NULL_BYTE

        return data


def get_int_type(bits: int, signed: bool = False) -> Data[int]:
    if signed:
        choose_from = _all_int

    else:
        choose_from = _all_uint

    for pointer_type in choose_from:
        if pointer_type.bits == bits:
            return pointer_type

    raise ValueError("Can not find type that matches given bits.")


get_pointer_type = get_int_type
get_size_type = get_int_type


def bytes_to_bits(count: int) -> int:
    return count << 3


def bits_to_bytes(count: int) -> int:
    return count >> 3


SIZE = ctypes.sizeof(ctypes.c_void_p)
SIZE_BITS = bytes_to_bits(SIZE)

_byte: Data[int] = Data("byte", "b")
_ubyte: Data[int] = Data("ubyte", "B")

_short: Data[int] = Data("short", "h")
_ushort: Data[int] = Data("ushort", "H")

_int: Data[int] = Data("int", "i")
_uint: Data[int] = Data("uint", "I")

_long: Data[int] = Data("long", "l")
_ulong: Data[int] = Data("ulong", "L")

_longlong: Data[int] = Data("longlong", "q")
_ulonglong: Data[int] = Data("ulonglong", "Q")

_int_size_to_format = {
    _int_type.size: _int_type.format for _int_type in (_byte, _short, _int, _long, _longlong)
}

_uint_size_to_format = {
    _uint_type.size: _uint_type.format
    for _uint_type in (_ubyte, _ushort, _uint, _ulong, _ulonglong)
}

boolean: Data[bool] = Data("bool", "?")

char: Data[bytes] = Data("char", "c")

try:
    int8: Data[int] = Data("int8", _int_size_to_format[bits_to_bytes(8)])
    uint8: Data[int] = Data("uint8", _uint_size_to_format[bits_to_bytes(8)])

    int16: Data[int] = Data("int16", _int_size_to_format[bits_to_bytes(16)])
    uint16: Data[int] = Data("uint16", _uint_size_to_format[bits_to_bytes(16)])

    int32: Data[int] = Data("int32", _int_size_to_format[bits_to_bytes(32)])
    uint32: Data[int] = Data("uint32", _uint_size_to_format[bits_to_bytes(32)])

    int64: Data[int] = Data("int64", _int_size_to_format[bits_to_bytes(64)])
    uint64: Data[int] = Data("uint64", _uint_size_to_format[bits_to_bytes(64)])

except KeyError as error:
    raise OSError(f"Can not find integer type of size {error}.")

_all_int = (int8, int16, int32, int64)
_all_uint = (uint8, uint16, uint32, uint64)

int_size: Data[int] = get_size_type(SIZE_BITS, signed=True)
uint_size: Data[int] = get_size_type(SIZE_BITS, signed=False)

float32: Data[float] = Data("float32", "f")
float64: Data[float] = Data("float64", "d")

string: Data[str] = String()

_bytes_from_hex = bytes.fromhex
_bytes_to_hex_std = bytes.hex


def _bytes_to_hex(data: bytes, step: int = 1) -> str:
    return " ".join(
        _bytes_to_hex_std(data[index : index + step]) for index in range(0, len(data), step)
    )


class BufferMeta(type):
    def __getitem__(cls, item: Union[int, Sequence[int]]) -> "Buffer":
        if isinstance(item, Sequence):
            return cls.from_byte_array(item)

        return cls.from_byte_array([item])

    def from_byte_array(cls, array: Sequence[int]) -> "Buffer":
        raise NotImplementedError("This function is implemented in the actual class.")


class Buffer(metaclass=BufferMeta):
    def __init__(self, data: bytes = EMPTY_BYTES) -> None:
        self._data = data

    def __str__(self) -> str:
        return self.to_hex().upper()

    def __repr__(self) -> str:
        info = {"data": repr(self.to_hex().upper())}
        return make_repr(self, info)

    @classmethod
    def from_value(
        cls, type: Data[T], value: T, byte_order: Union[str, ByteOrder] = ByteOrder.NATIVE
    ) -> "Buffer":
        return cls(type.to_bytes(value, byte_order))

    def to_value(self, type: Data[T], byte_order: Union[str, ByteOrder] = ByteOrder.NATIVE) -> T:
        return type.from_bytes(self._data, byte_order)

    @classmethod
    def from_byte_array(cls, array: Sequence[int]) -> "Buffer":
        return cls(bytes(array))

    def to_byte_array(self) -> Sequence[int]:
        return list(self._data)

    @classmethod
    def from_hex(cls, hex_string: str) -> "Buffer":
        return cls(_bytes_from_hex(hex_string))

    def to_hex(self, step: int = 1) -> str:
        return _bytes_to_hex(self._data, step)

    def into_buffer(self) -> Any:
        return ctypes.create_string_buffer(self._data, len(self._data))

    def unwrap(self) -> bytes:
        return self._data


def list_from(one_or_seq: Union[T, Iterable[T]]) -> List[T]:
    try:
        return list(one_or_seq)
    except Exception:
        return [one_or_seq]


def cache_by(*names: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Cache ``function`` result by object's attributes given by ``names``."""

    if not names:
        raise ValueError("@cache_by requires at least one name to be provided.")

    def decorator(function: Callable[..., T]) -> Callable[..., T]:
        get_attrs = tuple(attrgetter(name) for name in names)

        name = function.__name__

        if not name.isidentifier():
            name = f"unnamed_{id(function):x}"

        cached_attr = f"_{name}_cached"
        cached_by_attr = f"_{name}_cached_by"

        @functools.wraps(function)
        def wrapper(self, *args, **kwargs) -> T:
            actual = tuple(get_attr(self) for get_attr in get_attrs)

            try:
                cached = getattr(self, cached_attr)
                cached_by = getattr(self, cached_by_attr)

            except AttributeError:
                pass

            else:
                if actual == cached_by:
                    return cached

            result = function(self, *args, **kwargs)

            setattr(self, cached_attr, result)
            setattr(self, cached_by_attr, actual)

            return result

        return wrapper

    return decorator

