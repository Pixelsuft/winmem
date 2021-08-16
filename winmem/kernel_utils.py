from .imports import *


kernel32 = ctypes.windll.kernel32
T = TypeVar("T")


class StructureMeta(type(ctypes.Structure)):
    def __new__(
        meta_cls, name: str, bases: tuple, namespace: dict
    ):
        cls = super().__new__(meta_cls, name, bases, namespace)

        fields = {}

        for base in reversed(cls.mro()):
            fields.update(get_type_hints(base))

        cls._fields_ = list(fields.items())

        return cls


class Structure(ctypes.Structure, metaclass=StructureMeta):
    """Structure that has ability to populate its fields with annotations."""

    pass


class SecurityAttributes(Structure):
    length: wintypes.DWORD
    security_descriptor: wintypes.LPVOID
    inherit_handle: wintypes.BOOL

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.length = ctypes.sizeof(self)


LPSECURITY_ATTRIBUTES = ctypes.POINTER(SecurityAttributes)


def extern_fn(function_pointer: Any) -> Callable[[Callable[..., T]],
                                                               Callable[..., T]]:
    def wrap(function: Callable[..., T]) -> Callable[..., T]:
        annotations = get_type_hints(function)

        return_type = annotations.pop("return", None)

        if return_type:
            function_pointer.restype = return_type

        argument_types = list(annotations.values())

        if argument_types:
            function_pointer.argtypes = argument_types

        @functools.wraps(function)
        def handle_call(*args) -> T:
            return function_pointer(*args)

        return handle_call

    return wrap


@extern_fn(kernel32.CloseHandle)
def _close_handle(handle: wintypes.HANDLE) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.OpenProcess)
def _open_process(
    access: wintypes.DWORD, inherit_handle: wintypes.BOOL, process_id: wintypes.DWORD
) -> wintypes.HANDLE:
    pass


@extern_fn(kernel32.ReadProcessMemory)
def _read_process_memory(
    handle: wintypes.HANDLE,
    base_address: wintypes.LPVOID,
    buffer: wintypes.LPCVOID,
    size: ctypes.c_size_t,
    size_ptr: ctypes.POINTER(ctypes.c_size_t),
) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.WriteProcessMemory)
def _write_process_memory(
    handle: wintypes.HANDLE,
    base_address: wintypes.LPVOID,
    buffer: wintypes.LPCVOID,
    size: ctypes.c_size_t,
    size_ptr: ctypes.POINTER(ctypes.c_size_t),
) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.VirtualAllocEx)
def _virtual_alloc(
    handle: wintypes.HANDLE,
    address: wintypes.LPVOID,
    size: ctypes.c_size_t,
    allocation_type: wintypes.DWORD,
    protect: wintypes.DWORD,
) -> wintypes.LPVOID:
    pass


@extern_fn(kernel32.VirtualFreeEx)
def _virtual_free(
    handle: wintypes.HANDLE,
    address: wintypes.LPVOID,
    size: ctypes.c_size_t,
    free_type: wintypes.DWORD,
) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.WaitForSingleObject)
def _wait_for_single_object(
    handle: wintypes.HANDLE, time_milliseconds: wintypes.DWORD
) -> wintypes.DWORD:
    pass


@extern_fn(kernel32.TerminateProcess)
def _terminate_process(handle: wintypes.HANDLE, exit_code: wintypes.UINT) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.IsWow64Process)
def _is_wow_64_process_via_ptr(handle: wintypes.HANDLE, bool_ptr: wintypes.PBOOL) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.GetSystemWow64DirectoryA)
def _get_system_wow_64_directory(
    string_buffer: wintypes.LPSTR, size: wintypes.UINT
) -> wintypes.UINT:
    pass


@extern_fn(kernel32.CreateRemoteThread)
def _create_remote_thread(
    handle: wintypes.HANDLE,
    thread_attributes: LPSECURITY_ATTRIBUTES,
    stack_size: ctypes.c_size_t,
    start_address: wintypes.LPVOID,
    start_parameter: wintypes.LPVOID,
    flags: wintypes.DWORD,
    thread_id: wintypes.LPDWORD,
) -> wintypes.HANDLE:
    pass


@extern_fn(kernel32.GetModuleHandleA)
def _get_module_handle(module_name: wintypes.LPCSTR) -> wintypes.HMODULE:
    pass


@extern_fn(kernel32.GetProcAddress)
def _get_proc_address(
    module_handle: wintypes.HMODULE, proc_name: wintypes.LPCSTR
) -> wintypes.LPVOID:
    pass


@extern_fn(kernel32.VirtualProtectEx)
def _virtual_protect(
    handle: wintypes.HANDLE,
    address: wintypes.LPVOID,
    size: ctypes.c_size_t,
    flags: wintypes.DWORD,
    old_protect: wintypes.PDWORD,
) -> wintypes.BOOL:
    pass


@extern_fn(kernel32.IsWow64Process)
def _is_wow_64_process_via_ptr(handle: wintypes.HANDLE, bool_ptr: wintypes.PBOOL) -> wintypes.BOOL:
    pass


def _is_wow_64_process(process_handle: wintypes.HANDLE) -> bool:
    result = wintypes.BOOL(0)
    _is_wow_64_process_via_ptr(process_handle, ctypes.byref(result))
    return bool(result.value)


def _get_system_wow_64_dir():
    size = _get_system_wow_64_directory(None, 0)
    if not size:
        return
    path_buffer = ctypes.create_string_buffer(size)
    _get_system_wow_64_directory(path_buffer, size)
    return str(path_buffer.value.decode(ENCODING))


def _get_module_symbols(module_path: str):
    pe = pefile.PE(module_path, fast_load=True)
    pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])

    return {
        symbol.name.decode("utf-8"): symbol.address for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols
    }


_kernel32_name = "kernel32.dll"
_load_library_name = "LoadLibraryA"

_system_wow_64_dir = _get_system_wow_64_dir()

if _system_wow_64_dir:
    _kernel32_symbols = _get_module_symbols(os.path.join(_system_wow_64_dir, _kernel32_name))
else:
    _kernel32_symbols = {}


def _get_module_proc_address(module_name: str, proc_name: str):
    handle = _get_module_handle(ctypes.c_char_p(module_name.encode()))
    address = _get_proc_address(handle, ctypes.c_char_p(proc_name.encode()))
    return address


def get_process_bits_from_handle(process_handle):
    if struct.calcsize("P") * 8 > 64:
        if _is_wow_64_process(process_handle):
            return 32
        return 64
    return 32
