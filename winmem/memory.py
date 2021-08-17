from .imports import *
from .kernel_utils import _virtual_alloc, _virtual_protect, _kernel32_name, _get_module_proc_address,\
    _read_process_memory, _write_process_memory, _is_wow_64_process, _kernel32_symbols, _load_library_name, \
    _create_remote_thread, _wait_for_single_object, get_process_bits_from_handle, _virtual_free


kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi


class Memory:
    def __init__(self, pid: int, ptr_type: Type = uint32, *args):
        """Init Memory()"""
        super().__init__(*args)
        self.pid = pid
        self.process_handle = self.init_handle()
        self.kernel_process_handle = kernel32.OpenProcess(0x1F0FFF, False, self.pid)
        self.psutil_process = psutil.Process(self.pid)
        self.process_name = self.psutil_process.name()
        self.base_address = self.get_base_address()
        self.modules = self.get_modules()
        self.full_modules = self.get_full_modules()
        self.env = self.psutil_process.environ()
        self.cmd_line = self.psutil_process.cmdline()
        self.path = self.psutil_process.cwd()
        self.temp_module_bases = {}
        self.ptr_type = ptr_type
        self.bits = get_process_bits_from_handle(self.kernel_process_handle)
        self.pointer_type = get_pointer_type(self.bits)
        self.size_type = get_size_type(self.bits)

    def init_handle(self, open_args=0x1F0FFF):
        """Open process"""
        return win32api.OpenProcess(open_args, False, self.pid)

    def get_modules(self):
        """Get modules attached to this process"""
        modules = []
        for i in self.psutil_process.memory_maps():
            modules.append(os.path.basename(i.path))
        return tuple(modules)

    def get_full_modules(self):
        """Get full paths of modules attached to this process"""
        modules = []
        for i in self.psutil_process.memory_maps():
            modules.append(i.path)
        return tuple(modules)

    def refresh_modules(self):
        """Refresh modules"""
        self.modules = self.get_modules()
        self.full_modules = self.get_full_modules()

    def get_modules_ctypes(self):
        """Get all modules using ctypes. Returns an MODULEINFO class"""
        modules = (ctypes.c_void_p * 1024)()
        process_module_success = psapi.EnumProcessModulesEx(
            self.kernel_process_handle,
            ctypes.byref(modules),
            ctypes.sizeof(modules),
            ctypes.byref(ctypes.c_ulong()),
            0x03
        )
        if not process_module_success:
            raise ProcessError('Something wrong...')
        all_modules = []
        for module in iter(m for m in modules if m):
            module_info = MODULEINFO(self.kernel_process_handle)
            psapi.GetModuleInformation(
                self.kernel_process_handle,
                ctypes.c_void_p(module),
                ctypes.byref(module_info),
                ctypes.sizeof(module_info)
            )
            all_modules.append(module_info)
        return tuple(all_modules)

    def get_module_base(self, module: str, use_lowered: bool = True):
        """Get base address of module"""
        if use_lowered:
            for i in self.get_modules_ctypes():
                if module.lower() == i.name.lower():
                    return i.lpBaseOfDll
        else:
            for i in self.get_modules_ctypes():
                if module == i.name:
                    return i.lpBaseOfDll
        raise ModuleNotFound(f'Module {module} was not found')

    def get_base_address(self, module=None):
        """Get base address"""
        if module:
            module = module.lower()
            if module in self.temp_module_bases:
                return self.temp_module_bases[module]
            else:
                new_base = self.get_module_base(module)
                self.temp_module_bases[module] = new_base
                return self.get_module_base(module)
        else:
            return win32process.EnumProcessModules(self.process_handle)[0]

    def terminate(self, exit_code: int = 0):
        """Kill the process"""
        win32process.TerminateProcess(self.process_handle, exit_code)
        win32api.CloseHandle(self.process_handle)

    def allocate_memory(self, address: int, size: int, flags=READ | WRITE | EXECUTE):
        """Allocate memory"""
        return _virtual_alloc(
            self.kernel_process_handle, address, size, MEM_RESERVE | MEM_COMMIT, PROTECTION_FLAGS[flags]
        )

    def free_memory(self, address: int, size: int) -> None:
        """Free memory"""
        return _virtual_free(self.kernel_process_handle, address, size, MEM_RELEASE)

    def protect_process_memory(
            self, address: int, size: int, flags=READ | WRITE | EXECUTE,
    ):
        """Protect process memory"""
        old_protect = wintypes.DWORD(0)
        _virtual_protect(
            self.kernel_process_handle, address, size, PROTECTION_FLAGS[flags], ctypes.byref(old_protect)
        )
        return old_protect.value

    def read_process_memory(self, address: int, size: int) -> bytes:
        """Read process memory"""
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        _read_process_memory(self.kernel_process_handle, address, buffer, size, ctypes.byref(bytes_read))
        return buffer.raw

    def write_process_memory(self, address: int, data) -> int:
        """Write process memory"""
        size = len(data)
        buffer = ctypes.create_string_buffer(data, size)
        bytes_written = ctypes.c_size_t(0)
        _write_process_memory(self.kernel_process_handle, address, buffer, size, ctypes.byref(bytes_written))
        return bytes_written.value

    def _inject_dll(self, path: str):
        """Full function for injecting dlls"""
        if not os.access(path, os.F_OK):
            raise FileNotFoundError(f"Given DLL path does not exist: {path}.")

        path_bytes = str(path).encode(ENCODING)
        path_size = len(path_bytes) + 1
        parameter_address = self.allocate_memory(0, path_size)
        self.write_process_memory(parameter_address, path_bytes)

        if _is_wow_64_process(self.kernel_process_handle):
            module_base = self.get_module_base(_kernel32_name)
            load_library_offset = _kernel32_symbols.get(_load_library_name, 0)
            if not load_library_offset:
                raise LookupError(f"Can not find {_load_library_name} in WoW64 kernel32.dll module.")
            load_library = module_base + load_library_offset
        else:
            load_library = _get_module_proc_address("kernel32.dll", "LoadLibraryA")
        thread_id = wintypes.DWORD(0)
        thread_handle = _create_remote_thread(
            self.kernel_process_handle, None, 0, load_library, parameter_address, 0, ctypes.byref(thread_id)
        )
        _wait_for_single_object(thread_handle, INFINITE)
        self.free_memory(parameter_address, path_size)
        return thread_id.value

    def inject_dll(self, path: str):
        """Inject dll into process"""
        return bool(self._inject_dll(path))

    def read_at(self, size: int = 0, address: int = 0) -> Buffer:
        """Read ``size`` bytes at ``address``, returning :class:`.Buffer` object."""
        return Buffer(self.read_process_memory(address, size))

    def read(self, type: Data[T], address: int) -> T:
        """Read type"""
        return type.from_bytes(self.read_process_memory(address, type.size))

    def write_at(self, address: int, data: bytes) -> int:
        """Write at address"""
        return self.write_process_memory(address, data)

    def write(self, type: Data[T], value: T, address: int) -> int:
        """Write type"""
        return self.write_at(address, type.to_bytes(value))

    def resolve_layers(self, *offsets: Sequence[int], module: Optional[str] = None) -> int:
        """Get address by address or pointers"""
        offsets: List[int] = list_from(offsets)
        if module:
            address = self.get_base_address(module)
        else:
            address = self.base_address
        if offsets:
            address += offsets.pop(0)
        for offset in offsets:
            address = self.read(self.ptr_type, address) + offset
        return address

    get_pointer_address = resolve_layers

    def read_pointer(self, address: int) -> int:
        """Read pointer"""
        return self.read(self.pointer_type, address)

    def write_pointer(self, value: int, address: int) -> int:
        """Write pointer"""
        return self.write(self.pointer_type, value, address)

    def read_size(self, address: int) -> int:
        """Read size"""
        return self.read(self.size_type, address)

    def write_size(self, value: int, address: int) -> int:
        """Write size"""
        return self.write(self.size_type, value, address)

    def read_bytes(self, size: int = 0, *offsets, module: Optional[str] = None) -> Buffer:
        """Read ``size`` bytes, resolving ``*offsets`` to the final address."""
        return Buffer(self.read_process_memory(self.resolve_layers(*offsets, module=module), size))

    def read_type(self, type: Data[T], *offsets, module: Optional[str] = None) -> T:
        """Read ``type``, resolving ``*offsets`` to the final address."""
        return type.from_bytes(self.read_process_memory(self.resolve_layers(*offsets, module=module), type.size))

    def write_bytes(self, buffer: Buffer, *offsets, module: Optional[str] = None):
        """Write ``buffer``, resolving ``*offsets`` to the final address."""
        bytes_written = ctypes.c_size_t(0)
        data = buffer.into_buffer()
        _write_process_memory(
            self.kernel_process_handle, self.resolve_layers(*offsets, module=module),
            ctypes.byref(data), len(data), ctypes.byref(bytes_written)
        )
        return bytes_written.value

    def write_type(self, type: Data[T], value: T, *offsets, module: Optional[str] = None) -> T:
        """Read ``type``, resolving ``*offsets`` to the final address."""
        return self.write_bytes(Buffer(type.to_bytes(value)), *offsets, module=module)

    def read_bool(self, *offsets, module: Optional[str] = None) -> bool:
        """Read bool"""
        return self.read_type(boolean, *offsets, module=module)

    def write_bool(self, value: bool, *offsets, module: Optional[str] = None):
        """Read bool"""
        return self.write_type(boolean, value, *offsets, module=module)

    def read_buffer(self, size: int, address: int) -> Buffer:
        """Read buffer"""
        return self.read_at(address, size)

    def write_buffer(self, buffer: Buffer, address: int) -> int:
        """Write buffer"""
        return self.write_at(address, buffer.unwrap())

    def read_int8(self, address: int) -> int:
        """Read int8"""
        return self.read(int8, address)

    def write_int8(self, value: int, address: int) -> int:
        """Write int8"""
        return self.write(int8, value, address)

    def read_uint8(self, address: int) -> int:
        """Read uint8"""
        return self.read(uint8, address)

    def write_uint8(self, value: int, address: int) -> int:
        """Write uint8"""
        return self.write(uint8, value, address)

    def read_int16(self, address: int) -> int:
        """Read int16"""
        return self.read(int16, address)

    def write_int16(self, value: int, address: int) -> int:
        """Write int16"""
        return self.write(int16, value, address)

    def read_uint16(self, address: int) -> int:
        """Read uint16"""
        return self.read(uint16, address)

    def write_uint16(self, value: int, address: int) -> int:
        """Write uint16"""
        return self.write(uint16, value, address)

    def read_int32(self, address: int) -> int:
        """Read int32"""
        return self.read(int32, address)

    def write_int32(self, value: int, address: int) -> int:
        """Write int32"""
        return self.write(int32, value, address)

    def read_uint32(self, address: int) -> int:
        """Read uint32"""
        return self.read(uint32, address)

    def write_uint32(self, value: int, address: int) -> int:
        """Write uint32"""
        return self.write(uint32, value, address)

    def read_int64(self, address: int) -> int:
        """Read int64"""
        return self.read(int64, address)

    def write_int64(self, value: int, address: int) -> int:
        """Write int64"""
        return self.write(int64, value, address)

    def read_uint64(self, address: int) -> int:
        """Read uint64"""
        return self.read(uint64, address)

    def write_uint64(self, value: int, address: int) -> int:
        """Write uint64"""
        return self.write(uint64, value, address)

    @property
    @cache_by("bits")
    def byte_type(self) -> Data[int]:
        return int8

    @property
    @cache_by("bits")
    def ubyte_type(self) -> Data[int]:
        return uint8

    @property
    @cache_by("bits")
    def short_type(self) -> Data[int]:
        return int16

    @property
    @cache_by("bits")
    def ushort_type(self) -> Data[int]:
        return uint16

    @property
    @cache_by("bits")
    def int_type(self) -> Data[int]:
        if self.bits >= 32:
            return int32

        return int16

    @property
    @cache_by("bits")
    def uint_type(self) -> Data[int]:
        if self.bits >= 32:
            return uint32

        return uint16

    @property
    @cache_by("bits")
    def long_type(self) -> Data[int]:
        if self.bits >= 64:
            return int64

        return int32

    @property
    @cache_by("bits")
    def ulong_type(self) -> Data[int]:
        if self.bits >= 64:
            return uint64

        return uint32

    @property
    @cache_by("bits")
    def longlong_type(self) -> Data[int]:
        return int64

    @property
    @cache_by("bits")
    def ulonglong_type(self) -> Data[int]:
        return uint64

    def read_byte(self, address: int) -> int:
        """Read byte"""
        return self.read(self.byte_type, address)

    def write_byte(self, value: int, address: int) -> int:
        """Write byte"""
        return self.write(self.byte_type, value, address)

    def read_ubyte(self, address: int) -> int:
        """Read ubyte"""
        return self.read(self.ubyte_type, address)

    def write_ubyte(self, value: int, address: int) -> int:
        """Write ubyte"""
        return self.write(self.ubyte_type, value, address)

    def read_short(self, address: int) -> int:
        """Read short"""
        return self.read(self.short_type, address)

    def write_short(self, value: int, address: int) -> int:
        """Write short"""
        return self.write(self.short_type, value, address)

    def read_ushort(self, address: int) -> int:
        """Read ushort"""
        return self.read(self.ushort_type, address)

    def write_ushort(self, value: int, address: int) -> int:
        """Write ushort"""
        return self.write(self.ushort_type, value, address)

    def read_int(self, address: int) -> int:
        """Read int"""
        return self.read(self.int_type, address)

    def write_int(self, value: int, address: int) -> int:
        """Write int"""
        return self.write(self.int_type, value, address)

    def read_uint(self, address: int) -> int:
        """Read uint"""
        return self.read(self.uint_type, address)

    def write_uint(self, value: int, address: int) -> int:
        """Write uint"""
        return self.write(self.uint_type, value, address)

    def read_long(self, address: int) -> int:
        """Read long"""
        return self.read(self.long_type, address)

    def write_long(self, value: int, address: int) -> int:
        """Write long"""
        return self.write(self.long_type, value, address)

    def read_ulong(self, address: int) -> int:
        """Read ulong"""
        return self.read(self.ulong_type, address)

    def write_ulong(self, value: int, address: int) -> int:
        """Write ulong"""
        return self.write(self.ulong_type, value, address)

    def read_longlong(self, address: int) -> int:
        """Read longlong"""
        return self.read(self.longlong_type, address)

    def write_longlong(self, value: int, address: int) -> int:
        """Write longlong"""
        return self.write(self.longlong_type, value, address)

    def read_ulonglong(self, address: int) -> int:
        """Read ulonglong"""
        return self.read(self.ulonglong_type, address)

    def write_ulonglong(self, value: int, address: int) -> int:
        """Write ulonglong"""
        return self.write(self.ulonglong_type, value, address)

    def read_float32(self, address: int) -> float:
        """Read float32"""
        return self.read(float32, address)

    read_float = read_float32
    read_float.__doc__ = """Read float"""

    def write_float32(self, value: float, address: int) -> int:
        """Write float32"""
        return self.write(float32, value, address)

    write_float = write_float32
    write_float.__doc__ = """Write float"""

    def read_float64(self, address: int) -> float:
        """Read float64"""
        return self.read(float64, address)

    read_double = read_float64
    read_double.__doc__ = """Read double"""

    def write_float64(self, value: float, address: int) -> int:
        """Write float64"""
        return self.write(float64, value, address)

    write_double = write_float64
    write_double.__doc__ = """Write double"""

    def read_string(self, address: int) -> str:
        """Read string"""
        size_address = address + 16
        size = self.read(self.ptr_type, size_address)
        if size < 16:
            try:
                return String.from_bytes(data=self.read_process_memory(address, size))
            except UnicodeDecodeError:
                pass
        address = self.read(self.ptr_type, address)
        return String.from_bytes(data=self.read_process_memory(address, size))

    def write_string(self, value: str, address: int, alloc_address: int = 0x00, terminate: bool = True):
        """Write string"""
        size_address = address + 16

        data = String.to_bytes(value=value, terminate=terminate)

        size = len(data)

        self.write(self.ptr_type, size, size_address)

        if size > 16:
            address = self.allocate_memory(alloc_address, size)

        self.write_at(address, data)
