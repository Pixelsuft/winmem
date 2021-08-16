from .imports import *


psapi = ctypes.windll.psapi


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', ctypes.c_uint),
                ('cntUsage', ctypes.c_uint),
                ('th32ProcessID', ctypes.c_uint),
                ('th32DefaultHeapID', ctypes.c_uint),
                ('th32ModuleID', ctypes.c_uint),
                ('cntThreads', ctypes.c_uint),
                ('th32ParentProcessID', ctypes.c_uint),
                ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', ctypes.c_uint),
                ('szExeFile', ctypes.c_char * 260),
                ('th32MemoryBase', ctypes.c_long),
                ('th32AccessKey', ctypes.c_long)]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', ctypes.c_long),
                ('th32ModuleID', ctypes.c_long),
                ('th32ProcessID', ctypes.c_long),
                ('GlblcntUsage', ctypes.c_long),
                ('ProccntUsage', ctypes.c_long),
                ('modBaseAddr', ctypes.c_long),
                ('modBaseSize', ctypes.c_long),
                ('hModule', ctypes.c_void_p),
                ('szModule', ctypes.c_char * 256),
                ('szExePath', ctypes.c_char * 260)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.c_long),
        ('cntUsage', ctypes.c_long),
        ('th32ThreadID', ctypes.c_long),
        ('th32OwnerProcessID', ctypes.c_long),
        ('tpBasePri', ctypes.c_long),
        ('tpDeltaPri', ctypes.c_long),
        ('dwFlags', ctypes.c_long)]


class MODULEINFO(ctypes.Structure):
    """Contains the module load address, size, and entry point.
    attributes:
      lpBaseOfDll
      SizeOfImage
      EntryPoint
    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684229(v=vs.85).aspx
    """

    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_ulong),
        ("EntryPoint", ctypes.c_void_p),
    ]

    def __init__(self, handle):
        self.process_handle = handle

    @property
    def name(self):
        modname = ctypes.c_buffer(wintypes.MAX_PATH)
        psapi.GetModuleBaseNameA(
            self.process_handle,
            ctypes.c_void_p(self.lpBaseOfDll),
            modname,
            ctypes.sizeof(modname)
        )
        return modname.value.decode(locale.getpreferredencoding())

    @property
    def filename(self):
        _filename = ctypes.c_buffer(wintypes.MAX_PATH)
        psapi.GetModuleFileNameExA(
            self.process_handle,
            ctypes.c_void_p(self.lpBaseOfDll),
            _filename,
            ctypes.sizeof(_filename)
        )
        return _filename.value.decode(locale.getpreferredencoding())