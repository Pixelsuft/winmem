from .imports import *


def get_memory(pid=None, process_name=None, hwnd=None, **kwargs):
    if pid:
        return Memory(pid)
    if process_name:
        process_name = process_name.lower().strip()
        if not process_name.endswith('.exe'):
            process_name += '.exe'
        for proc in psutil.process_iter():
            if process_name == proc.name().lower().strip():
                return Memory(proc.pid)
        raise ProcessNotFound('Process not found')
    if hwnd:
        return Memory(win32process.GetWindowThreadProcessId(hwnd)[1])
    raise NoArgsSend('No PID, Process name and Window handle')
