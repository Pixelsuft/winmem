import winmem
import time


memory = winmem.get_memory(
    process_name='geometrydash'
)


for i in dir(memory):
    if i.startswith('__') and i.endswith('__'):
        continue
    val = eval('memory.' + i)
    if type(val) == int:
        val = f'{val} {hex(val)}'
    print(i, val)  # Show all values and functions in "Memory" class

print('cocos base address', hex(memory.get_base_address('libcocos2D.dll')))  # Find base address of libcocos2d.dll
'''
memory.inject_dll(r"D:\Program Files\Geometry Dash\adaf-dll1\GDLocalisation.dll")  # Inject dll
'''
print('is_dead boolean address', memory.resolve_layers(0x3222D0, 0x164, 0x39C))  # Get address by pointer
print('uint32 value', memory.read_uint32(memory.base_address + 0x2CDF44))  # Read uint32 value
memory.write_bool(True, 0x3222D0, 0x164, 0x39C)  # Write bool by pointer addresses

print('nickname string', memory.read_string(memory.get_pointer_address(0x3222D8, 0x108)))  # Read string
memory.write_string('Pixelsufted', memory.get_pointer_address(0x3222D8, 0x108))  # Write string

address = memory.find_bytes(
    tuple('Attempt %i'.encode()), from_value=memory.base_address, to_value=memory.base_address + 500, first_only=True
)  # Find bytes in memory

if address:
    memory.write_process_memory(address, b' ' * len('Attempt %i'))  # Write empty bytes to memory

# Get all windows names
for i in memory.get_all_windows(pid_type=2):
    print('Windows name', winmem.win32gui.GetWindowText(i))

# time.sleep(5)  # Sleep 5 seconds
# memory.terminate(1337)  # Terminate app with exit code 1337
