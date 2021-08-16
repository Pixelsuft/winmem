import winmem
import time


memory = winmem.get_memory(
    process_name='geometrydash'
)


'''for i in dir(memory):
    if i.startswith('__') and i.endswith('__'):
        continue
    val = eval('memory.' + i)
    if type(val) == int:
        val = f'{val} {hex(val)}'
    print(i, val)'''  # Show all values and functions in "Memory" class

print(hex(memory.get_base_address('libcocos2D.dll')))
memory.inject_dll(r"D:\Program Files\Geometry Dash\adaf-dll1\GDLocalisation.dll")  # Inject dll
print(memory.read_uint32(memory.base_address + 0x2CDF44))  # Read uint32 value
memory.write_bool(True, 0x3222D0, 0x164, 0x39C)  # Write bool by pointer addresses
print(memory.resolve_layers(0x3222D0, 0x164, 0x39C))  # Get address by pointer


time.sleep(5)
memory.terminate(1337)
