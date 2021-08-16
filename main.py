from winmem import get_memory


memory = get_memory(
    process_name='geometrydash'
)


'''for i in dir(memory):
    if i.startswith('__') and i.endswith('__'):
        continue
    val = eval('memory.' + i)
    if type(val) == int:
        val = f'{val} {hex(val)}'
    print(i, val)'''

print(hex(memory.get_base_address('libcocos2D.dll')))
memory.inject_dll(r"D:\Program Files\Geometry Dash\adaf-dll1\GDLocalisation.dll")
print(memory.read_at(6, memory.base_address + 0x2CDF44))
print(type(memory.read_at(6, memory.base_address + 0x2CDF44)))
