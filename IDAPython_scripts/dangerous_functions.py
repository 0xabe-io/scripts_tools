# A simple IDAPython script that tries to search all references to dangerous functions
from re import sub
from idautils import *
from idc import *

functions = {
        # what's wrong with you
        'gets': 'horrid',
        'strcat': 'horrid',
        'strcpy': 'horrid',
        'sprintf': 'horrid',

        # ends when the first \0 is reached
        'strlen': 'too_trusted',

        # usually based on size of an input
        'fgets': 'to_check',
        'snprintf': 'to_check',
        'strncpy': 'to_check',
        'strncat': 'to_check',
        'fscanf': 'to_check',
        'getopt': 'to_check',
        'getpass': 'to_check',
        'realpath': 'to_check',
        'scanf': 'to_check',
        'streadd': 'to_check',
        'strecpy': 'to_check',
        'strtrns': 'to_check',
        'vsprintf': 'to_check',
        }
# Really simple search, it won't get all the functions..
for funcea in Functions():
    name = sub('_', '', GetFunctionName(funcea))
    if name in functions:
        for ref in CodeRefsTo(funcea, 1):
            #asm = sub('\s+', ' ', GetDisasm(ref))
            #print('{},{},{},0x{:x},"{}"'.format(functions[name], name, GetFunctionName(ref), ref, asm))
            print('{},{},{},0x{:x}'.format(functions[name], name, GetFunctionName(ref), ref))
