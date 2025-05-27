import pybind11
import os
from setuptools import setup, Extension, find_packages

NPCAP_INCLUDE_PATH = "C:\\Program Files\\Npcap\\Include"
NPCAP_LIBRARY_PATH = "C:\\Program Files\\Npcap\\Lib\\x64"

if not os.path.isdir(NPCAP_INCLUDE_PATH):
    raise RuntimeError(f"Npcap Include directory not found.{NPCAP_INCLUDE_PATH}")
if not os.path.isdir(NPCAP_LIBRARY_PATH):
    raise RuntimeError(f"Npcap Library directory not found.{NPCAP_LIBRARY_PATH}")

cpp_sources = [
    'wrapper\\npcap_wrapper.cpp',
    'wrapper\\bindings.cpp'
]
ext_modules = [
    Extension(
        'npcap_module', #name of the .pyd
        sources=cpp_sources,
        include_dirs=[
            pybind11.get_include(),
            NPCAP_INCLUDE_PATH,
            'wrapper'  #include "npcap_wrapper.h"
        ],
        library_dirs=[NPCAP_LIBRARY_PATH],
        libraries=['Packet', 'wpcap', 'ws2_32'],  # Libraries to link against
        language='c++',
        extra_compile_args=['/EHsc'] if os.name == 'nt' else ['-std=c++11'],
    ),
]
setup(
    name='Network_Monitor',
    version='0.1',
    author='flarescenn',
    description='Python Network Monitoring tool with Npcap wrapper',
    packages=find_packages(where='src'), 
    package_dir={'': 'src'}, 
    ext_modules=ext_modules,
    python_requires='>=3.7',
    install_requires=[
        
    ],
    classifiers=[ 
        'Programming Language :: Python :: 3',
        'Programming Language :: C++',
        'Operating System :: Microsoft :: Windows',
    ],
)
