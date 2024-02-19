from setuptools import setup

setup(
    name='scsctl',
    description= 'Tool for automating Vulnerability Risk Management and Software Supply Chain Security Measures',
    version='0.0.6.6',
    py_modules=['scsctl'],
    install_requires=['click==8.1.3', 'clickhouse-driver==0.2.6', 'numpy==1.25.0', 'requests==2.31.0','questionary==1.10.0','tabulate==0.9.0','hvac==1.2.1','fastapi==0.103.1','uvicorn==0.23.2','kubernetes==27.2.0','pydgraph==23.0.2'],
    entry_points={
        'console_scripts': [
            'scsctl = scsctl.app:cli'
        ]
    }
)