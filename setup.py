from setuptools import setup, find_packages

setup(
    name="keyreusefinder",               # The package name
    version="0.2",                   # Initial version
    packages=find_packages(),        # Automatically find packages in the directory
    install_requires=[
        "numpy>=2.2.3",
    ],
    description="Finds ciphertext pairs vulnerable to venona-like attacks due to key reuse.",
    author="Ben Herzog",
)
