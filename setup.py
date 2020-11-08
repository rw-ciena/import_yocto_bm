import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="import-yocto-bm-matthewb66",
    version="1.4",
    author="Matthew Brady",
    author_email="w3matt@gmail.com",
    description="Import Yocto build manifest to Black Duck - new version",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matthewb66/import_yocto_bm",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
