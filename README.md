# Synopsys Import Yocto Build Manifest - import_yocto_bm.py
#OVERVIEW
This script is provided under an OSS license as an example of how to use the Black Duck APIs to import components from a manifest list.

It does not represent any extension of licensed functionality of Synopsys software itself and is provided as-is, without warranty or liability.

#DESCRIPTION

The `import_yocto_bm.py` script is designed to import a Yocto project build manifest created by Bitbake.

It must be executed on a Linux workstation where Yocto has been installed and after a successful Bitbake build.

If invoked in the Yocto top level folder for a build (or the folder is specified using the -y option), then it will locate the build-manifest file automatically in the build/tmp hierarchy.

If the build has been performed with the Yocto cve\_check class configured, then the script will also optionally locate the CVE list identified by cve\_check to set the remediation status of the locally patched CVEs in the Black Duck project.

It requires access to the Black Duck server via the API (see Prerequisites below) unless an option is used to create the output scan file for manual upload.

#PREREQUISITES

Python 3 and the Black Duck https://github.com/blackducksoftware/hub-rest-api-python package must be installed prior to using this script.

An API key for the Black Duck server must also be configured in the `.restconfig.json` file, and the Yocto environment must be loaded to the current shell (see [Preconfiguration](#PRECONFIGURATION) section below).

The Yocto project must have been pre-built.

For patched CVE remediation in the Black Duck project, you will need to add the `cve_check` bbclass to the Yocto build configuration to generate the CVE check log output. Add the following line to the `build/conf/local.conf` file:

		INHERIT += "cve-check"

Then use the Yocto build command (e.g. `bitbake core-image-sato` which will incrementally build without needing to rerun the full build, but will add the CVE check action to generate the log files.

#INSTALLATION

Change to a chosen location and use Git to download a copy of the project:

		git clone https://github.com/matthewb66/import_yocto_bm
		export YOCTO_BM_LOC=`pwd`/import_yocto_bm

# STANDARD USAGE

The `import_yocto_bm.py` usage is shown below:

		usage: import_yocto_bm [-h] [-p PROJECT] [-v VERSION] [-y YOCTO_FOLDER]
							   [-t TARGET] [-o OUTPUT_JSON] [-m MANIFEST]
							   [--arch ARCH] [--cve_check_only] [--no_cve_check]
							   [--cve_check_file CVE_CHECK_FILE]

		Import Yocto build manifest to BD project version

		optional arguments:
		  -h, --help            show this help message and exit
		  -p PROJECT, --project PROJECT
								Black Duck project to create (REQUIRED)
		  -v VERSION, --version VERSION
								Black Duck project version to create (REQUIRED)
		  -y YOCTO_FOLDER, --yocto_build_folder YOCTO_FOLDER
								Yocto build folder (required if CVE check required or
								manifest file not specified)
		  -o OUTPUT_JSON, --output_json OUTPUT_JSON
								Output JSON bom file for manual import to Black Duck
								(instead of uploading the scan automatically)
		  -t TARGET, --target TARGET
								Yocto target (default core-poky-sato)
		  -m MANIFEST, --manifest MANIFEST
								Input build manifest file (if not specified will be
								determined from conf files)
		  --arch ARCH           Architecture (if not specified then will be determined
								from conf files)
		  --cve_check_only      Only check for patched CVEs from cve_check and update
								existing project
		  --no_cve_check        Skip check for and update of patched CVEs
		  --cve_check_file CVE_CHECK_FILE
								CVE check output file (if not specified will be
								determined from conf files)

The script will use the invocation folder as the Yocto top-level folder by default (if there is a `poky` sub-folder then it will be used instead). The `--yocto_folder` option can be used to specify the Yocto top-level folder as opposed to the invocation folder.

The `--project` and `--version` options are required to define the Black Duck project and version names for inclusion in the json output file (and update CVE patch status).

The `--output_json` option can be used to specify an output file for the project scan. If specified, then the scan will not be uploaded automatically and CVE patch checking will be skipped.

The Yocto target name is required to locate the manifest and cve\_check log files and will be extracted from the Bitbake config files automatically, but the `--target` option can be used to specify manually.

The most recent Bitbake output manifest file (located in the `build/tmp/deploy/licenses/<image>-<target>-<datetime>/package.manifest` file) will be located automatically. Use the `--manifest` option to specify the manifest file manually.

The most recent cve\_check log file in the location  `build/tmp/deploy/images/<arch>/<image>-<target>-<datetime>.rootfs.cve` will be located automatically if it exists. Use the `--cve_check_file` option to specify the cve\_check log file manually.

Use the `--cve_check_only` option to skip the scanning of the project and creation of a project, only looking for a CVE check output log file to identify and patch CVEs within an existing Black Duck project.

Use the `--no_cve_check` option to skip the patched CVE identification and update of the Black Duck project. 

#PRECONFIGURATION

You will need to run the following commands (change the location as required):

    cd /home/users/myuser/yocto_zeus/poky
    source oe-init-build-env

This will change directory into the Yocto build sub-folder; you will need to create the `.restconfig.json` file in the current folder, for example:

		{
		  "baseurl": "https://SERVER_URL",
		  "api_token": "TOKEN",
		  "insecure": true,
		  "debug": false
		}

Where `SERVER_URL` is the Black Duck server URL and `TOKEN` is the Black Duck API token.

# EXAMPLE USAGE

Check the [Configuration](#PRECONFIGURATION) section above before running the script.

Use the following command to scan a Yocto build, create Black Duck project `myproject` and version `v1.0`, then update CVE patch status for identified CVEs:

    python3 $YOCTO_BM_LOC/import_yocto_bm.py -p myproject -v v1.0

To scan a Yocto project specifying a different build manifest as opposed to the most recent one:

    python3 $YOCTO_BM_LOC/import_yocto_bm.py -p myproject -v v1.0 -m tmp/deploy/licenses/core-image-sato-qemux86-64-20200728105751/package.manifest

To scan the most recent Yocto build in a different build folder location (not the current folder):

    python3 $YOCTO_BM_LOC/import_yocto_bm.py -p myproject -v v1.0 --y $HOME/newyocto/poky/build

To perform a CVE check patch analysis only use the command:

    python3 $YOCTO_BM_LOC/import_yocto_bm.py -p myproject -v v1.0 --cve_check_only

To create a JSON output scan without uploading (and no CVE patch update) use:

    python3 $YOCTO_BM_LOC/import_yocto_bm.py -p myproject -v v1.0 -o my.jsonld
