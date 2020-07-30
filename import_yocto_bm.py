import os, io
import json
import uuid
import datetime
import argparse
import sys
import platform
import re
import subprocess, shutil
import tempfile, time
from blackduck.HubRestApi import HubInstance

u = uuid.uuid1()

parser = argparse.ArgumentParser(description='Import Yocto build manifest to BD project version', prog='import_yocto_bm')

# parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")

parser.add_argument("-p", "--project", help="Black Duck project to create (REQUIRED)", default="")
parser.add_argument("-v", "--version", help="Black Duck project version to create (REQUIRED)", default="")
parser.add_argument("-y", "--yocto_build_folder", help="Yocto build folder (required if CVE check required or manifest file not specified)", default=".")
parser.add_argument("-o", "--output_json", help="Output JSON bom file for manual import to Black Duck (instead of uploading the scan automatically)", default="")
parser.add_argument("-t", "--target", help="Yocto target (default core-poky-sato)", default="core-image-sato")
parser.add_argument("-m", "--manifest", help="Input build manifest file (if not specified will be determined from conf files)", default="")
parser.add_argument("--arch", help="Architecture (if not specified then will be determined from conf files)", default="")
parser.add_argument("--cve_check_only", help="Only check for patched CVEs from cve_check and update existing project", action='store_true')
parser.add_argument("--no_cve_check", help="Skip check for and update of patched CVEs", action='store_true')
parser.add_argument("--cve_check_file", help="CVE check output file (if not specified will be determined from conf files)", default="")

args = parser.parse_args()

def check_args():
	global args
	if args.project != "" and args.version != "":
		pass
	else:
		print("Please specify Black Duck project/version using -p and -v\nExiting")
		return(False)

	if not os.path.isdir(args.yocto_build_folder):
		print("Specified Yocto build folder '{}' does not exist\nExiting".format(args.yocto_build_folder))
		return(False)

	if args.cve_check_file != "" and args.no_cve_check:
		print("Options cve_check_file and no_cve_check cannot be specified together".format(args.cve_check_file))
		return(False)

	if args.cve_check_file != "" and not os.path.isfile(args.cve_check_file):
		print("CVE check output file '{}' does not exist\nExiting".format(args.cve_check_file))
		return(False)

	if args.cve_check_only and args.no_cve_check:
		print("Options --cve_check_only and --no_cve_check cannot be specified together")
		return(False)

	if args.output_json != "":
		print("CVE checking not supported with --output_json option - will be skipped")
		args.no_cve_check = True

	if args.manifest != "" and not os.path.isfile(args.manifest):
		print("Manifest file '{}' does not exist\nExiting".format(args.manifest))
		return(False)

	return(True)

def check_env():
	if platform.system() != "Linux":
		print("Please use this program on a Linux platform where Yocto project has been installed\nExiting")
		return(False)

	# Check oe-pkgdata-util and bitbake commands are on PATH
	if shutil.which("bitbake") is None or shutil.which("oe-pkgdata-util") is None:
		print("Please ensure Yocto project has been installed and environment has been set (run 'source ooe-init-build-env')\nExiting")
		return(False)
	return(True)

def check_yocto_build_folder():
	global args
	# check Yocto build dir:
	#yocto_build_folders = [ "build", "meta", "bitbake" ]
	yocto_build_folders = [ "conf", "cache", "workspace" ]
	yocto_files = [ ]

	if os.path.isdir(os.path.join(args.yocto_build_folder, "build")):
		args.yocto_build_folder = os.path.join(args.yocto_build_folder, "build")

	for d in yocto_build_folders:
		if not os.path.isdir(os.path.join(args.yocto_build_folder, d)):
			print("Project folder {} does not appear to be a Yocto project folder which has been built({} folder missing)\nExiting".format(args.yocto_build_folder, d))
			return(False)

	for f in yocto_files:
		if not os.path.isfile(os.path.join(args.yocto_build_folder, f)):
	 		print("Project folder {} does not appear to be a Yocto project folder ({} file missing)\nExiting".format(args.yocto_build_folder, f))
	 		return(False)
	return(True)

def find_files():
	global args

	# Locate yocto files & folders
	bbconf = os.path.join(args.yocto_build_folder, "..", "meta", "conf", "bitbake.conf")
	if not os.path.isfile(bbconf):
		print("ERROR: Cannot locate bitbake conf file {}".format(bbconf))
		return(False)
	locconf = os.path.join(args.yocto_build_folder, "conf", "local.conf")
	if not os.path.isfile(locconf):
		print("ERROR: Cannot locate local bitbake conf file {}".format(locconf))
		return(False)

	import re
	import sys

	tmpdir = ""
	deploydir = ""
	machine = ""

	c = open(bbconf, "r")
	for line in c:
		if re.search('^TMPDIR ', line):
			tmpdir = line.split()[2]
		if re.search('^DEPLOY_DIR ', line):
			deploydir = line.split()[2]
	c.close()

	l = open(locconf, "r")
	for line in l:
		if re.search('^TMPDIR ', line):
			tmpdir = line.split()[2]
		if re.search('^DEPLOY_DIR ', line):
			deploydir = line.split()[2]
		if re.search('^MACHINE ', line):
			machine = line.split()[2]
	l.close()

	if tmpdir != "":
		tmpdir = tmpdir.replace('${TOPDIR}', args.yocto_build_folder)
		tmpdir = tmpdir.strip('"')
	else:
		tmpdir = os.path.join(args.yocto_build_folder, "tmp")

	if deploydir != "":
		deploydir = deploydir.replace('${TMPDIR}', tmpdir)
		deploydir = deploydir.strip('"')
	else:
		deploydir = os.path.join(args.yocto_build_folder, "tmp", "deploy")

	if args.arch == "":
		args.arch = machine.strip('"')

	if args.manifest == "":
		licdir = os.path.join(deploydir, "licenses")
		manifestdir = ""
		for file in sorted(os.listdir(licdir)):
			if file.startswith(args.target + "-" + args.arch + "-"):
				manifestdir = os.path.join(licdir, file)

		manifestfile = os.path.join(manifestdir, "package.manifest")
		if not os.path.isfile(manifestfile):
			print("Build manifest file {} does not exist - either build Yocto project or use -m option to specify build manifest file\nExiting".format(manifestfile))
			return(False)
		else:
			print("Located manifest file {}".format(manifestfile))

		args.manifest = manifestfile

	if args.cve_check_file == "" and not args.no_cve_check:
		imgdir = os.path.join(deploydir, "images", args.arch)
		cvefile = ""
		for file in sorted(os.listdir(imgdir)):
			if file.startswith(args.target + "-" + args.arch + "-") and file.endswith("rootfs.cve"):
				cvefile = os.path.join(imgdir, file)

		if not os.path.isfile(cvefile):
			print("WARNING: CVE check file could not be located - CVE patch updates will be skipped")
		else:
			print("Located CVE check output file {}".format(cvefile))
			args.cve_check_file = cvefile

	return(True)

if args.manifest == "":
	if not check_yocto_build_folder():
		sys.exit(1)
	elif os.path.isabs(args.yocto_build_folder):
		print("Working on Yocto build folder '{}'\n".format(args.yocto_build_folder))
	else:
		print("Working on Yocto build folder '{}' (Absolute path '{}')\n".format(args.yocto_build_folder, os.path.abspath(args.yocto_build_folder)))

if not check_args() or not check_env() or not find_files():
	sys.exit(1)

def upload_json(jsonfile):
	hub = HubInstance()
	r = hub.upload_scan(jsonfile)
	if r.status_code == 201:
		return(True)
	else:
		return(False)

bdio = []
proj = args.project
ver = args.version
if not args.cve_check_only:
	try:
		i = open(args.manifest, "r")
	except Exception as e:
		print('ERROR: Unable to open input manifest file {}\n'.format(args.manifest) + str(e))
		sys.exit(3)

	try:
		if args.output_json != "":
			o = open(args.output_json, "w")
		else:
			o = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonld")
			args.output_json = o.name
	except Exception as e:
		print('ERROR: Unable to open output json file {} \n'.format(args.output_json) + str(e))
		sys.exit(3)

	pkglines = i.readlines()
	i.close()

	print("\nProcessing packages: ...")

	kernel = ""
	recipes = []
	count = 0
	for line in pkglines:
		linesplit = line.split()
		#if count > 30:
		#	break
		if len(linesplit) == 0:
			break
		try:
			count += 1
			pkg = linesplit[0]
			print(pkg)
			if pkg.startswith("kernel-") and not "-module-" in pkg:
				x = re.search("^kernel\-[\d\.]*\-", pkg)
				if x != None:
					arr = pkg.split("-")
					kernel = arr[0] + "/" + arr[1]
			else:
				output = subprocess.check_output(['oe-pkgdata-util', 'package-info', linesplit[0]], stderr=subprocess.STDOUT)
				mystr = output.decode("utf-8").strip()
				re.sub(".*RPROVIDES.*\n?","",mystr)
				recipes.append(mystr)
		except:
			print("ERROR: Unexpected response from oe-pkgdata-util command - please check Yocto environment before continuing - exiting")
			sys.exit(1)

	print("Extracted recipes for {} packages in build manifest\n".format(count))

	pkgtree = {}
	allpkgs = []
	toppkgs = []

	print("Processing recipes: ...")
	lines = 0
	for line in recipes:
		linesplit = line.split()
		if len(linesplit) == 0:
			break
		pkg = linesplit[0] + "/" + linesplit[1]
		parent = linesplit[2] + "/" + linesplit[3]
		allpkgs.append(pkg)

		if pkg == parent:
			toppkgs.append(pkg)
		elif parent not in pkgtree:
			pkgtree[parent] = [ pkg ]
		else:
			pkgtree[parent].append(pkg)
		lines += 1

	print("Processed {} recipes".format(lines, args.manifest))

	#print(json.dumps(pkgtree, indent=4))
	proj_rel = []
	components = []

	if kernel != "":
		proj_rel.append(
		{
			"related": "http:debian//" + pkg,
			"relationshipType": "DYNAMIC_LINK"
		}
		)

	print("\nCreating bdio json file ...")
	for pkg in toppkgs:
		pkgname, pkgver = pkg.split("/")
		proj_rel.append(
		{
			"related": "http:yocto/meta/" + pkg,
			"relationshipType": "DYNAMIC_LINK"
		}
		)

	for pkg in pkgtree:
		if pkg not in toppkgs:
			pkgname, pkgver = pkg.split("/")
			proj_rel.append(
		{
			"related": "http:yocto/meta/" + pkg,
			"relationshipType": "DYNAMIC_LINK"
		}
			)
		if pkg not in allpkgs:
			allpkgs.append(pkg)

	for pkg in allpkgs:
		rel = []
		if pkg in pkgtree:
			for child in pkgtree[pkg]:
				#print("    " + child)
				rel.append(
		{
			"related": "http:yocto/meta/" + child,
			"relationshipType": "DYNAMIC_LINK"
		}
				)

		pkgname, pkgver = pkg.split("/")
		components.append(
	  {
		"@id": "http:yocto/meta/" + pkg,
		"@type": "Component",
		"externalIdentifier": {
		"externalSystemTypeId": "@yocto",
		"externalId": "meta/" + pkg,
		"externalIdMetaData": {
		"forge": {
			"name": "yocto",
			"separator": "/",
			"usePreferredNamespaceAlias": True
		},
		"pieces": [
			pkgname,
			pkgver
		],
		"prefix": "meta"
	      }
	    },
	    "relationship": rel
	  })
	mytime = datetime.datetime.now()
	bdio_header = {
	    "specVersion": "1.1.0",
	    "spdx:name": proj + "/" + ver + " yocto/bom",
	    "creationInfo": {
	      "spdx:creator": [
		"Tool: Detect-6.3.0",
		"Tool: IntegrationBdio-21.0.1"
	      ],
	      "spdx:created": mytime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
	    },
	    "@id": "uuid:" + str(u),
	    "@type": "BillOfMaterials",
	    "relationship": []
	  }

	bdio_project = {
	    "name": proj,
	    "revision": ver,
	    "@id": "http:yocto/" + proj,
	    "@type": "Project",
	    "externalIdentifier": {
	      "externalSystemTypeId": "@yocto",
	      "externalId": "yocto/" + proj + "/" + ver,
	      "externalIdMetaData": {
		"forge": {
		  "name": "yocto",
		  "separator": ":",
		  "usePreferredNamespaceAlias": True
		},
		"pieces": [
		  proj,
		  ver
		],
		"prefix": ""
	      }
	    },
	    "relationship": proj_rel
	  }

	#print("Writing json output file {} ...".format(args.output_json))

	bdio = [ bdio_header, bdio_project, components ]
	o.write(json.dumps(bdio, indent=4).encode())
	o.close()

	print("Uploading scan ...")
	if upload_json(args.output_json):
		print("Scan file uploaded successfully\n")
	else:
		print("ERROR: Unable to upload scan file")
		sys.exit(3)

def process_patched_cves(vuln_list):
	hub = HubInstance()

	try:
		project = hub.get_project_by_name(args.project)

		version = hub.get_version_by_name(project, args.version)

		vulnerable_components_url = hub.get_link(version, "vulnerable-components") + "?limit=9999"
		custom_headers = {'Accept':'application/vnd.blackducksoftware.bill-of-materials-6+json'}
		response = hub.execute_get(vulnerable_components_url, custom_headers=custom_headers)
		vulnerable_bom_components = response.json().get('items', [])

	except:
		print("ERROR: Unable to extract vulnerabilities from project via API")
		return()

	status = "PATCHED"
	comment = "Patched by bitbake recipe"

	count = 0
	try:
		for vuln in vulnerable_bom_components:
			vuln_name = vuln['vulnerabilityWithRemediation']['vulnerabilityName']

			if vuln_name in vuln_list:
				vuln['remediationStatus'] = status
				vuln['remediationComment'] = comment
				result = hub.execute_put(vuln['_meta']['href'], data=vuln)
				if result.status_code == 202:
					count += 1
				#	print("Marked {} as patched".format(vuln_name))
				#else:
				#	print("Skipped {} (Component not in image)".format(vuln_name))

		print("{} CVEs marked as patched in project {} version {}".format(count, args.project, args.version))
	except:
		print("ERROR: Unable to update vulnerabilities via API")

def wait_for_bom_completion(ver):
	uptodate = False
	try:
		links = ver['_meta']['links']
		link = next((item for item in links if item["rel"] == "bom-status"), None)

		href = link['href']
		custom_headers = {'Accept':'application/vnd.blackducksoftware.internal-1+json'}
		resp = hub.execute_get(href, custom_headers=custom_headers)

		loop = 0
		uptodate = resp.json()['upToDate']
		while not uptodate and loop < 80:
			time.sleep(15)
			resp = hub.execute_get(href, custom_headers=custom_headers)
			uptodate = resp.json()['upToDate']
			loop += 1
	except:
		return(False)

	if uptodate:
		return(True)
	else:
		return(False)


if args.cve_check_file != "" and not args.no_cve_check:
	hub = HubInstance()

	print("\nWaiting for scan completion before continuing ...")
	if not args.cve_check_only:
		time.sleep(30)

	try:
		ver = hub.get_project_version_by_name(args.project, args.version)
	except:
		print("ERROR: Unable to get project version from API")
		sys.exit(1)

	if not wait_for_bom_completion(ver):
		print("ERROR: Unable to determine BOM status - exiting")
		sys.exit(3)

	print("\nLoading CVEs from cve_check log ...")

	cvefile = open(args.cve_check_file, "r")
	cvelines = cvefile.readlines()
	cvefile.close()
	patched_vulns = []
	pkgvuln = {}
	for line in cvelines:
		arr = line.split(":")
		if len(arr) > 1:
			key = arr[0]
			value = arr[1].strip()
			if key == "PACKAGE NAME":
				pkgvuln['package'] = value
			elif key == "PACKAGE VERSION":
				pkgvuln['version'] = value
			elif key == "CVE":
				pkgvuln['CVE'] = value
			elif key == "CVE STATUS":
				pkgvuln['status'] = value
				if pkgvuln['status'] == "Patched":
					patched_vulns.append(pkgvuln['CVE'])
				pkgvuln = {}

	print("{} Patched CVEs identified from cve_check file".format(len(patched_vulns)))
	if len(patched_vulns) > 0:
		process_patched_cves(patched_vulns)

