
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
	else:
		args.yocto_build_folder = os.path.abspath(args.yocto_build_folder)

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
		print("Please use this program on a Linux platform where Yocto project has been built\nExiting")
		return(False)

	# Check oe-pkgdata-util and bitbake commands are on PATH
	if shutil.which("bitbake") is None or shutil.which("bitbake-layers") is None:
		print("Please ensure Yocto project has been installed and environment has been set (run 'source ooe-init-build-env')\nExiting")
		return(False)
	return(True)

def check_yocto_build_folder():
	global args
	# check Yocto build dir:
	#yocto_build_folders = [ "build", "meta", "bitbake" ]
	yocto_build_folders = [ "conf", "cache", "tmp" ]
	yocto_files = [ ]

	if os.path.isdir(os.path.join(args.yocto_build_folder, "build")):
		args.yocto_build_folder = os.path.join(args.yocto_build_folder, "build")

	for d in yocto_build_folders:
		if not os.path.isdir(os.path.join(args.yocto_build_folder, d)):
			print("Project build folder {} does not appear to be a Yocto project folder which has been built ({} folder missing)\nExiting".format(args.yocto_build_folder, d))
			return(False)

	for f in yocto_files:
		if not os.path.isfile(os.path.join(args.yocto_build_folder, f)):
	 		print("Project build folder {} does not appear to be a Yocto project folder ({} file missing)\nExiting".format(args.yocto_build_folder, f))
	 		return(False)
	return(True)

def find_files():
	global args, licdir

	# Locate yocto files & folders
	if args.buildconf == "":
		args.buildconf = os.path.join(args.yocto_build_folder, "..", "meta", "conf", "bitbake.conf")
	if not os.path.isfile(args.buildconf):
		print("ERROR: Cannot locate bitbake conf file {}".format(args.buildconf))
		return(False)
	if args.localconf == "":
		args.localconf = os.path.join(args.yocto_build_folder, "conf", "local.conf")
	if not os.path.isfile(args.localconf):
		print("ERROR: Cannot locate local bitbake conf file {}".format(args.localconf))
		return(False)

	import re
	import sys

	tmpdir = ""
	deploydir = ""
	machine = ""

	try:
		c = open(args.buildconf, "r")
		for line in c:
			if re.search('^TMPDIR ', line):
				tmpdir = line.split()[2]
			if re.search('^DEPLOY_DIR ', line):
				deploydir = line.split()[2]
		c.close()
	except Exception as e:
		print("ERROR: Unable to read bitbake.conf file {}\n".format(args.buildconf) + str(e))
		return(False)

	try:
		l = open(args.localconf, "r")
		for line in l:
			if re.search('^TMPDIR ', line):
				tmpdir = line.split()[2]
			if re.search('^DEPLOY_DIR ', line):
				deploydir = line.split()[2]
			if re.search('^MACHINE ', line):
				machine = line.split()[2]
		l.close()
	except Exception as e:
		print("ERROR: Unable to read local.conf file {}\n".format(args.localconf) + str(e))
		return(False)

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

	licdir = os.path.join(deploydir, "licenses")
	if args.manifest == "":
		manifestdir = ""
		if not os.path.isdir(licdir):
			print("License directory {} does not exist - has Yocto project been built?".format(licdir))
			return(False)
		for file in sorted(os.listdir(licdir)):
			if file.startswith(args.target + "-" + args.arch + "-"):
				manifestdir = os.path.join(licdir, file)

		manifestfile = os.path.join(manifestdir, "license.manifest")
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


def proc_license_manifest(liclines):
	global recipes, packages

	print("- Working on recipes from license.manifest: ...")
	entries = 0
	for line in liclines:
		arr = line.split(":")
		if len(arr) > 1:
			key = arr[0]
			value = arr[1].strip()
			if key == "PACKAGE NAME":
				packages.append(value)
			elif key == "PACKAGE VERSION":
				ver = value
			elif key == "RECIPE NAME":
				entries += 1
				if not value in recipes.keys():
					recipes[value] = ver
	print("	Identified {} recipes from {} packages".format(len(recipes), entries))

def proc_layers_in_recipes():
	global layers, recipe_layer

	print("- Identifying layers for recipes ...")
	output = subprocess.check_output(['bitbake-layers', 'show-recipes', '*'], stderr=subprocess.STDOUT)
	mystr = output.decode("utf-8").strip()
	lines = mystr.splitlines()
	rec = ""
	start = False
	for line in lines:
		if start:
			if line.endswith(":"):
				arr = line.split(":")
				rec = arr[0]
			else:
				arr = line.split()
				if len(arr) > 1:
					layer = arr[0]
					ver = arr[1]
					recipe_layer[rec] = layer
					if rec in recipes.keys():
						recipes[rec] = ver
					if layer not in layers:
						layers.append(layer)
				rec = ""
		elif line.find("=== Matching recipes: ===") != -1:
			start = True
	print("		Discovered {} layers".format(len(layers)))

def proc_recipe_revisions():
	global licdir, recipes

	print("- Identifying recipe revisions: ...")
	for recipe in recipes.keys():
		recipeinfo = os.path.join(licdir, recipe, "recipeinfo")
		if os.path.isfile(recipeinfo):
			try:
				r = open(recipeinfo, "r")
				reclines = r.readlines()
				r.close()
			except Exception as e:
				print("ERROR: unable to open recipeinfo file {}\n".format(recipeinfo) + str(e))
				sys.exit(3)
			for line in reclines:
				if line.find("PR:") != -1:
					arr = line.split(":")
					rev = arr[1].strip()
					recipes[recipe] += "-" + rev

def proc_layers():
	global proj_rel, comps_layers, layers, recipes, recipe_layer

	print("- Processing layers: ...")
	#proj_rel is for the project relationship (project to layers)
	for layer in layers:
		proj_rel.append(
			{
				"related": "http:yocto/" + layer + "/1.0",
				"relationshipType": "DYNAMIC_LINK"
			}
		)
		layer_rel = []
		for recipe in recipes.keys():
			if recipe in recipe_layer.keys() and recipe_layer[recipe] == layer:
				if recipes[recipe].find("+gitAUTOINC") != -1:
					ver = recipes[recipe].split("+")[0] + "+gitX-" + recipes[recipe].split("-")[-1]
				else:
					ver = recipes[recipe]
					
				layer_rel.append(
					{
						"related": "http:yocto/" + layer + "/" + recipe + "/" + ver,
						"relationshipType": "DYNAMIC_LINK"
					}
				)

		comps_layers.append(
		{
			"@id": "http:yocto/" + layer + "/1.0",
			"@type": "Component",
			"externalIdentifier": {
			"externalSystemTypeId": "@yocto",
			"externalId": layer,
			"externalIdMetaData": {
			"forge": {
				"name": "yocto",
				"separator": "/",
				"usePreferredNamespaceAlias": True
			},
			"pieces": [
				layer,
				"1.0"
			],
			"prefix": "meta"
		      }
		    },
		    "relationship": layer_rel
		})


def proc_recipes():
	global recipes, recipe_layer, comps_recipes

	print("- Processing recipes: ...")
	for recipe in recipes.keys():
		if recipes[recipe].find("+gitAUTOINC") != -1:
			ver = recipes[recipe].split("+")[0] + "+gitX-" + recipes[recipe].split("-")[-1]
		else:
			ver = recipes[recipe]

		if recipe in recipe_layer.keys():
			comps_recipes.append(
			{
				"@id": "http:yocto/" + recipe_layer[recipe] + "/" + recipe + "/" + ver,
				"@type": "Component",
				"externalIdentifier": {
				"externalSystemTypeId": "@yocto",
				"externalId": recipe_layer[recipe] + "/" + recipe + "/" + ver,
				"externalIdMetaData": {
				"forge": {
					"name": "yocto",
					"separator": "/",
					"usePreferredNamespaceAlias": True
				},
				"pieces": [
					recipe,
					ver
				],
				"prefix": recipe_layer[recipe]
			      }
			    },
			    "relationship": []
			  })

def write_bdio(bdio):
	global args

	if args.output_json != "":
		try:
			o = open(args.output_json, "w")
			o.write(json.dumps(bdio, indent=4))
			o.close()
			print("Json project file written to {} - must be manually uploaded".format(args.output_json))
		except Exception as e:
			print("ERROR: Unable to write output json file {}\n".format(args.output_json) + str(e))
			return(False)

	else:
		import tempfile
		try:
			with tempfile.NamedTemporaryFile(suffix=".jsonld", delete=False) as o:
				args.output_json = o.name
				o.write(json.dumps(bdio, indent=4).encode())
				o.close()
		except Exception as e:
			print("ERROR: Unable to write temporary output json file\n" + str(e))
			return(False)

	return(True)

def upload_json(jsonfile):
	hub = HubInstance()
	r = hub.upload_scan(jsonfile)
	if r.status_code == 201:
		return(True)
	else:
		return(False)


def patch_vuln(hub, comp):
	status = "PATCHED"
	comment = "Patched by bitbake recipe"

	try:
		vuln_name = comp['vulnerabilityWithRemediation']['vulnerabilityName']

		comp['remediationStatus'] = status
		comp['remediationComment'] = comment
		result = hub.execute_put(comp['_meta']['href'], data=comp)
		if result.status_code != 202:
			return(False)

	except Exception as e:
		print("ERROR: Unable to update vulnerabilities via API\n" + str(e))
		return(False)

	return(True)

def process_patched_cves(hub, version, vuln_list):
	global args

	try:
		vulnerable_components_url = hub.get_link(version, "vulnerable-components") + "?limit=9999"
		custom_headers = {'Accept':'application/vnd.blackducksoftware.bill-of-materials-6+json'}
		response = hub.execute_get(vulnerable_components_url, custom_headers=custom_headers)
		vulnerable_bom_components = response.json().get('items', [])

		count = 0

		for comp in vulnerable_bom_components:
			if comp['vulnerabilityWithRemediation']['source'] == "NVD":
				if comp['vulnerabilityWithRemediation']['vulnerabilityName'] in vuln_list:
					if patch_vuln(hub, comp):
						print("		Patched {}".format(comp['vulnerabilityWithRemediation']['vulnerabilityName']))
						count += 1
			elif comp['vulnerabilityWithRemediation']['source'] == "BDSA":
				vuln_url = hub.get_apibase() + "/vulnerabilities/" + comp['vulnerabilityWithRemediation']['vulnerabilityName']
				custom_headers = {'Accept':'application/vnd.blackducksoftware.vulnerability-4+json'}
				resp = hub.execute_get(vuln_url, custom_headers=custom_headers)
				vuln = resp.json()
				#print(json.dumps(vuln, indent=4))
				for x in vuln['_meta']['links']:
					if x['rel'] == 'related-vulnerability':
						if x['label'] == 'NVD':
							cve = x['href'].split("/")[-1]
							if cve in vuln_list:
								if patch_vuln(hub, comp):
									print("		Patched " + vuln['name'] + ": " + cve)
									count += 1

	except Exception as e:
		print("ERROR: Unable to get components from project via API\n" + str(e))
		return(False)

	print("- {} CVEs marked as patched in project '{}/{}'".format(count, args.project, args.version))
	return(True)

def wait_for_bom_completion(ver):
	global hub
	# Check job status
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
	except Exception as e:
		print("ERROR: {}".format(str(e)))
		return(False)

	if uptodate:
		return(True)
	else:
		return(False)

def wait_for_scans(ver):
	global hub

	links = ver['_meta']['links']
	link = next((item for item in links if item["rel"] == "codelocations"), None)

	href = link['href']

	time.sleep(10)
	wait = True
	loop = 0
	while wait and loop < 20:
		custom_headers = {'Accept':'application/vnd.blackducksoftware.internal-1+json'}
		resp = hub.execute_get(href, custom_headers=custom_headers)
		for cl in resp.json()['items']:
			if 'status' in cl:
				status_list = cl['status']
				for status in status_list:
					if status['operationNameCode'] == "ServerScanning":
						if status['status'] == "COMPLETED":
							wait = False
		if wait:
			time.sleep(15)
			loop += 1

	return(not wait)

import os, io
import json
import uuid
import datetime
import argparse
import sys
import platform
import re
import subprocess, shutil
import time
from blackduck.HubRestApi import HubInstance

parser = argparse.ArgumentParser(description='Import Yocto build manifest to BD project version', prog='import_yocto_bm')

# parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")

parser.add_argument("-p", "--project", help="Black Duck project to create (REQUIRED)", default="")
parser.add_argument("-v", "--version", help="Black Duck project version to create (REQUIRED)", default="")
parser.add_argument("-y", "--yocto_build_folder", help="Yocto build folder (required if CVE check required or manifest file not specified)", default=".")
parser.add_argument("-o", "--output_json", help="Output JSON bom file for manual import to Black Duck (instead of uploading the scan automatically)", default="")
parser.add_argument("-t", "--target", help="Yocto target (default core-poky-sato)", default="core-image-sato")
parser.add_argument("-m", "--manifest", help="Input build license.manifest file (if not specified will be determined from conf files)", default="")
parser.add_argument("-b", "--buildconf", help="Build config file (if not specified poky/meta/conf/bitbake.conf will be used)", default="")
parser.add_argument("-l", "--localconf", help="Local config file (if not specified poky/build/conf/local.conf will be used)", default="")
parser.add_argument("--arch", help="Architecture (if not specified then will be determined from conf files)", default="")
parser.add_argument("--cve_check_only", help="Only check for patched CVEs from cve_check and update existing project", action='store_true')
parser.add_argument("--no_cve_check", help="Skip check for and update of patched CVEs", action='store_true')
parser.add_argument("--cve_check_file", help="CVE check output file (if not specified will be determined from conf files)", default="")

args = parser.parse_args()

def main():
	global args
	print("Yocto build manifest import into Black Duck Utility v1.4")
	print("--------------------------------------------------------\n")

	if not check_args() or not check_env() or not find_files():
		sys.exit(1)
	
	if args.manifest == "":
		if not check_yocto_build_folder():
			sys.exit(1)
		elif os.path.isabs(args.yocto_build_folder):
			print("Working on Yocto build folder '{}'\n".format(args.yocto_build_folder))
		else:
			print("Working on Yocto build folder '{}' (Absolute path '{}')\n".format(args.yocto_build_folder, os.path.abspath(args.yocto_build_folder)))

	bdio = []
	proj = args.project
	ver = args.version
	comps_layers = []
	comps_recipes = []
	packages = []
	recipes = {}
	comps_recipes = []
	recipe_layer = {}
	layers = []
	proj_rel = []
	comps_layers = []

	u = uuid.uuid1()
	licdir = ""

	if not args.cve_check_only:
		try:
			i = open(args.manifest, "r")
		except Exception as e:
			print('ERROR: Unable to open input manifest file {}\n'.format(args.manifest) + str(e))
			sys.exit(3)

		try:
			liclines = i.readlines()
			i.close()
		except Exception as e:
			print('ERROR: Unable to read license.manifest file {} \n'.format(args.manifest) + str(e))
			sys.exit(3)

		print("\nProcessing Bitbake project:")
		proc_license_manifest(liclines)
		proc_layers_in_recipes()
		proc_recipe_revisions()
		proc_layers()
		proc_recipes()

		#proj_rel is for the project relationship (project to layers)

		mytime = datetime.datetime.now()
		bdio_header = {
			"specVersion": "1.1.0",
			"spdx:name": args.project + "/" + args.version + " yocto/bom",
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
			"name": args.project,
			"revision": args.version,
			"@id": "http:yocto/" + args.project + "/" + args.version,
			"@type": "Project",
			"externalIdentifier": {
			  "externalSystemTypeId": "@yocto",
			  "externalId": "yocto/" + args.project + "/" + args.version,
			  "externalIdMetaData": {
			"forge": {
			  "name": "yocto",
			  "separator": ":",
			  "usePreferredNamespaceAlias": True
			},
			"pieces": [
			  args.project,
			  args.version
			],
			"prefix": ""
			  }
			},
			"relationship": proj_rel
		  }

		bdio = [ bdio_header, bdio_project, comps_layers, comps_recipes ]
		if not write_bdio(bdio):
			sys.exit(3)

		print("\nUploading scan to Black Duck server ...")
		if upload_json(args.output_json):
			print("Scan file uploaded successfully\nBlack Duck project '{}/{}' created.".format(args.project, args.version))
		else:
			print("ERROR: Unable to upload scan file")
			sys.exit(3)

	if args.cve_check_file != "" and not args.no_cve_check:
		hub = HubInstance()

		print("\nProcessing CVEs ...")

		if not args.cve_check_only:
			print("Waiting for Black Duck server scan completion before continuing ...")
			# Need to wait for scan to process into queue - sleep 15
			time.sleep(15)

		try:
			print("- Reading Black Duck project ...")
			ver = hub.get_project_version_by_name(args.project, args.version)
		except Exception as e:
			print("ERROR: Unable to get project version from API\n" + str(e))
			sys.exit(3)

		if not wait_for_scans(ver):
			print("ERROR: Unable to determine scan status")
			sys.exit(3)

		if not wait_for_bom_completion(ver):
			print("ERROR: Unable to determine BOM status")
			sys.exit(3)

		print("- Loading CVEs from cve_check log ...")

		try:
			cvefile = open(args.cve_check_file, "r")
			cvelines = cvefile.readlines()
			cvefile.close()
		except Exception as e:
			print("ERROR: Unable to open CVE check output file\n" + str(e))
			sys.exit(3)
		
		patched_vulns = []
		pkgvuln = {}
		cves_in_bm = 0
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
						if pkgvuln['package'] in packages:
							cves_in_bm += 1
					pkgvuln = {}

		print("      {} total patched CVEs identified".format(len(patched_vulns)))
		if not args.cve_check_only:
			print("      {} Patched CVEs within packages in build manifest (including potentially mismatched CVEs which should be ignored)".format(cves_in_bm))
		if len(patched_vulns) > 0:
			process_patched_cves(hub, ver, patched_vulns)
	print("Done")

if __name__ == "__main__":
    main()