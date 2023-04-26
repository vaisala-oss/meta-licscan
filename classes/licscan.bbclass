LICSCAN_CACHE_DIR ?= "${TMPDIR}/work-shared/licscan/${PN}"
LICSCAN_JSON_STRUCTURE_VERSION = "9"
LICSCAN_RECIPES ??= ""
LICSCAN_SCANNERS ??= "nomossa"
LICSCAN_SKIP_PN_PREFIX ??= ""
LICSCAN_SKIP_PN_SUFFIX ??= "-cross -initial"
LICSCAN_SKIP_PN ??= "linux-libc-headers"
LICSCAN_SKIP_INHERIT ??= "image"

inherit image-artifact-names


def should_scan_package(d):
    pn = d.getVar('PN')

    # In case LICSCAN_RECIPES variable is non-empty, scan only recipes that are declared in it
    if len(d.getVar('LICSCAN_RECIPES').strip()) > 0 and d.getVar('PN') not in d.getVar('LICSCAN_RECIPES').split():
        bb.debug(1, 'Skipping ' + pn + ' (not in LICSCAN_RECIPES)')
        return False

    # Filter out non-target packages
    if d.getVar('CLASSOVERRIDE') != 'class-target':
        bb.debug(1, 'Skipping ' + pn + ' (CLASSOVERRIDE doesn\'t match class-target)')
        return False

    # Filter out packages due to specific prefix in package name
    for prefix in d.getVar('LICSCAN_SKIP_PN_PREFIX').split():
        if pn.startswith(prefix):
            bb.debug(1, 'Skipping ' + pn + ' (matches prefix \'' + prefix + '\')')
            return False

    # Filter out packages due to specific suffix in package name
    for suffix in d.getVar('LICSCAN_SKIP_PN_SUFFIX').split():
        if pn.endswith(suffix):
            bb.debug(1, 'Skipping ' + pn + ' (matches suffix \'' + suffix + '\')')
            return False

    # Filter out packages due to package name
    for pkg in d.getVar('LICSCAN_SKIP_PN').split():
        if pn == pkg:
            bb.debug(1, 'Skipping ' + pn + ' (matches \'' + pkg + '\')')
            return False

    # Filter out packages that should be skipped due to some bbclass they inherit
    for bbclass in d.getVar('LICSCAN_SKIP_INHERIT').split():
        if bb.data.inherits_class(bbclass, d):
            bb.debug(1, 'Skipping ' + pn + ' (inherits \'' + bbclass + '\')')
            return False

    bb.debug(1, 'Including ' + pn)
    return True


# Definitions for individual license scanners
LICSCAN_COMMAND_OPTS[nomossa] = "-l -J"
LICSCAN_VERSION_COMMAND[nomossa] = "nomossa -V"

# Anonymous python function executed during bitbake parsing phase
python() {
    if should_scan_package(d):
        d.appendVar('PACKAGEFUNCS', ' emit_pkgdata_licscan')

        # To avoid redundant license scanner runs, package families using shared source code directory will use a single
        # common intermediate results file (which contains only analysis results and skipped files)
        if d.getVar('BPN') in ['gcc', 'libgcc']:
            if d.getVar('PN') != 'gcc-source-' + d.getVar('PV'):
                d.appendVarFlag('do_package', 'depends', ' gcc-source-' + d.getVar('PV') + ':do_licscan')
                d.setVar('LICSCAN_CACHE_DIR', os.path.dirname(d.getVar('LICSCAN_CACHE_DIR').rstrip('/')) +
                         '/gcc-source-' + d.getVar('PV'))
                return

        # For glibc collateral recipes we declare explicit reuse of license analysis results of glibc package itself
        if d.getVar('PN').startswith('glibc-'):
            d.setVar('LICSCAN_CACHE_DIR', os.path.dirname(d.getVar('LICSCAN_CACHE_DIR').rstrip('/')) + '/glibc')
            d.appendVarFlag('do_package', 'depends', ' virtual/' + d.getVar('MLPREFIX') + 'libc:do_licscan')
            return

        # KERNEL_VERSION is not deterministic, so for now let's use just 'kernel-source' as shared intermediate results
        # directory name between kernel source code consumers. If this proves problematic then move LICSCAN_CACHE_DIR
        # arbitrage to a deterministic context (such as do_licscan/emit_pkgdata_licscan) where we can use e.g.
        # '/kernel-source-' + d.getVar('KERNEL_VERSION') instead
        if bb.data.inherits_class('kernel', d) or bb.data.inherits_class('kernelsrc', d):
            d.setVar('LICSCAN_CACHE_DIR', os.path.dirname(d.getVar('LICSCAN_CACHE_DIR').rstrip('/')) + '/kernel-source')
            if bb.data.inherits_class('kernelsrc', d):
                d.appendVarFlag('do_package', 'depends', ' virtual/kernel:do_licscan')
                return

        if d.getVar('WORKDIR') != d.getVar('S'):
            bb.build.addtask('do_licscan', 'do_preconfigure do_configure do_compile do_package',
                             'do_unpack do_patch', d)
        else:
            bb.build.addtask('do_licscan', 'do_package', 'do_install', d)

        for scanner in d.getVar('LICSCAN_SCANNERS').split():
            d.appendVarFlag('do_licscan', 'depends', ' ' + scanner + '-native:do_populate_sysroot')

        d.appendVar('SSTATETASKS', ' do_licscan')
        d.appendVarFlag('do_licscan', 'dirs', ' ' + d.getVar('LICSCAN_CACHE_DIR'))
        d.appendVarFlag('do_licscan', 'sstate-plaindirs', ' ' + d.getVar('LICSCAN_CACHE_DIR'))
}


def add_to_dict(d, dict_root, sub, key, value):
    if sub:
        if sub not in dict_root:
            dict_root[sub] = {}
        if key not in dict_root[sub]:
            dict_root[sub][key] = []
        dict_root[sub][key].append(value)
    else:
        if key not in dict_root:
            dict_root[key] = value
        else:
            dict_root[key].append(value)


def communicate(d, command):
    import subprocess
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    if p.returncode != 0 or stderr != '':
        bb.fatal("Command '%s' returned %d\nStdout was: '%s'\nStderr was: '%s'"
                 % (command, p.returncode, stdout, stderr))
    return stdout


do_licscan[doc] = "Runs defined license analyzers against patched source code tree"
python do_licscan() {
    from fnmatch import fnmatchcase
    import json
    try:
        import magic
    except ImportError:
        bb.fatal("Please install python-magic to host. See 'Requirements' section in meta-licscan/README.md.")
    from os import walk
    from os.path import islink, join
    import shlex

    # Arbitrate scan root directory location as 'S' or 'D' (without trailing slashes, should such exist)
    scan_root = d.getVar('S').rstrip('/') if d.getVar('WORKDIR') != d.getVar('S') else d.getVar('D').rstrip('/')

    # Create separate results files for each scanner program
    for scanner in d.getVar('LICSCAN_SCANNERS').split():
        cmd_base = scanner + ' ' + d.getVarFlag('LICSCAN_COMMAND_OPTS', scanner) + ' '

        # Blacklisted directory component names (considered to contain material irrelevant to actual package license(s))
        dirnameignores = [
            '/autom4te.cache/',
            '/build-aux/',
            '/examples/',
            '/.git/',
            '/gtests/',
            '/man/',
            '/patches/',
            '/.pc/',
            '/po/',
            '/.svn/',
            '/test/',
            '/tests/',
            '/testsuite/',
        ]

        # Blacklisted file names (considered to contain material irrelevant to actual package license(s))
        filenameignores = [
            '**/autogen.sh',
            '**/CMakeLists.txt',
            '**/compile',
            '**/config.guess',
            '**/config.h.in',
            '**/config.rpath',
            '**/config.sub',
            '**/configure',
            '**/configure.ac',
            '**/depcomp',
            '**/Doxyfile.in',
            '**/install-sh',
            '**/ltmain.sh',
            '**/Makefile.in',
            '**/Makefile.am',
            '**/Makefile',
            '**/meson.build',
            '**/missing',
        ]

        # Blacklisted file name prefixes
        filenameprefixignores = [
            '**/.*',
        ]

        # Blacklisted file name suffixes
        filenamesuffixignores = [
            '**/*~',
            '**/*.cmake',
            '**/*.cmake.in',
            '**/*.m4',
        ]

        # Blacklisted MIME types (considered irrelevant wrt. actual package license(s))
        mimetypeignores = [
            'application',
            'image',
            'audio',
        ]

        dict_root = dict()
        scan_files = []

        class Continue(Exception):
            """For assisting continue of external loop from within inner (nested) loop"""
            pass

        # Traverse files in target package
        for root, dirs, files in walk(scan_root):
            for filename in files:
                file = join(root, filename)
                value = file.split(scan_root + '/')[1]

                if islink(file):
                    add_to_dict(d, dict_root, 'ignoredFiles', 'symbolicLink', value)
                    continue

                try:
                    for pattern in dirnameignores:
                        if pattern in root + '/':
                            add_to_dict(d, dict_root, 'ignoredFiles', 'blacklistedDirectoryNameInPath_' +
                                        pattern.replace('/', ''), value)
                            raise Continue()
                except Continue:
                    continue

                if any(fnmatchcase(file, pattern) for pattern in filenameignores):
                    add_to_dict(d, dict_root, 'ignoredFiles', 'blacklistedFileName', value)
                    continue

                if any(fnmatchcase(file, pattern) for pattern in filenameprefixignores):
                    add_to_dict(d, dict_root, 'ignoredFiles', 'blacklistedFileNamePrefix', value)
                    continue

                if any(fnmatchcase(file, pattern) for pattern in filenamesuffixignores):
                    add_to_dict(d, dict_root, 'ignoredFiles', 'blacklistedFileNameSuffix', value)
                    continue

                mimetype = magic.from_file(file, mime=True).split('/')[0]
                if any(pattern in mimetype for pattern in mimetypeignores):
                    add_to_dict(d, dict_root, 'ignoredFiles', 'blacklistedMimeType_' + mimetype, value)
                    continue

                scan_files.append([shlex.split(cmd_base + shlex.quote(file)), value])

        if scanner == 'nomossa':
            def communicate_nomossa(scan_file):
                return (communicate(d, scan_file[0])[2:-2].replace('"', ''), scan_file[1])

            results = oe.utils.multiprocess_launch(communicate_nomossa, scan_files, d)
            for (result, path) in results:
                add_to_dict(d, dict_root, 'scannedFiles', result, path)
        else:
            bb.fatal("Unsupported scanner: %s" % scanner)

        # Add information about scanning facility (only in case there was at least one file scanned)
        if 'scannedFiles' in dict_root:
            add_to_dict(d, dict_root, 'scanInformation', 'scannerBaseCommand', cmd_base.strip())
            add_to_dict(d, dict_root, 'scanInformation', 'scannerVersion',
                        communicate(d, shlex.split(d.getVarFlag('LICSCAN_VERSION_COMMAND', scanner))).strip())
            add_to_dict(d, dict_root, 'scanInformation', 'jsonStructureVersion',
                        d.getVar('LICSCAN_JSON_STRUCTURE_VERSION'))

        # Sort entries for improved readability and inter-version comparability
        for key in dict_root.keys():
            if isinstance(dict_root[key], dict):
                for subkey in dict_root[key].keys():
                    dict_root[str(key)][str(subkey)].sort()

        # Create intermediate results file containing scanned and skipped files information
        cache_file = join(d.getVar('LICSCAN_CACHE_DIR'), scanner + '.json')
        bb.utils.mkdirhier(os.path.dirname(cache_file))
        with open(cache_file, 'w') as outputfile:
            outputfile.write(json.dumps(dict_root, indent=4, sort_keys=True))
            outputfile.write('\n')
}


# Finalize json creation at the end of do_package() as there are internal Yocto variables which are resolved only until
# this context has been reached, such as PACKAGES (particularly with recipes resorting to PACKAGES_DYNAMIC mechanism),
# PKGV (get_srcrev() puts "AUTOINC+" into return value instead of incremental revision value) and 'PKG:%s' package
# mappings
python emit_pkgdata_licscan() {
    import json
    from os.path import join
    import re
    import shlex

    # Create separate results files for each scanner program
    for scanner in d.getVar('LICSCAN_SCANNERS').split():
        dict_root = dict()

        # Restore scan results from intermediate file
        cache_file = join(d.getVar('LICSCAN_CACHE_DIR'), scanner + '.json')
        with open(cache_file, 'r') as inputfile:
            dict_root = json.loads(inputfile.read())

        # Add bitbake runtime information about recipes packages
        for bbvar in ['LICENSE', 'P', 'PF', 'PKGV', 'PN', 'PV', 'SUMMARY']:
            add_to_dict(d, dict_root, 'packageInformation', bbvar, d.getVar(bbvar))
        for key in d.keys():
            # Add sets of keys recognizable via specific characters in beginning of key name
            if ((key.startswith('LICENSE:') and key[8].islower()) or
                (key.startswith('PKG:') and key[4].islower()) or
                key.startswith('SRCREV')):
                    add_to_dict(d, dict_root, 'packageInformation', key, d.getVar(key))
            # Add multi-valued keys so that each value has own entry
            if key in ['LIC_FILES_CHKSUM', 'PACKAGES', 'SRC_URI']:
                if d.getVar(key) is not None:
                    for entry in d.getVar(key).split():
                        add_to_dict(d, dict_root, 'packageInformation', key, entry)

        # Add SPDX-mapped versions of LICENSE* entries, if the license label(s) in entries are not in SPDX format.
        # We do this by splitting the value of entry to license label and non-label list items, and recreating the entry
        # value so that license label parts are replaced with SPDXLICENSEMAP variants if they exist. Finally we add
        # SPDXMapped_<LICENSE*> = "<spdxmapped value>" entries to recipe specific json file, in case the resulting value
        # differs from value of recipe's respective LICENSE* variable.
        lic_keys = []
        for key in dict_root['packageInformation']:
            if key == 'LICENSE' or (key.startswith('LICENSE:') and key[8].islower()):
                lic_keys.append(key)

        for key in lic_keys:
            oldvalue = ''.join(dict_root['packageInformation'][key])
            nonlabels = []
            for item in re.split('[A-Za-z0-9-.]', oldvalue):
                if item:
                    nonlabels.append(item)

            liclabels = []
            for item in re.split('[* &|()+]', oldvalue):
                if item:
                    spdxmapped = d.getVarFlag('SPDXLICENSEMAP', ''.join(item))
                    if spdxmapped is not None:
                        liclabels.append(spdxmapped)
                    else:
                        liclabels.append(item)

            if re.match('[A-Za-z0-9-.]', oldvalue[0]):
                begins_with_nonlabels = False
            else:
                begins_with_nonlabels = True

            newvalue = ''
            idx = 0
            while idx < len(nonlabels) or idx < len(liclabels):
                if begins_with_nonlabels:
                    if idx < len(nonlabels):
                        newvalue += nonlabels[idx]
                    if idx < len(liclabels):
                        newvalue += liclabels[idx]
                else:
                    if idx < len(liclabels):
                        newvalue += liclabels[idx]
                    if idx < len(nonlabels):
                        newvalue += nonlabels[idx]
                idx += 1

            if newvalue != oldvalue:
                add_to_dict(d, dict_root, 'packageInformation', 'SPDXMapped_' + key, newvalue)

        # Sort entries for improved readability and inter-version comparability
        for key in dict_root.keys():
            if isinstance(dict_root[key], dict):
                for subkey in dict_root[key].keys():
                    dict_root[str(key)][str(subkey)].sort()

        # Create final results file in area which ends up under sstate-cached PKGDATA_DIR
        results_file = join(d.getVar('PKGDESTWORK'), 'licscan', scanner, d.getVar('PN') + '.json')
        bb.utils.mkdirhier(os.path.dirname(results_file))
        with open(results_file, 'w') as outputfile:
            outputfile.write(json.dumps(dict_root, indent=4, sort_keys=True))
            outputfile.write('\n')
}


# Generate DEPLOY_DIR_IMAGE/IMAGE_NAME.{licscan.json,licscantool.txt} based on recipe-specific licscan json files that
# were generated because one or more target-specific packages these recipes provide are included in dependency tree that
# IMAGE_INSTALL declaration resolves into.
python generate_image_licscan_files() {
    import argparse
    import glob
    import json
    import os
    import sys

    # Resolve json directory (i.e. scan results dir)
    scanner = d.getVar('LICSCAN_SCANNERS')
    if len(scanner.split()) > 1:
        bb.fatal('More than one scanner declared. Please update this task to work with more than one scanner.')
    jsondir = os.path.join(d.getVar('PKGDATA_DIR'), 'licscan',  scanner)
    if not os.path.isdir(jsondir):
        bb.fatal('Scan results directory %s does not exist' % jsondir)

    # Add content of .json files to a dictionary. We use PN as the key.
    json_data_in = {}
    prevdir = os.getcwd()
    os.chdir(jsondir)
    for file in sorted(glob.glob('*.json')):
        with open(file) as json_file:
            json_data_in.setdefault(file[:-5], json.load(json_file))
    os.chdir(prevdir)

    # Iterate image .manifest file one line at a time, and look for recipe name/version match in dictionary
    json_data_out = {}
    deploy_dir = d.getVar('IMGDEPLOYDIR')
    manifest = d.getVar('IMAGE_MANIFEST')
    with open(manifest) as fp:
        output = []
        pkgs_array = []

        for count, line in enumerate(fp):
            package_name, pkgarch, pkgv = format(line).split()

            # Map package name to a recipe
            recipe_name = None
            for pn in json_data_in:
                # Compare against PACKAGES names as well as respective PKG:<pkg_key> values
                for pkg_key in json_data_in[pn]['packageInformation']['PACKAGES']:
                    pkg_value = ''.join(json_data_in[pn]['packageInformation']['PKG:' + pkg_key])
                    if pkg_key == package_name or pkg_value == package_name:
                        if recipe_name is not None:
                            bb.fatal("Package key/value 'PKG:%s' matched twice, first in '%s.json' then in '%s.json'" %
                                     (package_name, recipe_name, pn))
                        recipe_name = pn

            if not recipe_name:
                for pn in json_data_in:
                    # Catch remaining candidates which match only by recipe name
                    if package_name == pn:
                        if recipe_name is not None:
                            bb.fatal("Package name '%s' matched twice, first in '%s.json' then in '%s.json'" %
                                     (package_name, recipe_name, pn))
                        recipe_name = pn

            if recipe_name:
                # Compare rpm packaging naming aligned ('-' chars replaced with '+') manifest PKGV against json PKGV
                json_pkgv = ''.join(json_data_in[recipe_name]['packageInformation']['PKGV'])
                if json_pkgv.replace('-', '+') != pkgv:
                    bb.fatal("Mismatching version for recipe '%s' -- image manifest has '%s', "
                             "while licscan json has '%s'" % (recipe_name, pkgv, json_pkgv))
                json_data_out.setdefault(recipe_name, json_data_in[recipe_name])
            else:
                bb.warn("Cannot find .json results file for '%s' package. Image specific .json results file will "
                        "be incomplete." % package_name)

    # Store image specific licscan results file, along with an agnostically named symlink to it
    results_file = os.path.join(deploy_dir, "%s%s.licscan.json" %
                                (d.getVar('IMAGE_NAME'), d.getVar('IMAGE_NAME_SUFFIX')))
    results_link = os.path.join(deploy_dir, "%s.licscan.json" % d.getVar('IMAGE_LINK_NAME'))
    bb.utils.mkdirhier(os.path.dirname(results_file))
    with open(results_file, 'w') as outputfile:
        outputfile.write(json.dumps(json_data_out, indent=4, sort_keys=True))
        outputfile.write('\n')
    if os.path.lexists(results_link):
        os.remove(results_link)
    os.symlink(os.path.basename(results_file), results_link)

    # Finally create analysis file too
    import subprocess
    command = 'licscantool -v -f -i ' + results_file
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         shell=True, universal_newlines=True, env={"COLUMNS": "240", "PATH": d.getVar('PATH')})
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        bb.fatal("Command '%s' returned %d\nStdout was: '%s'\nStderr was: '%s'"
                 % (command, p.returncode, stdout.strip(), stderr.strip()))
    licscantool_output = os.path.join(deploy_dir, "%s%s.licscantool.txt" %
                                      (d.getVar('IMAGE_NAME'), d.getVar('IMAGE_NAME_SUFFIX')))
    licscantool_link = os.path.join(deploy_dir, "%s.licscantool.txt" % d.getVar('IMAGE_LINK_NAME'))
    with open(licscantool_output, 'w') as outputfile:
        outputfile.write(stdout)
        outputfile.write(stderr)
    if os.path.lexists(licscantool_link):
        os.remove(licscantool_link)
    os.symlink(os.path.basename(licscantool_output), licscantool_link)
}
IMAGE_POSTPROCESS_COMMAND:append = " generate_image_licscan_files ;"
