### This README file contains information on the contents of the meta-licscan layer

The meta-licscan layer provides source code license analysis for Yocto based OS distributions.
Please see the corresponding sections below for details.

### Dependencies

URI: [git://git.yoctoproject.org/poky](https://git.yoctoproject.org/cgit/cgit.cgi/poky)<br>
branch: gatesgarth

### Contributing

Open pull request at [https://github.com/vaisala-oss/meta-licscan/pulls](https://github.com/vaisala-oss/meta-licscan/pulls)

### Layer maintainers

Niko Mauno \<<niko.mauno@vaisala.com>\>

### License

See [COPYING.MIT](COPYING.MIT)

## Table of Contents

 I.   About meta-licscan
 II.  Host OS requirements
 III. Usage
 IV.  Studying license analysis results

## I. About meta-licscan

This meta layer is a complementary facility for disambiguating software license compliance standing of devices that contain software artifacts built from source code with Yocto framework.
It facilitates generation of .json files containing both source code license analysis results (on a per-file basis) as well as relevant parts of Yocto metadata related to prementioned software artifacts.

A command line utility for studying image-wide and package-specific license analysis results from prementioned .json files is also provided.

## II. Host OS requirements

Requires [python-magic](https://pypi.org/project/python-magic/) installed on host OS.
The dependency can be satisfied e.g. with pip3 on Debian OS followingly

    sudo apt install python3-pip
    sudo pip3 install python-magic

## III. Usage

### Enabling build-time license analysis

Deploy the meta layer by adding meta-licscan to `BBLAYERS` in `<BUILDDIR>`/conf/bblayers.conf,
which can be achieved e.g. by issuing

    bitbake-layers add-layer meta-licscan

This will add the custom `do_licscan()` and `emit_pkgdata_licscan()` tasks to bitbake work flow for recipes generating target device specific packages.
Former task performs the actual license analysis, while latter adds relevant metadata fields before storing the final file.

Furthermore a `generate_image_licscan_files()` task is added to `IMAGE_POSTPROCESS_COMMAND` set,
which induces generation of image-specific licscan results files in licscan.json and licscantool.txt formats,
containing licscan results of recipes that provide the packages that are installed into the image specific rootfs.

Recipe-specific results are stored in JSON formatted files under `<PKGDATA_DIR>`/licscan/`<scanner>`/ (e.g. `<BUILDDIR>`/tmp/pkgdata/qemux86/licscan/nomossa/glibc.json),
and image-specific results in `<DEPLOY_DIR_IMAGE>`/`<IMAGE_NAME>`.licscan.json.

### Tuning the set of packages to scan

The scope of packages/recipes to run licenses scanner(s) against can be modified to better suit individual purposes.
This can be achieved by tuning variables which have base declaration in beginning of `<BUILDDIR>`/meta-licscan/classes/licscan.bbclass file.

### Avoiding scanning of specific recipes(s)

For example, to avoid altogether analyzing huge source code trees of Linux kernel and GNU C Library, respectively, one can add following lines to `<BUILDDIR>`/conf/local.conf file:

    LICSCAN_SKIP_INHERIT:append = " kernel"
    LICSCAN_SKIP_PN:append = " glibc glibc-locale glibc-mtrace glibc-scripts"

### Scanning only specific recipe(s)

In order to analyze source codes of only specific recipe(s), you can set `LICSCAN_RECIPES` to appropriate value in your `<BUILDDIR>`/conf/local.conf file.
For instance in order to scan only coreutils and util-linux source code:

    LICSCAN_RECIPES = "coreutils util-linux"

### Allowing incomplete image-specific results file

Note also that image specific .json generation will fail if all necessary recipe-specific licscan .json files are not available.
This can be avoided by declaring

    LICSCAN_INCOMPLETE_IMAGE_JSON_WARN_ONLY = "yes"

in `<BUILDDIR>`/conf/local.conf in which case each missing .json file produces mere bitbake warning about incomplete image specific .json instead.

## IV. Studying license analysis results

A command line method for studying license analysis results is provided by using `licscantool` program.

Note that when `licscantool` prints license information defined in recipes, it uses `SPDXLICENSEMAP` translated license labels which are declared in `meta/conf/licenses.conf` file.

### Examples

Example 1. To study image-specific results

    ../meta-licscan/scripts/licscantool -i <image_name>

Example 2. Studying package-specific results

    ../meta-licscan/scripts/licscantool -p <package_name> [<package_name2> <package_name3> ...]

Example 3. Show comprehensive image-specific results (combined information about an image and all packages it contains) from image-specific licscan.json and manifest files

    ../meta-licscan/scripts/licscantool -f -vvv -i path/to/<image_name>.licscan.json

Note that the first two examples resort to probing details from bitbake context while the last example doesn't (ie. Example 3 works also without sourcing oe-init-build-env first).
