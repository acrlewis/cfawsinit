import requests
import os
import urllib
from pkg_resources import parse_version
import sys
import time


class AuthException(Exception):
    pass


class Pivnet(object):

    def __init__(self, token=None, url_base=None):
        self.url_base = url_base or 'https://network.pivotal.io/api/v2'
        self.token = token or os.getenv('PIVNET_TOKEN')
        self.auth_header = {"Authorization": "Token {}".format(self.token)}
        self._validate_()

    def _validate_(self):
        """ ensure that you can logon to pivnet """
        if self.token is None:
            raise AuthException("PIVNET_TOKEN env var is not exported")
        ans = self.get("{}/authentication".format(self.url_base))
        if ans.status_code != 200:
            raise AuthException(ans.text)

    def get(self, url, **kwargs):
        return requests.get(url, headers=self.auth_header, **kwargs)

    def post(self, url, **kwargs):
        return requests.post(url, headers=self.auth_header, **kwargs)

    def _latest(self, product, include_unreleased=False, version=None):
        """ https://network.pivotal.io
            /api/v2/products/elastic-runtime/releases
        """
        if version is not None and version.lower() == 'latest':
            version = None

        ans = self.get(
            "{}/products/{}/releases".format(self.url_base, product))
        releases = {parse_version(r['version']): r
                    for r in ans.json()['releases']}
        vers = releases.keys()
        if include_unreleased is False:
            vers = [v for v in vers if v.is_prerelease is False]

        if version is not None:
            vers = [v for v in vers if v.base_version.startswith(version)]

        if len(vers) == 0:
            raise Exception("No version matched product={},"
                            "v={}, {}".format(
                                product, version, releases.keys()))

        return [releases[v] for v in sorted(vers, reverse=True)]

    def latest(self, product, include_unreleased=False, version=None):
        """ https://network.pivotal.io
            /api/v2/products/elastic-runtime/releases
        """
        return self._latest(product, include_unreleased, version)[0]

    def latest_file(self, product, include_unreleased, version, selector):
        vers = self._latest(product, include_unreleased, version)

        for ver in vers:
            for fl in self.productfiles(product, ver['id']):
                if selector(fl):
                    return ver, fl

    def productfiles(self, product, releaseNumber):
        return self.get("{}/products/{}/releases/{}/product_files".format(
            self.url_base, product, releaseNumber)).json()['product_files']

    def files(self, product, releaseNumber):
        return self.get("{}/products/{}/releases/{}/product_files".format(
            self.url_base, product, releaseNumber)).json()

    def acceptEULA(self, verDict):
        # eula acceptance per spec
        print "Accepting EULA for the relase"
        resp = self.post(href(verDict, 'eula_acceptance'),
                         allow_redirects=False)
        if resp.status_code != 200:
            raise Exception("Could not auto accept eula" +
                            href(verDict, 'eula_acceptance') +
                            " " + str(resp.headers))

    """ 'https://network.pivotal.io/api/v2/products/
    elastic-runtime/releases/1530/product_files/2946/download'
    """
    def download(self, ver, filedict, filename=None):
        filename = filename or os.path.basename(filedict['aws_object_key'])
        resp = self.post(href(filedict, 'download'), allow_redirects=False)
        if resp.status_code == 451:
            self.acceptEULA(ver)
            resp = self.post(href(filedict, 'download'), allow_redirects=False)

        if resp.status_code != 302:
            raise Exception(
                "Could not download " +
                href(filedict, 'download') + " "
                + str(resp.headers))

        class _progress_hook(object):
            lpr = 10
            started = False
            tm = time.time()

            def __call__(self, nblocks, block_size, size):
                if self.started is False:
                    self.started = True
                    print " size: ", size
                if (100.0 * nblocks * block_size)/size > self.lpr:
                    tm_end = time.time()
                    print >> sys.stderr, self.lpr, " ({} kBps)".format(
                        int((nblocks * block_size)/(1000.0*(tm_end-self.tm)))),
                    self.lpr += 10

        print "\nDownloading ", filename,
        return filename, urllib.urlretrieve(
            resp.headers['location'], filename, _progress_hook())


def href(obj, key):
    return obj['_links'][key]['href']
