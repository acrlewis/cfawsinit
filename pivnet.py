import requests
import json
import os
import urllib
from pkg_resources import parse_version


class Pivnet(object):

    def __init__(self, token=None, url_base=None):
        self.url_base = url_base or 'https://network.pivotal.io/api/v2'
        self.token = token or os.getenv('PIVNET_TOKEN')
        self.auth_header = {"Authorization": "Token {}".format(self.token)}
        self._validate_()

    def _validate_(self):
        """ ensure that you can logon to pivnet """
        if self.token is None:
            raise Exception("PIVNET_TOKEN env var is not exported")
        ans = self.get("{}/authentication".format(self.url_base))
        if ans.status_code != 200:
            raise Exception(ans.text)

    def get(self, url, **kwargs):
        return requests.get(url, headers=self.auth_header, **kwargs)

    def post(self, url, **kwargs):
        return requests.post(url, headers=self.auth_header, **kwargs)

    def latest(self, product, include_unreleased=False, version=None):
        """ https://network.pivotal.io/api/v2/products/elastic-runtime/releases """
        ans = self.get(
            "{}/products/{}/releases".format(self.url_base, product))
        releases = {parse_version(r['version'])                    : r for r in ans.json()['releases']}
        vers = releases.keys()
        if include_unreleased is False:
            vers = [v for v in vers if v.is_prerelease == False]

        maxver = max(vers)

        return releases[maxver]

    def productfiles(self, product, releaseNumber):
        return self.get("{}/products/{}/releases/{}/product_files".format(self.url_base, product, releaseNumber)).json()['product_files']

    """ 'https://network.pivotal.io/api/v2/products/elastic-runtime/releases/1530/product_files/2946/download'
    """
    def download(self, filedict):
        filename = os.path.basename(files[0]['aws_object_key'])
        resp = self.post(href(filedict, 'download'), allow_redirects=False)
        if resp.status_code != 302:
            raise Exception("Could not download " + href(filedict))

        return urllib.urlretrieve(resp.headers['location'], filename)


def href(obj, key):
    return obj['_links'][key]['href']


piv = Pivnet()
ver = piv.latest('elastic-runtime')
files = piv.productfiles('elastic-runtime', ver['id'])
dn = piv.download(files[0])
print dn
