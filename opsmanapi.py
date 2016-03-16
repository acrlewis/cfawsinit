from bs4 import BeautifulSoup
from robobrowser import RoboBrowser
from robobrowser import forms
import yaml
import requests
import requests.auth
import os
from mako.template import Template
from mako.runtime import Context
from StringIO import StringIO
import copy

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def get(*args, **kwargs):
    # bs4.find("span", {'class': 'version'})
    resp = requests. head(
        args[0]+"/uaa/login",
        verify=False,
        allow_redirects=False)
    # somewhat of a hack
    # pre api ops manager do not have /api/v0 endpoints
    if resp.status_code == 404:
        return OpsManApi(*args, **kwargs)
    else:
        return OpsManApi17(*args, **kwargs)


class OpsManApi(object):
    def __init__(self, url, username, password, private_key_file,
                 stack_vars, region='us-east-1'):
        self.url = url
        self.username = username
        self.password = password
        self.auth = requests.auth.HTTPBasicAuth(username, password)
        self.private_key = open(private_key_file, "rt").read()
        self.browser = RoboBrowser(history=True)
        self.var = stack_vars
        self.region = region
        if region == 'us-east-1':
            self.s3_endpoint = "https://s3.amazonaws.com"
        else:
            self.s3_endpoint = "https://s3-{}.amazonaws.com".format(region)
        self.action_map_file = THIS_DIR+'/opsman_mappings.yml'

    def setup(self):
        setup_data = {'setup[eula_accepted]': 'true',
                      'setup[password]': self.password,
                      'setup[password_confirmation]': self.password,
                      'setup[user_name]': self.username}
        resp = requests.post(
            self.url + "/api/setup",
            data=setup_data,
            verify=False,
            allow_redirects=False)

        if resp.status_code == 200:
            print "Admin user established", resp.json()
        elif resp.status_code == 422:
            jx = resp.json()
            if 'errors' in jx:
                raise Exception("Could not establish user: {}".
                                format(jx['errors']))
            else:
                print "Admin user is already established"
        return self

    def login(self):
        self.browser.open(self.url + "/login", verify=False)
        form = self.browser.get_form(action='/login')
        form['login[user_name]'].value = self.username
        form['login[password]'].value = self.password
        self.browser.submit_form(form)
        if self.browser.response.status_code >= 400:
            raise Exception("Error login in {}\n{}".
                            format(self.username, self.browser.response.text))
        return self

    def _is_configured(self):
        # check if this is already prepared
        resp = requests.get(
            self.url+"/api/installation_settings",
            verify=False,
            auth=self.auth)
        if resp.status_code == 200:
            jx = resp.json()
            if 'singleton_availability_zone_reference' in jx['products'][0]\
                    and jx['products'][0]['prepared'] is True:
                print "Product is already prepared"
                return True

        return False

    def process_action(self, action, mappings):
        if self._is_configured():
            return self

        self.browser.open(self.url + "/", verify=False)
        form = None
        suffix = mappings.get('__edit__', "/edit")
        self.browser.open(self.url + "/" + action + suffix, verify=False)
        form = self.browser.get_form(action='/' + action)

        """
        for suffix in ["/new", "/edit"]:
            self.browser.open(self.url + "/" + action + suffix, verify=False)
            raise Exception()
            form = self.browser.get_form(action='/' + action)
            if form is not None:
                break
        """
        if form is None:
            raise Exception("Could not find form for action="+action)

        # forms use ruby hash style params
        print form
        for k, v in mappings.items():
            if k.startswith("__"):
                continue
            if k not in form.keys() and "__force__" in mappings:
                field = forms.form._parse_fields(
                    BeautifulSoup('<input type="text" name="{}" />'.format(k))
                )[0]
                form.add_field(field)

            form[k].value = v
            print k, "=", v

        print form
        self.browser.submit_form(form)
        soup = BeautifulSoup(self.browser.response.text)
        # check if errors-block class is there in the output
        # ops manager sometime returns a 200 with and errors block
        # in html
        # HACK warning
        errblock = soup.select('.errors-block')

        if self.browser.response.status_code >= 400 or len(errblock) > 0:
            if '__IGNORE_ERROR__' not in mappings or \
                    mappings['__IGNORE_ERROR__'] not in errblock[0].text:
                raise Exception("Error submitting form " +
                                self.browser.response.text)

        return self

    def _load_mappings(self, filename):
        """
        load mappings and hydrate using self, stack_vars
        """
        mappings = yaml.load(open(filename, 'rt'))
        for mapping in mappings:
            mp = mapping.values()[0]
            for key, val in mp.items():
                if isinstance(val, (bool, int, long)):
                    continue
                if val.startswith("$."):
                    attrib = val[2:]
                    if hasattr(self, attrib):
                        mp[key] = getattr(self, attrib)
                    else:
                        raise Exception(val + " Is not provided"
                                        " as a mapping variable")
                elif val.startswith("$"):
                    attrib = val[1:]
                    if attrib in self.var:
                        mp[key] = self.var[attrib]
                    else:
                        raise Exception(val + " Is not provided"
                                        " as a stack output variable")
        return mappings

    def configure(self, filename=None, action=None):
        filename = filename or self.action_map_file

        mappings = self._load_mappings(filename)
        for mapping in mappings:
            ac, mp = mapping.items()[0]
            if action is None or action == ac:
                self.process_action(ac, mp)

        self.apply_changes()
        return self

    def apply_changes(self):
        print "Applying Changes"
        self.browser.open(self.url, verify=False)
        soup = BeautifulSoup(self.browser.response.text)
        fx = soup.find('meta', {"name": 'csrf-token'})
        csrf_token = fx.attrs["content"]

        rsp = self.browser.session.put(self.url+"/install",
                                       data={'authenticity_token': csrf_token})

        if rsp.status_code == 422 and \
                'Ignore errors and start the install' in rsp.text:
            # This happens because of the icmp error
            sp = BeautifulSoup(rsp.text)
            inst_form = sp.find("form", {"action": "/install"})
            if inst_form is None:
                raise Exception("Unable to complete installation")
            self.browser.submit_form(forms.form.Form(inst_form))


class CFAuthHandler(requests.auth.AuthBase):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.uaa = None

    def __call__(self, req):
        if self.uaa is None:
            url = req.url[:-len(req.path_url)]
            self.uaa = self._uaa(url)

        req.headers['Authorization'] = "Bearer "+self.uaa['access_token']
        return req

    def _uaa(self, url):
        resp = requests.post(
            url+"/uaa/oauth/token",
            verify=False,
            data={'grant_type': 'password',
                  'username': self.username,
                  'password': self.password},
            auth=('opsman', ''))

        if resp.status_code != 200:
            raise Exception("Unable to authenticate "+resp.text)

        return resp.json()


def getUAA_Auth_Header(username, password, url):
    resp = requests.post(
        url+"/uaa/oauth/token",
        verify=False,
        data={'grant_type': 'password',
              'username': username,
              'password': password},
        auth=('opsman', ''))

    if resp.status_code != 200:
        raise Exception("Unable to authenticate "+resp.text)

    return "Bearer "+resp.json()['access_token']


class OpsManApi17(OpsManApi):

    def __init__(self, *args, **kwargs):
        super(OpsManApi17, self).__init__(*args, **kwargs)
        # self.action_map_file = THIS_DIR+'/opsman_mappings17.yml'
        self.action_map_file = THIS_DIR+'/installation-aws-1.7.yml'

    def setup(self):
        setup_data = {
            'setup[eula_accepted]': 'true',
            'setup[identity_provider]': 'internal',
            'setup[decryption_passphrase]': self.password,
            'setup[decryption_passphrase_confirmation]': self.password,
            'setup[admin_password]': self.password,
            'setup[admin_password_confirmation]': self.password,
            'setup[admin_user_name]': self.username}

        resp = requests.post(
            self.url + "/api/v0/setup",
            data=setup_data,
            verify=False,
            allow_redirects=False)

        if resp.status_code == 200:
            print "Admin user established", resp.json()
        elif resp.status_code == 422:
            jx = resp.json()
            if 'errors' in jx:
                raise Exception("Could not establish user: {}".
                                format(jx['errors']))
            else:
                print "Admin user is already established"
        return self

    def login(self):
        self.auth = CFAuthHandler(self.username, self.password)
        resp = requests.get(
            self.url+"/api/v0/api_version",
            verify=False,
            auth=self.auth)
        if resp.status_code >= 400:
            raise Exception("Error login in {}\n{}".
                            format(self.username, self.browser.response.text))
        return self

    def configure(self, filename=None, action=None, force=False):
        if not force and self._is_configured():
            return self

        filename = filename or self.action_map_file
        template = Template(filename=filename)
        buf = StringIO()
        dct = copy.copy(self.var)
        self.private_key = self.private_key.replace('\n', '\n        ')
        dct['v'] = self
        ctx = Context(buf, **dct)
        template.render_context(ctx)
        yamlfile = buf.getvalue()
        files = {'installation[file]':
                 ('installation-integration-minimal.yml',
                     yamlfile, 'text/yaml')}
        resp = requests.post(
            self.url+"/api/installation_settings",
            files=files,
            verify=False,
            auth=self.auth)
        if resp.status_code != 200:
            raise Exception("Unable to configure "+resp.text)

        self.apply_changes()

        return self

    def apply_changes(self):
        print "Applying Changes"
        resp = requests.post(
            self.url+'/api/v0/installation',
            verify=False,
            data={'ignore_warnings': True},
            auth=self.auth)
        if resp.status_code != 200:
            raise Exception("Unable to start install, "+resp.text)
