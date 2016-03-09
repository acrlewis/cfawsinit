from bs4 import BeautifulSoup
from robobrowser import RoboBrowser
from robobrowser import forms
import yaml
import requests


class OpsManApi(object):
    def __init__(self, url, username, password, private_key_file,
                 stack_vars, region='us-east-1'):
        self.url = url
        self.username = username
        self.password = password
        self.private_key = open(private_key_file, "rt").read()
        self.browser = RoboBrowser(history=True)
        self.var = stack_vars
        self.region = region
        if region == 'us-east-1':
            self.s3_endpoint = "https://s3.amazonaws.com"
        else:
            self.s3_endpoint = "https://s3-{}.amazonaws.com".format(region)

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

    def process_action(self, action, mappings):

        form = None
        for suffix in ["/new", "/edit"]:
            self.browser.open(self.url + "/" + action + suffix, verify=False)
            form = self.browser.get_form(action='/' + action)
            if form is not None:
                break

        if form is None:
            raise Exception("Could not find form for action="+action)

        # forms use ruby hash style params
        print form
        for k, v in mappings.items():
            if k.startswith("__"):
                continue
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

    def load_mappings(self, filename):
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

    def process_mappings(self, filename, action=None):
        mappings = self.load_mappings(filename)
        for mapping in mappings:
            ac, mp = mapping.items()[0]
            if action is None or action == ac:
                self.process_action(ac, mp)

        return self

    def apply_changes(self):
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


"""
In [218]: ops1['PcfVmsSecurityGroupName'] = list(ec2.security_groups.filter(GroupIds=[ops1['PcfVmsSecurityGroupId']]))[0].group_name

In [219]: ops = { v['OutputKey']: v['OutputValue'] for v in stx.outputs}
"""
