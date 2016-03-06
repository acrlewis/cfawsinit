from bs4 import BeautifulSoup
from robobrowser import RoboBrowser


class OpsManApi(object):
    URIs = [("infrastructure/iaas_configuration", {u'utf': u'utf8', u'authenticity_toke': u'authenticity_token', 
        u'encrypted': u'iaas_configuration[encrypted]', 
        u'region': u'iaas_configuration[region]', 
        u'secret_access_key': u'iaas_configuration[secret_access_key]', 
        u'_metho': u'_method', u'key_pair_name': u'iaas_configuration[key_pair_name]', 
        u'ssh_private_key': u'iaas_configuration[ssh_private_key]', 
        u'access_key_id': u'iaas_configuration[access_key_id]', 
        u'security_group': u'iaas_configuration[security_group]', 
        u'vpc_id': u'iaas_configuration[vpc_id]'}),
            ("infrastructure/director_configuration", {u'access_key': u'director_configuration[s3_blobstore_options][access_key]', u'password': u'director_configuration[external_database_options][password]', u'endpoint': u'director_configuration[s3_blobstore_options][endpoint]', u'utf': u'utf8', u'database': u'director_configuration[external_database_options][database]', u'authenticity_toke': u'authenticity_token', u'user': u'director_configuration[external_database_options][user]', u'host': u'director_configuration[external_database_options][host]', u'metrics_ip': u'director_configuration[metrics_ip]', u'port': u'director_configuration[external_database_options][port]', u'_metho': u'_method', u'bucket_name': u'director_configuration[s3_blobstore_options][bucket_name]', u'blobstore_type': u'director_configuration[blobstore_type]', u'secret_key': u'director_configuration[s3_blobstore_options][secret_key]', u'ntp_servers_string': u'director_configuration[ntp_servers_string]', u'database_type': u'director_configuration[database_type]', u'max_threads': u'director_configuration[max_threads]', u'resurrector_enabled': u'director_configuration[resurrector_enabled]'}),
            ("infrastructure/availability_zones", {u'authenticity_toke': u'authenticity_token', u'_metho': u'_method', u'guid': u'availability_zones[availability_zones][][guid]', u'utf': u'utf8', u'iaas_identifier': u'availability_zones[availability_zones][][iaas_identifier]'}),
            ("infrastructure/director/availability_zone_assignment", {u'authenticity_toke': u'authenticity_token', u'_metho': u'_method', u'singleton_availability_zone': u'director_availability_zone_assignments[singleton_availability_zone]', u'utf': u'utf8'}),
            ("infrastructure/networks", {u'subnet': u'network[networks][][subnet]', u'utf': u'utf8', u'name': u'network[networks][][name]', u'authenticity_toke': u'authenticity_token', u'iaas_network_identifier': u'network[networks][][iaas_network_identifier]', u'_metho': u'_method', u'reserved_ip_ranges': u'network[networks][][reserved_ip_ranges]', u'dns': u'network[networks][][dns]', u'guid': u'network[networks][][guid]', u'gateway': u'network[networks][][gateway]'}),
            ("infrastructure/director/single_network_assignment", {u'authenticity_toke': u'authenticity_token', u'_metho': u'_method', u'utf': u'utf8', u'network': u'director_single_network_assignments[network]'})]

    def __init__(self, url, username, password, private_key_file, stack_vars):
        self.url = url
        self.username = username
        self.password = password
        self.private_key_file = private_key_file
        self.browser = RoboBrowser(history=True)
        self.var = stack_vars

    def login(self):
        self.browser.open(self.url+"/login", verify=False)
        form = self.browser.get_form(action='/login')
        form['login[user_name]'].value = self.username
        form['login[password]'].value = self.password
        self.browser.submit_form(form)
        if self.browser.response.status_code >= 400:
            raise Exception("Error login in {}\n{}".format(self.username,
                            self.browser.response.text))

    def process_action(self, action, mappings):
        self.browser.open(self.url+"/"+action+"/edit", verify=False)
        form = self.browser.get_form(action='/'+action)
        # forms use ruby hash style params
        fields = {k.rpartition('[')[-1][:-1]: k for k in form.keys()}
        print fields
        for k, v in mappings.items():
            if k in fields:
                form[fields[k]].value = v

        self.browser.submit_form(form)
        soup = BeautifulSoup(self.browser.response.text)
        # check if errors-block class is there in the output
        # HACK warning
        errblock = soup.select('.errors-block')
        if len(errblock) > 0:
            raise Exception("Error while processing {}\n{}".
                            format(action, str(errblock[0])))

    def _make_form_mappings(self, vmappings, mappings):
        ret = {}
        ret.update(mappings)
        ret.update({k: self.var[v] for k, v in vmappings.items()})
        return ret

    def process_iaas_configuration(self):
        vmappings = {"access_key_id": "PcfIamUserAccessKey",
                "secret_access_key": "PcfIamUserSecretAccessKey",
                "vpc_id": "PcfVpc",
                "security_group": "PcfVmsSecurityGroupName",
                "key_pair_name": "PcfKeyPairName"}
        mappings = {
                "region": "us-east-1",
                "ssh_private_key": open(self.private_key_file, "rt").read()}
        self.process_action("infrastructure/iaas_configuration",
                self._make_form_mappings(vmappings, mappings))

"""
In [218]: ops1['PcfVmsSecurityGroupName'] = list(ec2.security_groups.filter(GroupIds=[ops1['PcfVmsSecurityGroupId']]))[0].group_name

In [219]: ops = { v['OutputKey']: v['OutputValue'] for v in stx.outputs}
"""
