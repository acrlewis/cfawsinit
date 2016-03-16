from boto3.session import Session
import botocore.exceptions
import uuid
import yaml
from datetime import datetime
import os
import time
import requests
import requests.exceptions
import pivnet
import opsmanapi
import sys


THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def get_stack_outputvars(stack, ec2):
    ops = {v['OutputKey']: v['OutputValue'] for v in stack.outputs}
    # group name is needed in a few places
    ops['PcfVmsSecurityGroupName'] = list(
        ec2.security_groups.filter(
            GroupIds=[ops['PcfVmsSecurityGroupId']]))[0].group_name
    return ops


def get_stack(stackName, cff):
    try:
        stt = list(cff.stacks.filter(StackName=stackName))
        return stt[0]
    except botocore.exceptions.ClientError as e:
        if "{} does not exist".format(stackName) in\
                e.response['Error']['Message']:
            return None
        else:
            raise


def create_stack(opts, ec2, cff, timeout=300):
    """
    ensure idempotency

    returns a stack that is either in
    'CREATE_COMPLETE' or 'CREATE_IN_PROGRESS'
    """
    st = get_stack(opts['stack-name'], cff)

    if st is not None:
        msg = "stack {} is in state {}".format(st.name, st.stack_status)
        if st.stack_status in ('CREATE_IN_PROGRESS', 'CREATE_COMPLETE'):
            print msg
            return st
        else:
            raise Exception(msg)

    # stack does not exist create it
    args = {"01NATKeyPair": opts['ssh_key_name'],
            "05RdsUsername": opts['rds-username'],
            "06RdsPassword": opts['rds-password'],
            "07SSLCertificateARN": opts['ssl_cert_arn']}
    paramaters = [{"ParameterKey": k, "ParameterValue": v,
                   "UsePreviousValue": True} for k, v in args.items()]
    tags = [{"Key": "email", "Value": opts["email"]}]
    return cff.create_stack(
        StackName=opts['stack-name'],
        TemplateBody=open(opts['elastic-runtime']['cloudformation-template'],
                          'rt').read(),
        Tags=tags,
        Parameters=paramaters,
        Capabilities=['CAPABILITY_IAM'])


def launch_ops_manager(opts, stack_vars, ec2):
    """
    given a stack in CREATE_COMPLETE launch an ops manager
    """
    insts = list(ec2.instances.filter(
        Filters=[{'Name': 'tag:Name', 'Values': ['Ops Manager']},
                 {'Name': 'tag:stack-name', 'Values': [opts['stack-name']]},
                 {'Name': 'instance-state-name', 'Values': ['running']}]))
    if len(insts) == 1:
        print "Found running ops manager ", insts[0].id
        return insts[0]
    elif len(insts) > 1:
        raise Exception("Several Ops Managers running {} for stack {}".format(
            insts, opts['stack-name']))

    # no instance is running, create one
    inst = ec2.create_instances(
        ImageId=opts['ops-manager']['ami-id'],
        MinCount=1,
        MaxCount=1,
        KeyName=stack_vars['PcfKeyPairName'],
        InstanceType='m3.large',
        NetworkInterfaces=[
            {'DeviceIndex': 0,
             'SubnetId': stack_vars['PcfPublicSubnetId'],
             'Groups': [stack_vars['PcfOpsManagerSecurityGroupId']],
             'AssociatePublicIpAddress': True}],
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1",
             "Ebs": {"VolumeSize": 100,
                     "VolumeType": "gp2"
                     }
             }]
        )[0]
    inst.wait_until_exists()
    inst.create_tags(
        Tags=[{'Key': 'Name', 'Value': 'Ops Manager'},
              {'Key': 'stack-name', 'Value': opts['stack-name']}])
    print "Waiting for instance to start", inst.id
    inst.wait_until_running()
    return inst


def configure_ops_manager(opts, stack_vars, inst):
    ops = opsmanapi.get(
        "https://"+inst.public_dns_name,
        opts['opsman-username'],
        opts['opsman-password'],
        os.path.expanduser(opts['ssh_private_key_path']),
        stack_vars,
        opts['region'])

    ops.setup().login()
    ops.configure()
    return ops


class TimeoutException(Exception):
    pass


def wait_while(condition, refresh=lambda: True):
    def waitfor(timeout):
        waited = 0
        SLEEPTIME = 5

        refresh()
        if not condition():
            return True

        while waited < timeout and condition():
            time.sleep(SLEEPTIME)
            waited += SLEEPTIME
            refresh()
        if condition():
            raise TimeoutException()

    return waitfor


def wait_for_stack_ready(st, timeout):
    waiter = wait_while(
        lambda: st.stack_status == 'CREATE_IN_PROGRESS',
        lambda: st.reload())
    waiter(timeout)

    if st.stack_status == 'CREATE_COMPLETE':
        return True

    raise Exception("Stack {} is in bad state {}".format(
        st.name, st.stack_status))


def wait_for_stack_ready1(st, timeout):
    waited = 0
    SLEEPTIME = 5
    st.reload()
    if st.stack_status == 'CREATE_IN_PROGRESS':
        print "Waiting for {} stack to be ready".format(st.name)

    while waited < timeout and st.stack_status == 'CREATE_IN_PROGRESS':
        time.sleep(SLEEPTIME)
        waited += SLEEPTIME
        st.reload()

    if st.stack_status == 'CREATE_COMPLETE':
        return True

    if st.stack_status == 'CREATE_IN_PROGRESS':
        raise TimeoutException(st.name + ' In CREATE_IN_PROGRESS')

    raise Exception("Stack {} is in bad state {}".format(
        st.name, st.stack_status))


def wait_for_opsman_ready(inst, timeout):
    def shoud_wait():
        try:
            resp = requests.head(
                "https://{}/".format(inst.public_dns_name),
                verify=False, timeout=1)
            return resp.status_code >= 400
        except requests.exceptions.RequestException as ex:
            pass
        except requests.HTTPError as ex:
            print ex
        return True

    waiter = wait_while(shoud_wait)
    return waiter(timeout)


def deploy(prepared_file, timeout=300):
    """
    Topline driver
    idempotent
    """
    opts = yaml.load(open(prepared_file, 'rt'))

    if '__PREPARED__' not in opts:
        raise Exception("using 'unprepared' file to deploy."
                        " First run prepare on it")

    session = Session(profile_name=opts.get('profile_name'),
                      region_name=opts['region'])
    ec2 = session.resource("ec2")
    cff = session.resource("cloudformation")

    stack = create_stack(opts, ec2, cff)
    # ensure that stack is ready
    wait_for_stack_ready(stack, timeout)

    stack_vars = get_stack_outputvars(stack, ec2)
    ops_manager_inst = launch_ops_manager(opts, stack_vars, ec2)

    # ensure that ops manager is ready to receive requests
    wait_for_opsman_ready(ops_manager_inst, timeout)
    configure_ops_manager(opts, stack_vars, ops_manager_inst)

    ert_file = upload_ert_to_ops_manager(ops_manager_inst, opts)
    # ensure that ops manager is ready to receive request
    install_ert_to_ops_manager(ops_manager_inst, opts, ert_file)


def execute_on_opsman(ops_manager_inst, opts, cmd):
    from sh import ssh
    ssh("-i {} ".format(opts['ssh_private_key_path']),
        "ubuntu@"+ops_manager_inst.public_dns_name,
        cmd)


def upload_ert_to_ops_manager(ops_manager_inst, opts):
    """
    logon to opsman and download the
    ert file from pivnet

    it runs the command *from* ops manager
    so it can be locally uploaded
    """
    filename = "cf-ert.{}.pivotal".format(opts['elastic-runtime']['version'])
    CMD = ""
    if '_NO_CACHE_' not in os.environ:
        CMD += '[[ -e {filename} ]] || '
    CMD += (
        'wget -O {filename} --post-data="" '
        '--header="Authorization: Token {token}" {url}')

    cmd = CMD.format(
        filename=filename,
        token=opts['PIVNET_TOKEN'],
        url=opts['elastic-runtime']['image-file-url'])

    from sh import ssh
    print "Downloading ERT {} onto the opsmanager".format(filename)
    ssh(
        "ubuntu@"+ops_manager_inst.public_dns_name,
        cmd,
        i=opts['ssh_private_key_path'])
    return filename


def install_ert_to_ops_manager(ops_manager_inst, opts, ert_file):
    CMD = (
        'curl -v -k https://localhost/api/v0/products '
        '-F \'product[file]=@{filename}\' '
        '-X POST '
        '-H "Authorization: {auth}"')

    cmd = CMD.format(
        filename=ert_file,
        auth=opsmanapi.getUAA_Auth_Header(
            opts['opsman-username'],
            opts['opsman-password'],
            "https://" + ops_manager_inst.public_dns_name))
    from sh import ssh
    ssh(
        "ubuntu@"+ops_manager_inst.public_dns_name,
        cmd,
        i=opts['ssh_private_key_path'])


AMI_PREFIX = "pivotal-ops-manager-v"
PCF_AWS_OWNERID = '364390758643'


def resolve_versions(token, opsman, ert, ec2):
    """
    resolve and return 2 new dicts which will replace the old
    """
    piv = pivnet.Pivnet(token=token)
    opsman_vers = piv._latest(
        'ops-manager',
        opsman['beta-ok'],
        opsman['version'])

    amidict = {
        e.name[len(AMI_PREFIX):]: e for e in
        ec2.images.filter(
            Owners=[PCF_AWS_OWNERID])
        if e.name.startswith(AMI_PREFIX)}

    ami = next(
        amidict[vv['version']] for vv in opsman_vers
        if vv['version'] in amidict)

    opsman_out = {'version': opsman_vers[0]['version'],
                  'beta-ok': opsman['beta-ok'],
                  'ami-id': ami.image_id,
                  'ami-name': ami.name}
    elastic_runtime_ver = piv.latest('elastic-runtime',
                                     ert['beta-ok'],
                                     ert['version'])
    ert_out = {'version': elastic_runtime_ver['version'],
               'beta-ok': ert['beta-ok']}

    files = piv.productfiles('elastic-runtime', elastic_runtime_ver['id'])

    cloudformation = next((f for f in files
                          if 'cloudformation script for aws'
                          in f['name'].lower()), None)
    if cloudformation is not None:
        filename, dn = piv.download(elastic_runtime_ver, cloudformation)
        ert_out['cloudformation-template-version'] = \
            elastic_runtime_ver['version']
    else:
        print ("Could not find cloud formation template for ver =",
               elastic_runtime_ver)
        print "Trying latest available"
        vv = piv.latest_file(
            'elastic-runtime',
            ert['beta-ok'],
            ert['version'],
            selector=lambda x:
            'cloudformation script for aws' in x['name'].lower())
        if vv is not None:
            vr, cloudformation = vv
            filename, dn = piv.download(vr, cloudformation)
            ert_out['cloudformation-template-version'] = vr['version']
        else:
            raise Exception(
                ("Could not find link for "
                 "'cloudformation template for aws' in {} {}".format(
                     elastic_runtime_ver, files)))

    ert_out['cloudformation-template'] = filename
    ert_out['cloudformation-template-url'] = \
        pivnet.href(cloudformation, 'download')
    er = next((f for f in files if 'PCF Elastic Runtime' == f['name']), None)
    if er is None:
        raise Exception(
            "Could not find link for 'PCF Elastic Runtime' in "
            + str(elastic_runtime_ver) + " "+files)
    ert_out['image-file-url'] = \
        pivnet.href(er, 'download')

    return opsman_out, ert_out


def prepare_deploy(infilename, outfilename):
    """
    given infile.yml
    fully resolve it and produce outfile.yml
    """
    infile = yaml.load(open(infilename, 'rt'))
    if 'uid' not in infile:
        infile['uid'] = str(uuid.uuid4())[:6]
    stack_name = infile['email'].partition('@')[0] + "-pcf-" + infile['uid']
    date = datetime.utcnow()

    outfile = {k: v.format(**infile)
               if hasattr(v, 'format')
               else v for k, v in infile.items()}
    outfile['stack-name'] = stack_name
    outfile['date'] = date

    ec2 = Session(profile_name=None,
                  region_name=outfile['region']).resource("ec2")

    opsman_ver, elastic_runtime_ver =\
        resolve_versions(infile['PIVNET_TOKEN'],
                         infile['ops-manager'],
                         infile['elastic-runtime'],
                         ec2)

    outfile['ops-manager'] = opsman_ver
    outfile['elastic-runtime'] = elastic_runtime_ver

    verify_ssh_key(ec2, outfile['ssh_private_key_path'],
                   outfile['ssh_key_name'])

    outfile['__PREPARED__'] = True

    def set_if_empty(key, val):
        if key not in outfile:
            outfile[key] = val

    # default params
    set_if_empty('rds-username', 'dbadmin')
    set_if_empty('rds-password', 'keepitsimple')
    set_if_empty('opsman-username', 'admin')
    set_if_empty('opsman-password', 'keepitsimple')

    yamlout = open(outfilename, 'wt')\
        if outfilename is not None \
        else sys.stdout

    yaml.safe_dump(outfile, yamlout,
                   indent=2, default_flow_style=False)
    return outfile


def verify_ssh_key(ec2, key_file, ec2_keypair_name):
    """
    ensure that the keypair matches
    """
    info = ec2.KeyPair(ec2_keypair_name)
    print info.key_fingerprint
    # TODO verify this fingerprint with the key on disk
    open(os.path.expanduser(key_file), 'rt').read()


def get_args():
    import argparse
    argp = argparse.ArgumentParser("awsdeploy [prepare|deploy]")
    argp.add_argument('--action', choices=["prepare", "deploy"], required=True)
    argp.add_argument('--cfg')
    argp.add_argument('--prepared-cfg')
    return argp


def validate_creds(opts):
    session = Session(profile_name=opts.get('profile_name'),
                      region_name=opts['region'])
    ec2 = session.resource("ec2")
    try:
        ec2.meta.client.describe_id_format()
    except botocore.exceptions.NoCredentialsError as ex:
        print "Missing ~/.aws/credentials ? missing profile_name from cfg file"
        print "http://boto3.readthedocs.org/en/latest/guide/configuration.html"
        print ex
        return False

    try:
        pivnet.Pivnet(token=opts['PIVNET_TOKEN'])
    except pivnet.AuthException as ex:
        print "Get API TOKEN from "
        print "https://network.pivotal.io/users/dashboard/edit-profile"
        print ex
        return False

    return True


def main(argv):
    args = get_args().parse_args(argv)

    cfg = args.cfg or args.prepared_cfg
    if cfg is None:
        print "One of --cfg or --prepared-cfg is required"
        return -1
    opts = yaml.load(open(cfg, 'rt'))

    if validate_creds(opts) is False:
        return -1

    if args.action == 'prepare':
        prepare_deploy(args.cfg, args.prepared_cfg)
    elif args.action == 'deploy':
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
