from boto3.session import Session
import botocore.exceptions
import uuid
import yaml
from datetime import datetime
import os
import time

import pivnet
import opsmanapi


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
                 {'Name': 'tag:stack-name', 'Values': [opts['stack-name']]}]))
    if len(insts) == 1:
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
        )
    inst.wait_until_exists()
    inst.create_tags(
        Tags=[{'Key': 'Name', 'Value': 'Ops Manager'},
              {'Key': 'stack-name', 'Value': opts['stack-name']}])
    return inst



def configure_ops_manager(opts, stack_vars, ops_manager_inst):
    ops = opsmanapi.OpsManApi(
            "https://ec2-54-88-79-182.compute-1.amazonaws.com",
            "admin",
            "keepitsimple",
            "/Users/mjog/.ssh/id_rsa",
            ops1)


class TimeoutException(Exception):
    pass


def wait_for_stack_ready(st, timeout):
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


def deloy(prepared_file, timeout=300):
    """
    Topline driver
    idempotent
    """
    opts = yaml.load(open(prepared_file, 'rt'))

    if '__PREPARED__' not in opts:
        raise Exception("using 'unprepared' file to deploy."
                        " First run prepare on it")

    session = Session(profile_name=None,
                      region_name=opts['region'])
    ec2 = session.resource("ec2")
    cff = session.resource("cloudformation")

    stack = create_stack(opts, ec2, cff)
    # ensure that stack is ready
    wait_for_stack_ready(stack, timeout)

    stack_vars = get_stack_outputvars(stack, ec2)
    ops_manager_inst = launch_ops_manager(opts, stack_vars, ec2)

    # ensure that ops manager is ready to receive requests
    configure_ops_manager(opts, stack_vars, ops_manager_inst)


def resolve_versions(token, opsman, ert):
    """
    resolve and return 2 new dicts which will replace the old
    """
    piv = pivnet.Pivnet(token=token)
    opsman_ver = piv.latest('ops-manager',
                            opsman['beta-ok'],
                            opsman['version'])

    opsman_out = {'version': opsman_ver['version'],
                  'beta-ok': opsman['beta-ok']}
    elastic_runtime_ver = piv.latest('elastic-runtime',
                                     ert['beta-ok'],
                                     ert['version'])
    ert_out = {'version': elastic_runtime_ver['version'],
               'beta-ok': ert['beta-ok']}

    files = piv.productfiles('elastic-runtime', elastic_runtime_ver['id'])

    cloudformation = next((f for f in files
                          if 'cloudformation script for aws'
                          in f['name'].lower()), None)
    if cloudformation is None:
        raise Exception(
            "Could not find link for 'cloudformation template for aws' in "
            + str(elastic_runtime_ver)+" "+files)
    ert_out['cloudformation-template-url'] = \
        pivnet.href(cloudformation, 'download')

    filename, dn = piv.download(elastic_runtime_ver, cloudformation)
    ert_out['cloudformation-template'] = filename
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
    infile['random'] = str(uuid.uuid4())[:6]
    stack_name = infile['email'].partition('@')[0] + "-pcf-" + infile['random']
    date = datetime.utcnow()

    outfile = {k: v.format(**infile)
               if hasattr(v, 'format')
               else v for k, v in infile.items()}
    outfile['stack-name'] = stack_name
    outfile['date'] = date

    opsman_ver, elastic_runtime_ver =\
        resolve_versions(infile['PIVNET_TOKEN'],
                         infile['ops-manager'],
                         infile['elastic-runtime'])

    outfile['ops-manager'] = opsman_ver
    outfile['elastic-runtime'] = elastic_runtime_ver

    ec2 = Session(profile_name=None,
                  region_name=outfile['region']).resource("ec2")

    ami_name = "pivotal-ops-manager-v" + opsman_ver['version']
    opsman_ver['ami-id'] = find_ami(ec2, ami_name)
    opsman_ver['ami-name'] = ami_name

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

    yaml.safe_dump(outfile, open(outfilename, 'wt'),
                   indent=2, default_flow_style=False)
    return outfile


PCF_AWS_OWNERID = '364390758643'


def find_ami(ec2, ami_name):
    amis = list(
        ec2.images.filter(
            Owners=[PCF_AWS_OWNERID],
            Filters=[{'Name': 'name', 'Values': [ami_name]}]))

    if len(amis) == 0:
        raise Exception("unable to find ami for " + ami_name)

    ami = amis[0]

    print "Selected", ami.image_id, ami.name
    return ami.image_id


def verify_ssh_key(ec2, key_file, ec2_keypair_name):
    """
    ensure that the keypair matches
    """
    info = ec2.KeyPair(ec2_keypair_name)
    print info.key_fingerprint
    # TODO verify this fingerprint with the key on disk
    open(os.path.expanduser(key_file), 'rt').read()
