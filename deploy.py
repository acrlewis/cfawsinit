import botocore
from boto3.session import Session
import pivnet
import uuid


def validate_key(ssh_key_name):
    """
    check if the .pem file is associated with the keypair name
    """
    pass


def deploy(email, ssh_key_name, domain, version=None, create_hosted_zone=False, cert_arn=None, rds_user="dbadmin", rds_password="keepitsimple"):
    """
    validate ssh_key
    validate domain
    create zone
    create cert and get arn
    """
    validate_key(ssh_key_name)

"""
stx = deploy.create_stack('mjog', 'mjog@pivotal.io', './ert_cloudformation.json', 'arn:aws:iam::375783000519:server-certificate/mjogCertificate')
"""


def create_stack(key_pair, email, templateFile, cert_arn=None, rds_user="dbadmin", rds_password="keepitsimple"):
    cf = cloudformation(None, 'us-east-1')
    args = {"01NATKeyPair": key_pair,
            "05RdsUsername": rds_user,
            "06RdsPassword": rds_password,
            "07SSLCertificateARN": cert_arn}
    paramaters = [{"ParameterKey": k, "ParameterValue": v,
                   "UsePreviousValue": True} for k, v in args.items()]
    tags = [{"Key": "email", "Value": email}]
    name = email.partition('@')[0] + "-pcf-" + str(uuid.uuid4())[:6]
    return cf.create_stack(StackName=name,
                           TemplateBody=open(templateFile, 'rt').read(),
                           Tags=tags,
                           Parameters=paramaters,
                           Capabilities=['CAPABILITY_IAM'])


PCF_AWS_OWNERID = '364390758643'


def launch_ops_man(stack_name, ops_man_version=None, include_unreleased=False):
    """
    launch an ops manager AMI based on the given stack
    if version is not specified latest is used.
    """
    ec2conn = ec2(None, 'us-east-1')
    piv = pivnet.Pivnet()
    ver = piv.latest('ops-manager', include_unreleased, ops_man_version)
    ami_name = "pivotal-ops-manager-v" + ver['version']
    amis = list(
        ec2conn.images.filter(
            Owners=[PCF_AWS_OWNERID],
            Filters=[{'Name': 'name', 'Values': [ami_name]}]))

    if len(amis) == 0:
        raise Exception("unable to find ami for " + ami_name)

    ami = amis[0]

    print "Selected", ami.image_id, ami.name

    st = get_stack(stack_name)
    ops = get_stack_outputvars(st)

    inst = ec2conn.create_instances(
        ImageId=ami.id,
        MinCount=1,
        MaxCount=1,
        KeyName=ops['PcfKeyPairName'],
        InstanceType='m3.large',
        NetworkInterfaces=[{'DeviceIndex': 0,
                            'SubnetId': ops['PcfPublicSubnetId'],
                            'Groups': [ops['PcfOpsManagerSecurityGroupId']],
                            'AssociatePublicIpAddress': True}],
        BlockDeviceMappings=[{"DeviceName": "/dev/sda1",
                              "Ebs": {"VolumeSize": 100,
                                      "VolumeType": "gp2"
                                      }
                              }]
        )
    inst.wait_until_exists()
    inst.create_tags(
        Tags=[{'Key': 'Name', 'Value': 'Ops Manager ' + stack_name}])
    return inst


def get_stack_outputvars(st):
    ops = {v['OutputKey']: v['OutputValue'] for v in st.outputs}
    # group name is needed in a few places
    ops['PcfVmsSecurityGroupName'] = list(
        ec2.security_groups.filter(
            GroupIds=[ops['PcfVmsSecurityGroupId']]))[0].group_name
    return ops


def get_stack(stackName):
    cff = cloudformation(None, 'us-east-1')
    stt = list(cff.stacks.filter(StackName=stackName))
    if len(stt) == 0:
        raise Exception("Could not find stack with name " + stackName)

    st = stt[0]
    if st.stack_status != 'CREATE_COMPLETE':
        raise Exception(
            stackName + " Is not in CREATE_COMPLETE. Is in " + st.stack_status)

    return st


def ec2(profile, region):
    session = Session(profile_name=profile, region_name=region)
    return session.resource('ec2')


def cloudformation(profile, region):
    session = Session(profile_name=profile, region_name=region)
    return session.resource('cloudformation')


def get_args():
    import argparse
    argp = argparse.ArgumentParser()
    argp.add_argument('--profile')
    argp.add_argument('--region', default='us-east-1')
    return argp


def main(argv):
    args = get_args().parse_args(argv)
    ec2 = get_ec2_connection(args.profile, args.region)
    try:
        report(summarize(ec2_servers_by_deployment(
            ec2, cloudFormation_templatename_classifier())))
    except botocore.exceptions.NoCredentialsError as ex:
        print ex
        print "Missing ~/.aws/credentials directory?"
        print "http://boto3.readthedocs.org/en/latest/guide/configuration.html"
        return -1

    return 0


if __name__ == "__main__1":
    import sys
    sys.exit(main(sys.argv[1:]))
