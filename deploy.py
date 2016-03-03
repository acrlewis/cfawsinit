import botocore
from boto3.session import Session
import pivnet
import json
import uuid

def validate_key(ssh_key_name):
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
    paramaters = [{"ParameterKey":k, "ParameterValue":v, "UsePreviousValue": True} for k,v in args.items()]
    tags = [{"Key":"email", "Value": email}] 
    name = email.partition('@')[0]+"-pcf-"+str(uuid.uuid4())[:6]
    return cf.create_stack(StackName=name,
        TemplateBody=open(templateFile, 'rt').read(),
        Tags=tags,
        Parameters=paramaters,
        Capabilities=['CAPABILITY_IAM']) 
 
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
