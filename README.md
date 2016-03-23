# cfawsinit
Automate Creation of CloudFoundry deployment in AWS

Automates steps outlined in
http://docs.pivotal.io/pivotalcf/customizing/cloudform.html

## Progress So far
Given a configuration file you can create a fully working ops manager
with Elastic Runtime tile staged.

## Features
1. Supports Ops Manager 1.6 and 1.7.
2. Uses network.pivotal.io / pivnet to resolve and fetch needed artifacts.
3. Idempotence

## TODO
1. Fully configure elastic runtime
2. Autocreate self signed ssl cert and arn
3. Register Routes
4. Configure HA parameters in OpsManager

## Goals
1. Minimal input configuration file
2. Input file is resolved to a specific configuration file
3. Idempotence. The job can be killed and restarted anytime.

## Requirements
1. Python 2.7
2. PIVNET_TOKEN from https://network.pivotal.io/users/dashboard/edit-profile
3. AWS Keypair loaded to your private key path
```
➜  chmod 400 mjog.pem
➜  ssh-add mjog.pem
Identity added: mjog.pem (mjog.pem)
```
4. Install Requirements
```
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage
```shell
mjog@ mac ~/cfawsinit$ ./awsdeploy.py  --help
usage: awsdeploy [prepare|deploy] [-h] --action {prepare,deploy} [--cfg CFG]
                                  [--prepared-cfg PREPARED_CFG]
                                  [--timeout TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  --action {prepare,deploy}
  --cfg CFG
  --prepared-cfg PREPARED_CFG
  --timeout TIMEOUT
```
### Minimal input file  (awsdeploy.yml)
```yml
region: us-east-1
email: email@gmail.com
ssh_private_key_path: ~/.ssh/id_rsa
ssh_key_name: mjog
domain: "{ssh_key_name}{uid}.pcf-practice.com"
PIVNET_TOKEN: AAAA-h6BBBBBCotwXFi
ops-manager:
    version: latest
    beta-ok: true
elastic-runtime:
    version: latest
    beta-ok: true
ssl_cert_arn: arn:aws:iam::375783000519:server-certificate/mjogCertificate
```
```shell
mjog@ mac ~/cfawsinit $ ./awsdeploy.py --action prepare --cfg awsdeploy.yml --prepared-cfg awsout.yml
```
### This command produces the following fully resolved yaml file
The resolve (prepared) yaml file is used to deploy cloud foundry
```yml
PIVNET_TOKEN: AAAA-h6BBBBBCotwXFi
__PREPARED__: true
date: 2016-03-17 04:08:41.544568
domain: mjog431699.pcf-practice.com
elastic-runtime:
  beta-ok: true
  cloudformation-template: ert_cloudformation.json
  cloudformation-template-url: https://network.pivotal.io/api/v2/products/elastic-runtime/releases/1555/product_files/4060/download
  cloudformation-template-version: 1.7.0.alpha4
  image-build: 1.7.0-build.58
  image-file-url: https://network.pivotal.io/api/v2/products/elastic-runtime/releases/1555/product_files/4040/download
  image-filename: cf-1.7.0-build.58.pivotal
  version: 1.7.0.alpha4
email: email@gmail.com
ops-manager:
  ami-id: ami-67ccf40d
  ami-name: pivotal-ops-manager-v1.7-alpha5
  beta-ok: true
  version: 1.7-alpha7
opsman-password: keepitsimple
opsman-username: admin
rds-password: keepitsimple
rds-username: dbadmin
region: us-east-1
ssh_key_name: mjog
ssh_private_key_path: ~/.ssh/id_rsa
ssl_cert_arn: arn:aws:iam::375783000519:server-certificate/mjogCertificate
stack-name: mjog-pcf-431699
uid: 431699
```

### The prepared yaml file is used during deploy
Many operations take a long time. You may press Ctrl-C and restart the same command later

```shell
mjog@ mac ~/CFWORK/cfinit$ ./awsdeploy.py --action deploy --prepared-cfg ./awsout.yml
Creating stack mjog-pcf-431699
It takes about 22 minutes to create the stack
^CTraceback (most recent call last):
KeyboardInterrupt

mjog@ mac ~/CFWORK/cfinit$ ./awsdeploy.py --action deploy --prepared-cfg ./awsout.yml
stack mjog-pcf-431699 is in state CREATE_IN_PROGRESS
^CTraceback (most recent call last):
KeyboardInterrupt
```
After about 20 mins ...
```shell
mjog@ mac ~/CFWORK/cfinit$ ./awsdeploy.py --action deploy --prepared-cfg ./awsout.yml
stack mjog-pcf-431699 is in state CREATE_COMPLETE
Waiting for instance to start i-2361c5b8 ...
Admin user established.
Configuring Ops Manager
Applying Changes...
Downloading (1.7.0.alpha4) cf-1.7.0-build.58.pivotal to ops manager... done
Installing Elastic runtime (1.7.0.alpha4) cf-1.7.0-build.58.pivotal ... done
Staged {u'product_version': u'1.7.0-build.58', u'name': u'cf'}
Ops manager is now available at  https://ec2-51-9-24-33.compute-1.amazonaws.com
```

After a loooong time, Success!!

As always, if it times out waiting for a certain operation, restart it.
Alternatively use --timeout parameter to give a very large timeout
