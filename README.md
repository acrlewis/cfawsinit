# cfawsinit
Automate Creation of CloudFoundry deployment in AWS

Automates steps outlined in 
http://docs.pivotal.io/pivotalcf/customizing/cloudform.html

## Progress So far
Given a configuration file you can create a fully working ops manager
with Elastic Runtime tile staged.

## TODO
1. Fully configure elastic runtime
2. Autocreate self signed ssl cert and arn
3. Register Routes

## Goals
1. minimal input configuration file
2. Minimal input file is resolved to a specific configuration file
3. Be fully idempotent. The job can be killed and restarted anytime.

## Usage
```shell
mjog@ mac ~/CFWORK/cfinit$ python ./awsdeploy.py
usage: awsdeploy [prepare|deploy] [-h] --action {prepare,deploy} [--cfg CFG]
                                  [--prepared-cfg PREPARED_CFG]
                                  [--timeout TIMEOUT]
awsdeploy [prepare|deploy]: error: argument --action is required
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
mjog@ mac ~/CFWORK/cfinit$ python ./awsdeploy.py --action prepare --cfg awsdeploy.yml --prepared-cfg awsout.yml
```
### This command produces the following fully resolved yaml file
The resolve (prepared) yaml file is used to deploy cloud foundry
```yml
PIVNET_TOKEN: AAAA-h6BBBBBCotwXFi
__PREPARED__: true
date: 2016-03-17 04:08:41.544568
domain: mjog66ff48.pcf-practice.com
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
stack-name: mjog-pcf-66ff48
uid: 66ff48
```
