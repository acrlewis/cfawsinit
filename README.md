# cfawsinit
Automate Creation of CloudFoundry deployment in AWS

Automates steps outlined in 
http://docs.pivotal.io/pivotalcf/customizing/cloudform.html

## Progress So far
Given a configuration file you can create a fully working ops manager
with Elastic Runtime tile staged.

## TODO
Fully configure elastic runtime

## Goals
1. minimal input configuration file
2. Minimal input file is resolved to a specific configuration file
3. Be fully idempotent. The job can be killed and restarted anytime.
