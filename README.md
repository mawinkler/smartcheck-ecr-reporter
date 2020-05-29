# smartcheck-ecr-reporter
Compares discovered vulnerabilities by Smart Check and Clair. The used Clair
engine is the embedded one of AWS ECR which can be used free of charge. This
small project doesn't rate AWS capabilities in any sense.

First, create your config.yml by
```shell
cp config.yml.sample config.yml
```
and then define the values.

Run the comparison by
```shell
./reporter.py
```

A couple of lists are created:
* Findings by Clair
* Findings by Smart Check
* Additional Findings by Clair
* Additional Findings by Smart Check
* Intersection of Clair and Smart Check

## Requirements
* Python3
* Boto3 (`pip3 install boto3 --user`)

**Note: The image must exist in both repositories with the identical tag**
