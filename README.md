# smartcheck-ecr-reporter
Compares discovered vulnerabilities by Smart Check and ECR.

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
* Findings by ECR
* Findings by Smart Check
* Additional Findings by ECR
* Additional Findings by Smart Check
* Intersection of ECR and Smart Check

## Requirements
* Python3
* Boto3 (`pip3 install boto3 --user`)

**Note: The image must exist in both repositories with the identical tag**
