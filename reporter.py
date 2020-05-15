#!/usr/bin/env python3

import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
import json
import yaml
import os
import time
import re
import boto3
import pprint

def ecr_report(cfg):
    ###Queries the scan report of the given image from ECR###

    print("Accessing ECR " + cfg['ecr']['registry_id'])
    print("Query Scan Report from ECR for "
          + cfg['repository']['name']
          + ":" + cfg['repository']['image_tag'])
    ecr = boto3.client('ecr')
    response = ecr.describe_image_scan_findings(
        registryId = cfg['ecr']['registry_id'],
        repositoryName = cfg['repository']['name'],
        imageId = { 'imageTag': cfg['repository']['image_tag'] }
    )

    vulns = {}
    vul_count_defcon1 = 0
    vul_count_critical = 0
    vul_count_high = 0
    vul_count_medium = 0

    for vul in response['imageScanFindings']['findings']:
        vul_cve = vul['name']

        vul_severity = vul['severity'].lower()
        if (( vul_severity not in cfg['criticalities']) and
            ( vul_severity != "unknown" )):
            continue

        if (vul_severity == "defcon1"): vul_count_defcon1 += 1
        if (vul_severity == "critical"): vul_count_critical += 1
        if (vul_severity == "high"): vul_count_high += 1
        if (vul_severity == "medium"): vul_count_medium += 1

        vul_av2 = ""
        for attr in vul['attributes']:
            if (attr.get('key') == 'CVSS2_VECTOR'):
                vul_av2 = attr.get('value')

        if ((str(vul_av2).find('AV:N') >= 0)):
            vul_av = "network"
        else:
            vul_av = "local"

        vulns[str(vul_cve)] = { "severity": str(vul_severity),
                                "av": str(vul_av) }

    print("defcon1: {}, critical: {}, high: {}, medium: {}".format(
                                                            vul_count_defcon1,
                                                            vul_count_critical,
                                                            vul_count_high,
                                                            vul_count_medium))
    print()

    return vulns

def dssc_report(cfg):
    ###Queries the scan report of the given image from Smart Check###

    content_type = "application/vnd.com.trendmicro.argus.webhook.v1+json"

    print("Accessing Smart Check engine at "
          + cfg['dssc']['service'])
    url = cfg['dssc']['service'] + "/api/sessions"
    data = {
        "user": {
            "userid": cfg['dssc']['username'],
            "password": cfg['dssc']['password']
            }
        }

    post_header = {
        "Content-type": "application/json",
        "x-argus-api-version": "2017-10-16"
        }
    response = requests.post(url,
                             data=json.dumps(data),
                             headers=post_header,
                             verify=False
                             ).json()

    if 'message' in response:
        print("Authentication response: " + response['message'])
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or",
                             "SmartCheck not available")

    response_token = response['token']

    print("Search for latest Scan ID of "
          + cfg['repository']['name']
          + ":" + cfg['repository']['image_tag'])

    url = cfg['dssc']['service'] + "/api/scans"
    data = { }
    post_header = {
        "Content-type": content_type,
        "authorization": "Bearer " + response_token
    }
    response = requests.get(url,
                            data=json.dumps(data),
                            headers=post_header,
                            verify=False
                            ).json()

    scan_id = ""
    scan_time = "2000-01-1T00:00:00Z"
    for scan in response.get('scans', {}):
        if (( scan['source']['repository'] == cfg['repository']['name'] ) and
            ( scan['source']['tag'] == cfg['repository']['image_tag'] )):
            if ( scan['details']['updated'] > scan_time ):
                scan_time = scan['details']['updated']
                scan_id = scan['id']

    if ( scan_id == ""):
        raise ValueError("Scan not found")

    print("Query Scan Report for ID " + scan_id)
    url = cfg['dssc']['service'] + "/api/scans/" + scan_id
    data = { }
    post_header = {
        "Content-type": content_type,
        "authorization": "Bearer " + response_token
    }
    response = requests.get(url,
                            data=json.dumps(data),
                            headers=post_header,
                            verify=False
                            ).json()

    # query vulnerability database update time
    scanners_list = response['findings'].get('scanners', {})
    database_time = scanners_list.get('vulnerabilities', {}).get('updated', {})
    print("Database last update time {}".format(database_time))

    # iterate layers
    result_list = response['details'].get('results', {})

    vulns = {}
    vul_count_defcon1 = 0
    vul_count_critical = 0
    vul_count_high = 0
    vul_count_medium = 0

    for result in result_list:
        if 'vulnerabilities' in result:

            url = cfg['dssc']['service'] \
                  + result.get('vulnerabilities', {}) \
                  + "?limit=10000"
            data = { }
            post_header = {
                "Content-type": content_type,
                "authorization": "Bearer " + response_token,
            }
            response_layer = requests.get(url,
                                          data=json.dumps(data),
                                          headers=post_header,
                                          verify=False
                                          ).json()

            for item in response_layer.get('vulnerabilities', {}):
                affected=item.get('name', {})
                for vul in item.get('vulnerabilities', {}):
                    vul_cve = vul.get('name', {})

                    vul_severity = vul.get('severity', {}).lower()
                    if (( vul_severity not in cfg['criticalities'] ) and
                        ( vul_severity != "unknown" )):
                        continue

                    if (vul_severity == "defcon1"): vul_count_defcon1 += 1
                    if (vul_severity == "critical"): vul_count_critical += 1
                    if (vul_severity == "high"): vul_count_high += 1
                    if (vul_severity == "medium"): vul_count_medium += 1

                    vul_av2 = vul.get('metadata', {}) \
                                 .get('NVD', {}) \
                                 .get('CVSSv2', {}) \
                                 .get('Vectors', {})
                    vul_av3 = vul.get('metadata', {}) \
                                 .get('NVD', {}) \
                                 .get('CVSSv3', {}) \
                                 .get('Vectors', {})
                    if (
                        (str(vul_av2).find('AV:N') >= 0) or
                        (str(vul_av3).find('AV:N') >= 0)):
                        vul_av = "network"
                    else:
                        vul_av = "local"

                    vulns[str(vul_cve)] = { "severity": str(vul_severity),
                                            "av": str(vul_av)}

    print("defcon1: {}, critical: {}, high: {}, medium: {}".format(
                                                            vul_count_defcon1,
                                                            vul_count_critical,
                                                            vul_count_high,
                                                            vul_count_medium))
    print()

    return vulns

def main():

    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    # Query Reports
    ecr_vulns = ecr_report(cfg)
    dssc_vulns = dssc_report(cfg)

    # Some Calculations
    ecr_additionals = {
        k : ecr_vulns[k] for k in set(ecr_vulns) - set(dssc_vulns) }
    dssc_additionals = {
        k : dssc_vulns[k] for k in set(dssc_vulns) - set(ecr_vulns) }
    intersection = {
        k : dssc_vulns[k] for k in set(dssc_vulns) & set(ecr_vulns) }

    pp = pprint.PrettyPrinter()

    print()
    print("Findings by ECR:")
    pp.pprint(ecr_vulns)

    print()
    print("Findings by Smart Check:")
    pp.pprint(dssc_vulns)

    print()
    print("Additional Findings by ECR:")
    pp.pprint(ecr_additionals)

    print()
    print("Additional Findings by Smart Check:")
    pp.pprint(dssc_additionals)

    print()
    print("Intersection of ECR and Smart Check:")
    pp.pprint(intersection)

    exit(0)

if __name__ == '__main__':
    main()
