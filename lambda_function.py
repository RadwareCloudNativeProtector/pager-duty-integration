#!/usr/bin/env python
#
# *******************************************************************************
# Name: lambda_function.py
# Version: v1.1
# Description: This open source AWS tool consumes the published security findings detected in Radware CWP to then
# trigger an event in the PagerDuty events API. The CWP Findings passed to PagerDuty are determined by the CWP risk
# score filter within the tool. All other findings are discarded.
#
# Author: Matt Ambroziak, mambroziak@github
# www.radware.com
#
# PIP Packages required:
#  - pdpyras
#
# Environment Variables required:
#  - pd_integration_key
#  - pd_event_severity
#  - cwp_score_filter
# *******************************************************************************

import os
import json
import pdpyras

# declare variables
pd_integration_key = os.environ['pd_integration_key']
pd_event_severity = os.environ['pd_event_severity']
cwp_score_filter = os.environ['cwp_score_filter']
cwp_score_filter = cwp_score_filter.split(',')


def process_alert(msg):
    # determine if event meets PD alert threshold
    if msg["score"] in cwp_score_filter:
        # Alert objectType considerations for differences in metadata
        if msg["objectType"] == 'Alert':
            summary = msg["title"]
            timestamp = msg["createdDate"]
            custom_details = {
              "Event Type": "Alert",
              "Risk Score": msg["score"]
            }
        elif msg["objectType"] == 'WarningEntity':
            summary = msg["subject"]
            timestamp = msg["lastDetectionDate"]
            custom_details = {
                "Event Type": "Warning",
                "Account Name": msg["accountName"],
                "Risk Score": msg["score"],
                "Warning Description": msg["description"],
                "Recommendation": msg["recommendation"],
                "Resource Type": msg["resourceType"]
            }
        else:
            process_error = f'Alert (objectType) not supported: {msg["objectType"]}'
            print(process_error)
            return {"success": False, "comment": process_error}

        links = [{"href": msg["objectPortalURL"], "text": "Link to event in Radware CWP Portal"}]

        payload = {
            "summary": summary,
            "source": f'{msg["accountVendor"]}:{msg["accountIds"][0]}',
            "timestamp": timestamp,
            "severity": pd_event_severity,
            "group": msg["accountIds"][0],
            "custom_details": custom_details
        }

        # Create PD session and send event trigger
        session = pdpyras.EventsAPISession(pd_integration_key)
        dedup_key = session.trigger(summary=None, source=None, links=links, payload=payload)

        if dedup_key:
            success = True
            comment = "Accepted and published to PagerDuty"
        else:
            dedup_key = ""
            success = False
            comment = "Error publishing alert to PagerDuty"

        # write report
        report = {"success": success, "eventType": msg["objectType"], "riskScore": msg["score"], "deduplication_key": dedup_key, "comment": comment}
        return report
    else:
        report = {"success": False, "eventType": msg["objectType"], "riskScore": msg["score"], "deduplication_key": "", "comment": "Discarded. Risk score did not meet threshold requirements."}
        return report


def lambda_handler(event, context):
    message = event['Records'][0]['Sns']['Message']
    print("From SNS: " + str(message))
    message = json.loads(message)
    report = process_alert(message)

    print(report)
    return report
