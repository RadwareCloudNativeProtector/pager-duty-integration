# Radware CWP PagerDuty Integration
*with PD Events API*

This open source AWS tool consumes the published security findings detected in Radware CWP to then trigger an event in the PagerDuty events API. The CWP Findings passed to PagerDuty are determined by the CWP risk score filter within the tool. All other findings are discarded. 

The CFT deployment process will create an SNS Topic, an IAM Role, CloudWatch Log Group (default 90 days retention), and a Lambda Function. Messages published to the created SNS Topic trigger the Lambda Function on-demand.

## Setup

## Prerequisities
* Create a **PagerDuty Integration Key** with _direct API_ access. [Read the docs](https://support.pagerduty.com/docs/services-and-integrations)

### CFT Parameters
This CFT stack has 3 parameters:

- **PagerDutyIntegrationKey** -  PagerDuty integration (routing) key
- **PagerDutySeverity** - PagerDuty event severity level for alerts (values: `critical`/`error`/`warning`/`info`)
- **CwpScoreFilter** - CWP risk scores which will trigger a PagerDuty alert (comma separated values: 1 through 10)

### [Option 1] One-click CFT Deployment:
[<img src="docs/pictures/cloudformation-launch-stack.png">]( https://console.aws.amazon.com/cloudformation/home?#/stacks/new?stackName=RadwareCWP-PagerDuty-Integration&templateURL=https://cnp-public-us-east-1.s3.amazonaws.com/radware_cwp_pagerduty_integration/radware_cwp_pagerduty_integration.yaml)
> Note: One-click CFT deployment currently works for regions: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-central-1. The AWS region you are actively logged into will be the region of deployment.
1. Fill in the parameter fields. 
1. Click **Next** twice.
1. Under **Capabilities and transforms**, click to check the **3** pending acknowledgements: "_I acknowledge..._".
1. Click **Create stack**.
1. After the process finished view the **Outputs** tab. The **InputTopicARN** value will be needed for the next step in the CWP console.

### [Option 2] Manual CFT Deployment:
1. Download the contents of this repo.
1. Build your own Lambda deployment file (see [Appendix A](#appendix-A))
1. Upload the deployment file to an S3 bucket 
1. Modify `radware_cwp_pagerduty_integration.yaml` lines `47` and `52` and enter values for `bucket` and `key` (zip file), respectively. Remove lines `48-51`.
1. Login to the AWS console, select a region, and navigate to CloudFormation. 
1. Click **Create stack**
1. Under **Specify template**, click **Upload a template file**
1. Click the **Choose file** button and upload the modified CFT.
1. Click **Next** twice.
1. Under **Capabilities and transforms**, click to check the **3** pending acknowledgements: "_I acknowledge..._". (or use "--capabilities CAPABILITY_IAM" if using the AWS CLI.)
1. Click **Create stack**.
1. After the process finished view the **Outputs** tab. The **InputTopicARN** value will be needed for the next step in the Radware CWP console.

## Post-Deployment Steps

### Radware CWP Setup:
1. Log into **Radware CWP** and then click **Settings** > **Manage Cloud Accounts** from the menu at the top. 
1. Find the AWS cloud account you want to get alerts from in the list, click **Activate** under the **Automated Response** column.
1. In the **Activate Automated Response** dialogue box, under step 2, paste the **InputTopicARN** value from the CFT deployment process. 
1. Click **Activate**.
All done!

### Testing:
##### Option 1: Synthetic Test
1. Find the sample CWP JSON files in the `samples` directory from this repo for *WarningEntity* and *Alert* payloads.
1. From the CFT stack deployment in the AWS Console, open the SNS topic found in the **Resources** tab, shown as **InputTopic**.
1. At the top-right, click the **Publish message** button and copy and paste the contents of one of the JSON files into the **Message body** field. (You may need the ``score`` value in the payload to include a value in your `CwpScoreFilter` parameter)
1. Scroll down and click the **Publish messsage** button. 
1. Validate the results in S3.

##### Option 2 - CWP Native Test
It is recommended to perform the synthetic test first before attempting a CWP native test.
1. Temporarily set the `CwpScoreFilter` parameter to `4,5,6,7,8,9,10`
1. Login to an AWS account that is already protected by Radware CWP with [automated response](#radware-cwp-setup).
1. Create a test S3 bucket and set the bucket policy to allow public acess. You should see Public warnings in the AWS console. This will trigger CWP and push a *WarningEntity* payload.
1. Validate the Lambda function logs and the results in S3.
1. Reset the `CwpScoreFilter` parameter to the desired value (e.g. `7,8,9,10`)
1. Cleanup the S3 bucket created for this test.

## Appendix A
**Build your own deployment file to publish to AWS Lambda**
1. Create a new instance with an Amazon Linux AMI. 
2. Login and validate the version of Python matches the latest Lambda Function runtime (v3.8 at the time of this writing) `python --version`.
3. Clone this project `git clone https://github.com/mambroziak/radware-cwp-pager-duty-integration.git`
4. Change into the project root directory `cd radware-cwp-pager-duty-integration`
5. Run the following bash script to install the dependencies.
```
pip install --target ./package pdpyras
# More info: https://github.com/PagerDuty/pdpyras
```
6. Build the Lambda deployment zip file
```
# Cleanup stale deployment file
rm ./radware_cwp_pagerduty_integration.zip
# Build the deployment file
chmod -R 755 .
cd package
zip -r9 ${OLDPWD}/radware_cwp_pagerduty_integration.zip .
cd $OLDPWD
zip -g radware_cwp_pagerduty_integration.zip lambda_function.py
```
7. Publish the deployment file to lambda.
```
aws lambda update-function-code \
 --function-name <my-function-name> \
 --zip-file fileb://radware_cwp_pagerduty_integration.zip\
 --publish \
 --region=us-east-1
```

## License
This project is licensed under the MIT License
