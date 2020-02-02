# AWS IAMs by service permission
A simple script that fetches users that has access to a certain AWS
service.

## What is this script for?
This is a simple script to generate the list of IAMs with permissions/access to an AWS service. Its main purpose is to generate documentation for access reviews or auditing purposes.

## Usage
This script runs on python3 and you'll have to have that installed to run this script.

```
$python3 AWS_user_by_permission.py -h
usage: AWS_user_by_permission.py [-h] [--profile PROFILE] [--output OUTPUT]
                                 service

A Simple application that fetches users that has access to a certain AWS
service. This application would require a profile with (mininally) view
permissions to the IAMs. It is recommended that the profile has the
IAMReadOnlyAccess policy attached.

positional arguments:
  service               Service namespace of the AWS service. (e.g. iam, ec2,
                        sqs, sns, s3, etc.)

optional arguments:
  -h, --help            show this help message and exit
  --profile PROFILE, -p PROFILE
                        Name of the credential profile in '~/.aws/credentials'
                        (default: default)
  --output OUTPUT, -o OUTPUT
                        Path and filename of the output. Must be a .json file
                        (default: result.json)
```

Example usage:

```
$AWS_user_by_permission.py s3 --profile iam_sandbox --output ./output/s3_permissions.json
```


## Installation
Just download/clone/pull the script and you're good to go!


## IAM Permissions required
This script would require a profile with (mininally) view
permissions to the IAMs. It is recommended that the profile has the
IAMReadOnlyAccess policy attached.

## Sample output
```
{
  "service": "AWS Identity and Access Management",
  "service_prefix": "iam",
  "date": "2020-02-02",
  "users": [
    {
      "username": "someusername",
      "user_id": "AIDA6LGKREXH52TPISKTU",
      "arn": "arn:aws:iam::someaccount:user/someusername",
      "permissions": {
        "managed_policies": [
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:Get*",
          "iam:List*",
          "iam:SimulateCustomPolicy",
          "iam:SimulatePrincipalPolicy"
        ]
      }
    }
  ]
}
```