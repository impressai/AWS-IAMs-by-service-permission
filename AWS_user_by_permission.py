import argparse
import sys
import boto3
import json
import datetime
import re

SERVICE_MAPPING = {
    "kms": "Amazon Key Management Service",
    "iam": "AWS Identity and Access Management"
}


# Utility to convert datetime to strings for json.dump
def datetime_to_string(dt_obj):
    if isinstance(dt_obj, datetime.datetime):
        return dt_obj.__str__()


# Get todays date in str format
def get_date_today():
    return datetime.datetime.now().date().__str__()


# Get permissions from policy dictionary
def get_permission_from_policy(policy):
    policy_versions = policy.get("PolicyVersionList", [])
    policy_actions = []
    for version in policy_versions:
        if version.get("IsDefaultVersion", False):
            version_doc = version.get("Document", {})
            policy_actions += get_permissions_from_policy_doc(version_doc)
    return policy_actions


# Get filter policy documents and get permisions from them
def seek_permission_dicts(all_policies, policy_arn_list):
    policy_permissions = []
    for policy in all_policies:
        policy_arn = policy.get("Arn", "")
        if policy_arn in policy_arn_list:
            policy_permission = get_permission_from_policy(policy)
            policy_permissions += policy_permission

    return policy_permissions


# Go through groups and filter & gather policy arns
def get_group_policy_arns(all_groups, user_group_list):
    group_policy_arns = []
    for group in all_groups:
        if group.get("GroupName", "") in user_group_list:
            group_policies = group.get("AttachedManagedPolicies", [])
            for policy in group_policies:
                group_policy_arns.append(policy["PolicyArn"])

    return group_policy_arns


# Extract the list of actions from the policy document
def get_permissions_from_policy_doc(policy_doc):
    doc_permissions = []
    policy_doc_statements = policy_doc.get("Statement", [])
    for statement in policy_doc_statements:
        statement_actions = statement.get("Action", [])
        doc_permissions += statement_actions
    return doc_permissions


# Filter permission for a service
def filter_service_permissions(permission_list, service_prefix=None):
    if service_prefix is None:
        return permission_list

    result = []
    service_regex = "^{0}".format(service_prefix)
    for permission in permission_list:
        if re.match(service_regex, permission):
            result.append(permission)
    return result


def get_users_with_service_permissions(auth_document, service):
    user_list = []

    user_details = auth_document.pop("UserDetailList")
    group_details = auth_document.pop("GroupDetailList")
    role_details = auth_document.pop("RoleDetailList")
    policies = auth_document.pop("Policies")

    for user_detail in user_details:
        permissions = {}
        if "UserPolicyList" in user_detail:
            user_policy_permissions = []
            for user_policy in user_detail["UserPolicyList"]:
                user_policy_permissions += get_permissions_from_policy_doc(user_policy)
            filtered_user_policy_permissions = filter_service_permissions(user_policy_permissions, service)
            if filtered_user_policy_permissions:
                permissions["user_policies"] = filtered_user_policy_permissions

        if "GroupList" in user_detail:
            user_group_policies = get_group_policy_arns(group_details, user_detail["GroupList"])
            user_group_permissions = seek_permission_dicts(policies, user_group_policies)
            filtered_user_group_permissions = filter_service_permissions(user_group_permissions, service)
            if filtered_user_group_permissions:
                permissions["user_group_permissions"] = filtered_user_group_permissions

        if "AttachedManagedPolicies" in user_detail:
            managed_policies_permissions = []
            for managed_policy in user_detail["AttachedManagedPolicies"]:
                policy_arn = managed_policy["PolicyArn"]
                managed_policies_permissions += seek_permission_dicts(policies, policy_arn)
            filtered_managed_policies_permissions = filter_service_permissions(managed_policies_permissions, service)
            if filtered_managed_policies_permissions:
                permissions["managed_policies"] = filtered_managed_policies_permissions

        if permissions:
            permission_details = {
                "username": user_detail["UserName"],
                "user_id": user_detail["UserId"],
                "arn": user_detail["Arn"],
                "permissions": permissions
            }
            user_list.append(permission_details)
        else:
            continue

    return user_list


# Writes the results to a json file
def write_results_to_file(result, filename="result.json"):
    with open(filename, 'w') as f:
        json.dump(result, f, default=datetime_to_string)


# Maps the service namespace to the service name (SERVICE_MAPPING)
def get_verbose_service_name(prefix):
    return SERVICE_MAPPING.get(prefix, "Service name is not mapped")


# GetAccountAuthorizationDetails
def main(service, profile, output):
    session = boto3.Session(profile_name=profile)
    client = session.client("iam")
    auth_document = client.get_account_authorization_details(
        Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
    )
    user_list = get_users_with_service_permissions(auth_document, service)
    result = {
        "service": get_verbose_service_name(service),
        "service_prefix": service,
        "date": get_date_today(),
        "users": user_list
    }
    write_results_to_file(result, filename=output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='A Simple application that fetches users that has access to a certain AWS service. This application would require a profile with (mininally) view permissions to the IAMs. It is recommended that the profile has the IAMReadOnlyAccess policy attached.')

    parser.add_argument(
        'service',
        type=str,
        action="store",
        help="Service namespace of the AWS service. (e.g. iam, ec2, sqs, sns, s3, etc.)")

    parser.add_argument(
        '--profile',
        '-p',
        type=str,
        action="store",
        default="default",
        help="Name of the credential profile in '~/.aws/credentials' (default: default)")

    parser.add_argument(
        '--output',
        '-o',
        type=str,
        action="store",
        default="result.json",
        help="Path and filename of the output. Must be a .json file (default: result.json)")

    arguments = parser.parse_args()
    service = arguments.service
    profile = arguments.profile
    output = arguments.output
    main(service, profile, output)
