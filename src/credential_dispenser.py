import json
import boto3
import base64
import os
import binascii

def lambda_handler(event, context):
    try:
        student_passwords = json.loads(os.environ['STUDENT_PASSWORDS_JSON'])
    except (KeyError, json.JSONDecodeError):
        return {"statusCode": 500, "body": "Internal Server Error: Password configuration missing or malformed."}

    aws_account_id = context.invoked_function_arn.split(":")[4]
    headers = {key.lower(): value for key, value in event.get('headers', {}).items()}
    auth_header = headers.get('authorization', '')

    try:
        auth_type, encoded_creds = auth_header.split()
        if auth_type.lower() != 'basic':
            return {"statusCode": 401, "body": "Unauthorized: Only Basic Auth supported"}

        decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
        username, password = decoded_creds.split(':')

        if username != "student":
            return {"statusCode": 401, "body": "Unauthorized: Invalid username"}

    except (ValueError, TypeError, binascii.Error):
        return {"statusCode": 401, "body": "Unauthorized: Malformed Authorization header"}

    fruit = event.get('pathParameters', {}).get('fruit')
    if not fruit:
         return {"statusCode": 400, "body": "Bad Request: Fruit not specified in path."}

    capitalized_fruit = fruit.capitalize()

    if capitalized_fruit not in student_passwords:
        return {"statusCode": 404, "body": f"Not Found: Fruit '{fruit}' not recognized"}

    if password != student_passwords.get(capitalized_fruit):
        return {"statusCode": 401, "body": "Unauthorized: Invalid password for this fruit"}

    try:
        sts_client = boto3.client('sts')
        role_arn = f"arn:aws:iam::{aws_account_id}:role/StudentRole-{capitalized_fruit}"

        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"{capitalized_fruit}WebAppSession"
        )
        credentials = assumed_role_object['Credentials']

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "AccessKeyId": credentials['AccessKeyId'],
                "SecretAccessKey": credentials['SecretAccessKey'],
                "SessionToken": credentials['SessionToken']
            })
        }
    except Exception as e:
        print(f"Error assuming role: {e}")
        return {"statusCode": 500, "body": "Internal Server Error: Could not assume role."}