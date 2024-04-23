import argparse, boto3, getpass, os

def assume_role(role: str, ext_id: str = None) -> dict:
    """Performs STS role assumption API call for a provided ARN within the user context account"""
    sts = boto3.client('sts')
    res = {}
    try:
        print('[+] Retrieving Account ID')
        res = sts.get_caller_identity()
        account_id = res.get('Account', None)
    except sts.exceptions.ClientError as err:
        print(f'[x] {err}')
        exit()

    try: # Assume role from STS API
        arn = f'arn:aws:iam::{account_id}:role/{role}'
        print(f'[+] Executing role assumption for {arn}')
        if ext_id:
            res = sts.assume_role(RoleArn=arn, RoleSessionName=f'{role}-Session', ExternalId=ext_id)
        else:
            res = sts.assume_role(RoleArn=arn, RoleSessionName=f'{role}-Session')
        print(f'[+] Received credentials from STS')
    
    except sts.exceptions.ClientError as err:
        print(f'[x] {err}')
        exit()
    
    return res


def configure_default_profile(res: dict) -> None:
    """Sets aws_access_key, secret_access_key, and session_token within ~/.aws/credentials under [default]"""
    creds = res.get("Credentials", {})
    arn = res.get("AssumedRoleUser", {}).get("Arn", "")
    print(f'[+] Setting default profile credentials to assumed role \'{arn}\'')
    os.system(f'aws configure set aws_access_key_id {creds.get("AccessKeyId")} --profile default')
    os.system(f'aws configure set aws_secret_access_key {creds.get("SecretAccessKey")} --profile default')
    os.system(f'aws configure set aws_session_token {creds.get("SessionToken")} --profile default')
    return None


def revert_default_profile(profile: str) -> None:
    """Reverts default AWS profile to the provided profile"""
    boto_session = boto3.Session(profile_name=profile)
    access_key = boto_session.get_credentials().access_key
    secret = boto_session.get_credentials().secret_key
    token = boto_session.get_credentials().token
    if not token:
        token = "\'\'"

    print(f'[+] Setting default profile credentials to profile \'{profile}\'')
    os.system(f'aws configure set aws_access_key_id {access_key} --profile default')
    os.system(f'aws configure set aws_secret_access_key {secret} --profile default')
    os.system(f'aws configure set aws_session_token {token} --profile default')

    return None


def print_env_variables(res: dict) -> None:
    creds = res.get("Credentials", {})
    arn = res.get("AssumedRoleUser", {}).get("Arn", "")
    print(f'Credentials for assumed role: {arn}')
    print(f'export AWS_ACCESS_KEY_ID={creds.get("AccessKeyId")}')
    print(f'export AWS_SECRET_ACCESS_KEY={creds.get("SecretAccessKey")}')
    print(f'export AWS_SESSION_TOKEN={creds.get("SessionToken")}')
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser('olaar.py - OhitskiLabs AWS Assume Role script', usage='python3 olaar.py [assume|revert] [--role <role> [--external-id <id>] | --profile <name>]')
    parser.add_argument('--external-id',required=False,action='store_true',default=False,help='Prompt for the external id required for role assumption')
    parser.add_argument('--role',required=False,default=None,help='Role to assume within the account')
    parser.add_argument('--profile',required=False,default=None,help='AWS profile to set as default')
    parser.add_argument('--env', default=False, action='store_true', help='Print bash environment variables instead of overwriting default profile')
    parser.add_argument('command',default=None,help='Command to run [assume|revert] (note: revert removes all aws_session_token entries')
    
    args = parser.parse_args()

    if (args.command == 'assume'):
        if not args.role:
            print(f'[x] Command \'assume\' requires a specified role arn (--role)')
            parser.print_usage()
        ext_id = getpass.getpass('External Id >> ') if (args.external_id) else None
        res = assume_role(args.role, ext_id)

        if (args.env): print_env_variables(res)
        else: configure_default_profile(res)
    elif (args.command == 'revert'):
        if not args.profile:
            print(f'[x] Command \'revert\' requires a profile name (--profile)')
            parser.print_usage()
        profile = args.profile
        revert_default_profile(profile)
    else:
        parser.print_usage()
    
    exit()
