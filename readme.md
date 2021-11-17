OhitskiLabs AWS Assume Role Script
----------------------------------

#### Description
Cuts down on some AWS CLI role assumption annoyances by automatically setting the newly assumed role to the CLI's default profile within ~/.aws/credentials. Olaar's 'revert' command swaps the default AWS context back to the provided profile. Role assumption via Olaar supports an optional external id and uses the current AWS profile's account id to determine the assumed role ARN. Future implementation will allow for specified account ids, but please note that MFA is not supported if trust policies require supply an MFA device's serial number / arn and token.

---

#### Usage
Usage differs slightly on whether Olaar will be used to assume a role or revert back to a saved profile. Examples are probably the easiest way to demonstrate:
```bash
# Assumes role to arn:aws:iam::{AccountId}:assumed-role/MyRoleToAssume/MyRoleToAssume-Session
# And sets the aws_access_key, aws_secret_access_key, and aws_session_token in ~/.aws/credentials
python3 olaar.py assume --role MyRoleToAssume
```
```bash
# Assumes role to arn:aws:iam::{AccountId}:assumed-role/MyRoleThatRequiresExternalId/MyRoleThatRequiresExternalId-Session
# And sets the aws_access_key, aws_secret_access_key, and aws_session_token in ~/.aws/credentials
python3 olaar.py assume --role MyRoleThatRequiresExternalId --external-id MyExternalId
```
```bash
# Sets the default AWS profile to match what is specified for [MyStandardProfile] within ~/.aws/credentials
python3 olaar.py revert --profile MyStandardProfile
```

---

#### Requirements
Olaar requires argparse and boto3. Install the dependencies if you do not already have them with one of the two following lines:
```bash
python3 -m pip install argparse boto3
# Or
python3 -m pip install -r requirements.txt
```