#Instructions
On the user deployment machine.
This is all done from the command line.
I am guessing if you are on window your best bet might be to use powershell
Install:
- Boto: pip install boto3         (see https://boto3.readthedocs.org/en/latest/guide/quickstart.html)
- AWSCLI: pip install awscli      (http://docs.aws.amazon.com/cli/latest/reference/index.html#cli-aws)
- fabric: pip install fabric
    
Make sure you set up your boto config file.


# Next we want to create our users
aws iam create-user cjpoole
aws iam create-user jtillman
aws iam create-user onorris
aws iam create-user spashby
aws iam create-user kjames

aws iam add-user-to-group --group-name root_YMAC_return --user-name cjpoole
aws iam add-user-to-group --group-name root_YMAC_return --user-name jtillman
aws iam add-user-to-group --group-name YMAC_return_basic --user-name onorris
aws iam add-user-to-group --group-name YMAC_return_basic --user-name spashby
aws iam add-user-to-group --group-name YMAC_return_basic --user-name kjames

# Next we will add users to groups
aws iam attach-group-policy

# Using boto, fabric  we will create our instances S3, EC2, RCS

Create our Resources groups
