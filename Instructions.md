Instructions
  On the user deployment machine.
  This is all done from the command line.
  I am guessing if you are on window your best bet might be to use powershell
  Install:
    Boto: pip install boto3         (see https://boto3.readthedocs.org/en/latest/guide/quickstart.html)
    AWSCLI: pip install awscli 
    fabric: pip install fabric
    
Decide if we run from shell or in fabfile in any case:
aws iam create-group --group-name root_YMAC_return
aws iam create-group --group-name YMAC_return_basic

# Next we want to create our users
aws iam create-user cjpoole
aws iam create-user jtillman
aws iam create-user onorris
aws iam create-user spashby
aws iam create-user kjames

aws iam add-user-to-group --group-name --user-name
aws iam add-user-to-group --group-name --user-name
aws iam add-user-to-group --group-name --user-name

# Next we will add users to groups
aws iam attach-group-policy