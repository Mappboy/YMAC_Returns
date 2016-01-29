"""
Fabric file for installing application portal servers for AWS and Mukurtu
Copyright (C) 2016  Cameron Poole

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
Test deployment on EC2 is simple as it only runs on one server
fab test_deploy

The tasks can be used individually and thus allow installations in very
diverse situations.

For a full deployment use the command

fab --set postfix=False -f machine-setup/deploy.py test_deploy

# TODO check all our packages required
# Need to insure we have Apache,  MemCached, Drush, Python, Git, Php,Supervisor
# Need to include sudo a2enmod rewrite for mod_rewrite
# To Permit changes in .htacccess
# sudo nano /etc/apache2/sites-available/default
# Once inside that file, find the following section, and change the line
# that says AllowOverride from None to All. The section should now look
# like this:

# <Directory /var/www/>
#                Options Indexes FollowSymLinks MultiViews
#                AllowOverride All
#                Order allow,deny
#                allow from all
# </Directory>
# After you save and exit that file, restart apache.
# .htacess files will now be available for all of your sites.
# sudo service apache2 restart


"""
# TODO:
# 1 : Major task at the moment is migratation from boto to boto3
# 2 : Read up on elastic ip addresses
# 3 : Read up on S3, RDS, Glacier, Route 53
# 4 : Proper naming of groups, users etc
# 5 : Set up S3
import glob
import inspect

import boto3
import os
import time

from configobj import ConfigObj

from botocore.exceptions import ClientError

from fabric.api import env
from fabric.api import local
from fabric.api import put
from fabric.api import require
from fabric.api import run
from fabric.api import sudo
from fabric.api import task
from fabric.colors import *
from fabric.context_managers import cd
from fabric.context_managers import hide
from fabric.context_managers import settings
from fabric.contrib.console import confirm
from fabric.contrib.files import append
from fabric.contrib.files import comment
from fabric.contrib.files import exists
from fabric.contrib.files import sed
from fabric.decorators import serial
from fabric.decorators import task
from fabric.exceptions import NetworkError
from fabric.network import ssh
from fabric.operations import prompt
from fabric.operations import put
from fabric.utils import abort
from fabric.utils import fastprint
from fabric.utils import puts

from Crypto.PublicKey import RSA

try:
    import urllib2
except:
    import urllib

# Defaults
thisDir = os.path.dirname(os.path.realpath(__file__))

PUBLIC_KEYS = os.path.expanduser('~/.ssh')

config.filename = "mukurtucms.config"
config.write()

config.ConfigObj("mukurtucms.config")

# Set up server values
server_conf = config['Server']
APT_PACKAGES = server_conf['APT_PACKAGES']
PIP_PACKAGES = server_conf['PIP_PACKAGES']
USERNAME = server_conf['ROOT_USER']

# Logging files
log_conf = config['Logs']
HOSTS_FILE = log_conf['HOSTS_FILE']
DB_FILE = log_conf['DB_FILE']
SETUP_FILE = log_conf['SETUP_FILE']
EC2_LOG = log_conf['EC2_LOG']
ssh.util.log_to_file(SETUP_FILE, 10)

# EC2 values
ec2_conf = config['EC2']
POSTFIX = ec2_conf['POSTFIX']
AMI_IDs = ec2_conf['AMI_IDs']
AMI_NAME = ec2_conf['AMI_NAME']
AMI_ID = AMI_IDS[AMI_NAME]
ELASTIC_IP = ec2_conf['ELASTIC_IP']
APP_PYTHON_VERSION = ec2_conf['APP_PYTHON_VERSION']
APP_PYTHON_URL = ec2_conf['APP_PYTHON_URL']
INSTANCE_NAME = ec2_conf['INSTANCE_NAME']
INSTANCE_TYPE = ec2_conf['INSTANCE_TYPE']
INSTANCES_FILE = os.path.expanduser(EC2_LOG)

# RDS configuration
rds_conf = config['RDS']
RDS_PACKAGE = rds_conf['RDS_PACKAGE']
RDS_TYPE = rds_conf['RDS_TYPE']
RDS_STORAGE = rds_conf['RDS_STORAGE']
RDS_MAINTAINENCE = rds_conf['RDS_MAINTAINENCE']
RDS_BACKUP_DAYS = rds_conf['RDS_BACKUP_DAYS']
RDS_BACKUP_TIME = rds_conf['RDS_BACKUP_TIME']
RDS_DATABASE_NAME = rds_conf['RDS_DATABASE_NAME']
RDS_HOST = rds_conf['RDS_HOST']
RDS_PORT = rds_port['RDS_PORT']
RDS_USER = rds_conf['RDS_USER']

# AWS configuration
aws_conf = config['AWS']
AWS_REGION = aws_conf['AWS_REGION']
AWS_PROFILE = aws_conf['AWS_PROFILE']
KEY_NAME = aws_conf['KEY_NAME']
AWS_KEY = os.path.expanduser('~/.ssh/{0}.pem'.format(KEY_NAME))
AWS_SEC_GROUP = aws_conf['AWS_SEC_GROUP']
SECURITY_GROUPS = aws_conf['SECURITY_GROUPS']
ADMIN_POLICIES = aws_conf['ADMIN_POLICIES']
BASIC_POLICIES = aws_conf['BASIC_POLICIES']
ADMINGROUP = aws_conf['ADMINGROUP']
BOTO_CONFIG = os.path.expanduser(aws_conf['BOTO_CONFIG'])
AWS_CONFIG = os.path.expanduser(aws_conf['AWS_CONFIG'])

# Set up mukurtu cms stuff
mucms_conf = config['Mukurtu Setup']
GITUSER = mucms_conf['git_user']
GITREPO = mucms_conf['git_repo']
BRANCH = mucms_conf['git_branch']
USERS = mucms_conf['users']
ADMINISTRATORS = mucms_conf['ADMINISTRATORS']
GROUP = mucms_conf['GROUP']
DEFAULT_PASSWORD = mucms_conf['DEFAULT_PASSWORD']
APACHE_ROOT = mucms_conf['APACHE_ROOT']
APP_DIR = mucms_conf['APP_DIR']
APP_DEF_DB = mucms_conf['APP_DEF_DB']

# s3_conf = config['S3']

@task
def create_aws_user_groups():
    """
    Creates users and groups for AWS with specific permissions
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    client = boto3.client('iam')

    try:
        get_groups = client.list_groups()['Groups']
        created_groups = [group['GroupName'] for group in [json for json in get_groups ] ]
    except:
        puts( red("Couldn't get group list. Code {HTTPStatusCode} ".format(**get_groups['ResponseMetadata'])) )
    # Create security groups
    for sg in SECURITY_GROUPS:
        if sg not in created_groups:
            try:
                client.create_group(GroupName=sg)
            except ClientError as ce:
                puts( red("Problem creating {group} error is {message}".format(group=sg,message=ce.message)))
    # Create users and attach to groups
    for username in USERS:
        try:
            get_users = client.list_users()['Users'] 
            created_users = [ user['UserName'] for user in  [ json for json in get_users ] ]
        except:
            puts( red("Couldn't get user list {HTTPStatusCode}".format(**get_users['ResponseMetadata']) ) )
        if username not in created_users:
            try:
                client.create_user(UserName=username)
                response = client.create_login_profile(
                    UserName=username,
                    Password=DEFAULT_PASSWORD,
                    PasswordResetRequired=True)
            except ClientError as ce:
                puts( red("Problem creating {user} error is {message}".format(user=username,message=ce.message)))
        # Create our admins
        if username in ADMINISTRATORS:
            try:
                client.add_user_to_group(GroupName=ADMINGROUP,
                                    UserName=username
                                        )
            except ClientError as ce:
                puts( red("Problem attaching {user} \
                    to ADMIN GROUP error is {message}".format(
                                                        user=username,
                                                        message=ce.message)))
        else:
            for groups in SECURITY_GROUPS:
                if groups not in ADMINGROUP:
                    try:
                        client.add_user_to_group(GroupName=groups,
                                            UserName=username)
                    except ClientError as ce:
                        puts( red("Problem attaching {user} \
                            to {group} error is {message}".format(
                                                                group=groups,
                                                                user=username,
                                                                message=ce.message)))
    # Attach our security policies to our groups
    arn_polstr = "arn:aws:iam::aws:policy/"
    for policy in ADMIN_POLICIES:
        pol_arn = arn_polstr + policy
        try:
            client.attach_group_policy(GroupName=ADMINGROUP,
                                    PolicyArn=pol_arn)
        except ClientError as ce:
            puts( red("Problem attaching policy {policy}  to {group} error is {message}".format(
                policy=pol_arn,
                group=ADMINGROUP,
                message=ce.message)))
    for policy in BASIC_POLICIES:
        pol_arn = arn_polstr + policy
        try:
            client.attach_group_policy(GroupName=SECURITY_GROUPS[1],
                                    PolicyArn=pol_arn)
        except ClientError as ce:
            puts( red("Problem attaching policy {policy}  to {group} error is {message}".format(
                policy=pol_arn,
                group=SECURITY_GROUPS[1],
                message=ce.message)))
    puts(green("\n***** Completed Setting up User, Groups,Roles and Policies *****\n"))


@task
def aws_create_key_pair():
    """
    Create the AWS_KEY if it does not exist already and copies it into ~/.ssh
    This is the key that will be used to SSH into our Resoueces such as EC2, RDS, S3 
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    if not env.has_key('AWS_PROFILE') or not env.AWS_PROFILE:
        env.AWS_PROFILE = AWS_PROFILE
    client = boto3.client('ec2')
    respone = False
    try:
        response = client.describe_key_pairs(KeyNames=[KEY_NAME])
        puts(green('***** KEY_PAIR exists! *******'))
    except: #key does not exist on AWS
        kp = client.create_key_pair(KeyName=KEY_NAME)
        puts(green("\n******** KEY_PAIR created!********\n"))
        if os.path.exists(os.path.expanduser(AWS_KEY)):
            os.unlink(AWS_KEY)
        with open(os.path.expanduser(AWS_KEY),'w') as key_file:
            key_file.write(kp['KeyMaterial'])
        Rkey = RSA.importKey(kp['KeyMaterial'])
        env.SSH_PUBLIC_KEY = Rkey.exportKey('OpenSSH')
        puts(green("\n******** KEY_PAIR written!********\n"))

    if not os.path.exists(os.path.expanduser(AWS_KEY)): # don't have the private key
        if not response:
            response = client.describe_key_pairs(KeyNames=[KEY_NAME])
        puts(green("\n******** KEY_PAIR retrieved********\n"))
        Rkey = RSA.importKey(response['KeyMaterial'])
        env.SSH_PUBLIC_KEY = Rkey.exportKey('OpenSSH')
        with open(os.path.expanduser(AWS_KEY),'w') as key_file:
            key_file.write(kp['KeyMaterial'])
        Rkey = RSA.importKey(kp['KeyMaterial'])
        puts(green("\n******** KEY_PAIR written!********\n"))
    local('chmod 400 {}'.format(os.path.expanduser(AWS_KEY)))
    puts(green("\n******** Task {0} finished!********\n".\
        format(inspect.stack()[0][3])))


@task
def check_create_aws_sec_group():
    """
    Check whether default security group exists
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    client = boto3.client('ec2')
    ec2 = boto3.resource('ec2')
    sec = client.describe_security_groups()
    security_group = ec2.SecurityGroup('id')
    if map(lambda x:x.upper(), [ s['GroupName'] for s in sec['SecurityGroups'] ]).count(AWS_SEC_GROUP):
        puts(green("\n******** Group {0} exists!********\n".format(AWS_SEC_GROUP)))
        response = filter(lambda x: x['GroupName'] == AWS_SEC_GROUP, sec['SecurityGroups'])[0]
    else:
        response = client.create_security_group(GroupName=AWS_SEC_GROUP,
                                                Description='YMACRETURN default permissions')
    ymrsg = ec2.SecurityGroup(response['GroupId'])
    # SSH
    try:
        ymrsg.authorize_ingress(IpProtocol='tcp', FromPort=22, ToPort=22, CidrIp='0.0.0.0/0')
        # HTTP
        ymrsg.authorize_ingress(IpProtocol='tcp', FromPort=80, ToPort=80, CidrIp='0.0.0.0/0')
        ymrsg.authorize_ingress(IpProtocol='tcp', FromPort=443, ToPort=443, CidrIp='0.0.0.0/0')
        # MySQL
        ymrsg.authorize(IpProtocol='tcp', FromPort=3306, ToPort=3306, CidrIp='0.0.0.0/0')
    except:
        puts("security_group already exists")
            # NOTE NOT SURE ABOUT THE FOLLOWING
    # ymrsg.authorize('tcp', 5678, 5678, '0.0.0.0/0')
    
    # ymrsg.authorize('tcp', 7777, 7777, '0.0.0.0/0')
    # ymrsg.authorize('tcp', 8888, 8888, '0.0.0.0/0')
    puts(green("\n******** Task {0} finished!********\n".\
        format(inspect.stack()[0][3])))


@task
def delete_key_pair():
    """
    delete our key key_pair
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    try:
        client = boto3.client('ec2')
        response = client.delete_key_pair(KeyName=KEY_NAME)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            puts(green("Deleted {}".format(KEY_NAME)))
        else:
            puts(red("Something bad happened {}".format(response)))
    except:
        puts(red("Something bad happened, Key probably doesn't exist"))
    puts(green("\n******** Task {0} finished!********\n".\
        format(inspect.stack()[0][3])))


@task
def whatsmyip():
    """
    Returns the external IP address of the host running fab.

    NOTE: This is only used for EC2 setups, thus it is assumed
    that the host is on-line.
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    whatismyip = 'http://bot.whatismyipaddress.com/'
    try:
        myip = urllib2.urlopen(whatismyip).readlines()[0]
    except NameError:
        myip = urllib.urlopen(whatismyip).readlines()[0]
    except:
        puts(red('Unable to derive IP through {0}'.format(whatismyip)))
        myip = '127.0.0.1'
    puts(green('IpAddress = "{0}"'.format(myip)))

    return myip


@task
def check_ssh():
    """
    Check availability of SSH on HOST
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))

    if not env.has_key('key_filename') or not env.key_filename:
        env.key_filename = AWS_KEY
    else:
        puts(red("SSH key_filename: {0}".format(env.key_filename)))
    if not env.has_key('user') or not env.user:
        env.user = USERNAME
    else:
        puts(red("SSH user name: {0}".format(env.user)))

    ssh_available = False
    ntries = 10
    tries = 0
    t_sleep = 30
    while tries < ntries and not ssh_available:
        try:
            run("echo 'Is SSH working?'", combine_stderr=True)
            ssh_available = True
            puts(green("SSH is working!"))
        except NetworkError:
            puts(red("SSH is NOT working after {0} seconds!".format(str(tries*t_sleep))))
            tries += 1
            time.sleep(t_sleep)

@task
def get_host_names():
    """
    Sets host names by creating a new instance
    Or checking our hosts file
    """
    with open(HOSTS_FILE,'r') as hf:
        hostnames = [ line.rstrip("\n") for line in hf.readlines() ] 
    puts(green("Found hosts {}".format(hostnames)))
    env.hosts = hostnames
    if not env.host_string:
        env.host_string = env.hosts[0]

@task
def get_db():
    if os.path.isdir(DB_FILE):
        with open(DB_FILE,'r') as db_file:
            for line in db_file.xreadlines():
                line = line.rstrip("\n")
                db, port = line.split(":")
    else:
        client = boto3.client('rds')
        rds = client.describe_db_instances()
        db, port = '{DBInstances[0][Endpoint][Address]}:{DBInstances[0][Endpoint][Port]}\n'.format(**rds).split(":")
    return (db, port)

@task
def set_env():
    # set environment to default for EC2, if not specified on command line.
    # THIS NEEDS FIXING SHOULD ALSO SET RDS and S3 envs 
    # puts(env)
    get_host_names()
    if not env.has_key('GITUSER') or not env.GITUSER:
        env.GITUSER = GITUSER
    if not env.has_key('GITREPO') or not env.GITREPO:
        env.GITREPO = GITREPO
    if not env.has_key('postfix') or not env.postfix:
        env.postfix = POSTFIX
    if not env.has_key('key_filename') or not env.key_filename:
        env.key_filename = AWS_KEY
    if not env.has_key('db_host') or not env.db_host:
        env.db_host, env.db_port = get_db()
    if not env.has_key('User') or not env.User:
        env.user = USERNAME
    if not env.has_key('USERS') or not env.USERS:
        env.USERS = USERS
    if type(env.USERS) == type(''): # if its just a string
        puts("USERS preset to {0}".format(env.USERS))
        env.USERS = [env.USERS] # change the type
    if not env.has_key('HOME') or env.HOME[0] == '~' or not env.HOME:
        env.HOME = run("echo ~{0}".format(env.USERS[0]))
    if not env.has_key('src_dir') or not env.src_dir:
        env.src_dir = thisDir
    require('hosts', provided_by=[get_host_names, test_env])
    if not env.has_key('hosts') or not env.hosts:
        env.hosts = get_host_names()
    if not env.has_key('host_string') or not env.host_string:
        env.host_string = get_host_names()
    # Maybe load hosts from host file
    # if not env.has_key('host_string'):
    # open hosts file and attempt to load host from that
    if not env.has_key('HOME') or env.HOME[0] == '~' or not env.HOME:
        env.HOME = run("echo ~{0}".format(USERS[0]))
    if not env.has_key('PREFIX') or env.PREFIX[0] == '~' or not env.PREFIX:
        env.PREFIX = env.HOME
    if not env.has_key('APP_DIR_ABS') or env.APP_DIR_ABS[0] == '~' \
    or not env.APP_DIR_ABS:
        env.APP_DIR_ABS = '{0}/{1}'.format(env.PREFIX, APP_DIR)
        env.APP_DIR = APP_DIR
    else:
        env.APP_DIR = APP_DIR#env.APP_DIR_ABS.split('/')[-1]
    if not env.has_key('force') or not env.force:
        env.force = 0
    if not env.has_key('ami_name') or not env.ami_name:
        env.ami_name = 'CentOS'
    env.AMI_ID = AMI_IDs[env.ami_name]
    if env.ami_name == 'SLES':
        env.user = 'root'
    get_linux_flavor()
    puts("""Environment:
            USER:              {0};
            Key file:          {1};
            hosts:             {2};
            host_string:       {3};
            postfix:           {4};
            HOME:              {8};
            APP_DIR_ABS:       {5};
            APP_DIR:           {6};
            USERS:             {7};
            PREFIX:            {9};
            SRC_DIR:           {10}
            RDS                {11};
            """.\
            format(env.user, env.key_filename, env.hosts,
                   env.host_string, env.postfix, env.APP_DIR_ABS,
                   env.APP_DIR, env.USERS, env.HOME, env.PREFIX, 
                   env.src_dir, env.db_host))



@task(alias='setup')
def check_setup():
    """ Check current user has everything required to deploy 

    Includes boto config/aws config 
    Security keys, possibly check permissions
    """
    if not os.path.isfile(BOTO_CONFIG) and not os.path.isfile(AWS_CONFIG):
        abort('Require boto config or aws config to create instance')
    # Check if user can import Flask
    # Check if user can import boto
    

@task
def create_rds(name, tag, username='cjpoole', password='YamatjiReturns', dbtype='DEV', enhanced_monitoring=False):
    """
    Create our RDS Instance
    :param name: the name to be used for this instance
    :param tags: tag to be associated with our instance
    :param type: DEV or PRODUCTION
    # NEED TO SET SecurityGroup = YMACRETURN

    NOTE: You will need to create emaccess role if you want enhanced MonitoringInterval
            - see http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.html#USER_Monitoring.OS.IAMRole
    """

    # TODO:  Not sure about VPC Security Groups 
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    ec2_client = boto3.client('ec2')
    sec_groups = ec2_client.describe_security_groups(GroupNames=[AWS_SEC_GROUP])
    group_id = sec_groups['SecurityGroups'][0]['GroupId']
    client = boto3.client('rds')
    RDS_TAGS = [ {'Key':'Name', 'Value':tag} ]
    if enhanced_monitoring:
        reponse = client.create_db_instance(
                                DBName=name,
                                DBInstanceIdentifier="{}-{}".format(name,dbtype),
                                AllocatedStorage=RDS_STORAGE,
                                DBInstanceClass=RDS_TYPE,
                                Engine=RDS_PACKAGE,
                                MasterUsername=username,
                                MasterUserPassword=password,
                                PreferredMaintenanceWindow=RDS_MAINTAINENCE,
                                BackupRetentionPeriod=RDS_BACKUP_DAYS,
                                PreferredBackupWindow=RDS_BACKUP_TIME,
                                Tags=RDS_TAGS,
                                MonitoringInterval=15,
                                MonitoringRoleArn='arn:aws:iam::512935204824:role/emaccess',
                                VpcSecurityGroupIds=[group_id]
                                )
    else:
        response = client.create_db_instance(
                                DBName=name,
                                DBInstanceIdentifier="{}-{}".format(name,dbtype),
                                AllocatedStorage=RDS_STORAGE,
                                DBInstanceClass=RDS_TYPE,
                                Engine=RDS_PACKAGE,
                                MasterUsername=username,
                                MasterUserPassword=password,
                                PreferredMaintenanceWindow=RDS_MAINTAINENCE,
                                BackupRetentionPeriod=RDS_BACKUP_DAYS,
                                PreferredBackupWindow=RDS_BACKUP_TIME,
                                VpcSecurityGroupIds=[group_id],
                                Tags=RDS_TAGS)
    puts(blue(response))
    puts(green("\n******** Task {0} finished!********\n".\
        format(inspect.stack()[0][3])))
    return response


@task
def create_instance(names,  tags='', use_elastic_ip=False, public_ips=''):
    """Create the EC2 instance. Pass names, public ips as pipe-del strings
    i.e names='myname1|myname2'
    Pass tags as comma and colon delim string
    i.e tags='key,value:name,dev:resource,ec2:claim-group,yinhawankga'

    :param names: the name to be used for this instance
    :type names: list of strings
    :param boolean use_elastic_ip: is this instance to use an Elastic IP address
    :param tags: list of tags to be associated with our instance
    :type tags: list of strings

    :rtype: string
    :return: The public host name of the AWS instance
    TODO: Test All AMIS
    """
    puts('Creating instances {0} {1} [{2}:{3}]'.format(names, tags, use_elastic_ip, public_ips))
    number_instances = len(names.split("|"))
    names = names.split("|")
    if number_instances > 1 and number_instances != len(public_ips):
        abort('The lists do not match in length')

    # This relies on a ~/.boto file holding the '<aws access key>', '<aws secret key>'
    client = boto3.client('ec2')
    ec2 = boto3.resource('ec2')

    if use_elastic_ip:
        # Disassociate the public IP
        public_ips = public_ips.split("|")
        for public_ip in public_ips:
            if not client.disassociate_address(PublicIp=public_ip):
                abort('Could not disassociate the IP {0}'.format(public_ip))


    reservations = client.run_instances(
                                        ImageId=AMI_IDs[AMI_NAME], 
                                        InstanceType=INSTANCE_TYPE,
                                        KeyName=KEY_NAME, 
                                        SecurityGroups=[AWS_SEC_GROUP],
                                        MinCount=number_instances, 
                                        MaxCount=number_instances,
                                        )

    instances = reservations['Instances']
    # Sleep so Amazon recognizes the new instance
    for i in range(4):
        fastprint('.')
        time.sleep(5)

    # Are we running yet?
    iid = []
    for i in range(number_instances):
        iid.append(instances[i]['InstanceId'])

    stat = [ ec2.Instance(i) for i in iid ]
    running = [x.state['Name'] =='running' for x in stat]
    puts('\nWaiting for instances to be fully available:\n')
    while not all(running):
        fastprint('.')
        time.sleep(5)
        for instance in stat:
            instance.reload()
        running = [x.state['Name'] =='running' for x in stat]
    puts('.') #enforce the line-end

    # Local user and host
    userAThost = os.environ['USER'] + '@' + whatsmyip()

    # Create tag list of dicts
    ec2_tags = [ dict(zip(['Key','Value'],tag.split(":"))) for tag in [ tstr for tstr in tags.split("|")] ]
    # Tag the instance
    ec2_tags.append({'Key': 'Created By','Value':userAThost})
    for i, instance in enumerate(stat):
        ec2_tags.append({'Key': 'Name', 'Value': names[i]} )
        instance.create_tags(Tags=ec2_tags)
        ec2_tags.pop()


    # Associate the IP if needed
    if use_elastic_ip:
        for i, instance in enumerate(stat):
            puts('Current DNS name is {0}. About to associate the Elastic IP'.format(instance.private_dns_name))
            if not instance.associate_address(InstanceId=instance.instance.id, PublicIp=public_ips[i]):
                abort('Could not associate the IP {0} to the instance {1}'.format(public_ips[i], instance.instance_id))

    # Load the new instance data as the dns_name may have changed
    host_names = []
    for instance in stat:
        instance.reload()
        puts('Current DNS name is {0} after associating the Elastic IP'.format(instance.public_dns_name))
        puts('Instance ID is {0}'.format(instance.instance_id))
        print blue('In order to terminate this instance you can call:')
        print blue('fab terminate:instance_id={0}'.format(instance.id))
        host_names.append(str(instance.public_dns_name))
        with open( HOSTS_FILE, 'a' ) as hf:
            hf.write("{}\n".format(instance.public_dns_name))

    # The instance is started, but not useable (yet)
    puts('Started the instance(s) now waiting for the SSH daemon to start.')
    env.host_string = host_names[0]

    if AMI_NAME in ['CentOS', 'SLES']:
        env.user = 'root'
    elif AMI_NAME == 'Ubuntu':
        env.user = 'ubuntu'
    else:
        env.user = USERNAME
    check_ssh()
    return host_names

@task
def destroy_all_instances():
    """
    Shuts down all ec2 instances
    TODO: remove these instances from mour hosts file
    """
    ec2_client = boto3.client('ec2')
    instance_ids = [ i[0]['InstanceId'] for i in [ inst['Instances'] for inst in 
                     ec2_client.describe_instances()['Reservations'] ] ]
    ec2_client.terminate_instances(InstanceIds=instance_ids)
    local('rm {}'.format(HOSTS_FILE))

@task
def get_linux_flavor():
    """
    Obtain and set the env variable linux_flavor
    """
    if (check_path('/etc/issue')):
        re = run('cat /etc/issue')
        linux_flavor = re.split()
        if (len(linux_flavor) > 0):
            if linux_flavor[0] == 'CentOS' or linux_flavor[0] == 'Ubuntu' \
               or linux_flavor[0] == 'Debian':
                linux_flavor = linux_flavor[0]
            elif linux_flavor[0] == 'Amazon':
                linux_flavor = ' '.join(linux_flavor[:2])
            elif linux_flavor[2] == 'SUSE':
                linux_flavor = linux_flavor[2]
    else:
        linux_flavor = run('uname -s')

    puts(green("Remote machine running %s" % linux_flavor))
    env.linux_flavor = linux_flavor
    return linux_flavor



def to_boolean(choice, default=False):
    """Convert the yes/no to true/false

    :param choice: the text string input
    :type choice: string
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    choice_lower = choice.lower()
    if choice_lower in valid:
        return valid[choice_lower]
    return default

def check_command(command):
    """
    Check existence of command remotely

    INPUT:
    command:  string

    OUTPUT:
    Boolean
    """
    res = run('if command -v {0} &> /dev/null ;then command -v {0};else echo ;fi'.format(command))
    return res

def check_dir(directory):
    """
    Check existence of remote directory
    """
    res = run('if [ -d {0} ]; then echo 1; else echo ; fi'.format(directory))
    return res


def check_path(path):
    """
    Check existence of remote path
    """
    res = run('if [ -e {0} ]; then echo 1; else echo ; fi'.format(path))
    return res


def check_python():
    """
    Check for the existence of correct version of python

    INPUT:
    None

    OUTPUT:
    path to python binary    string, could be empty string
    """
    # Try whether there is already a local python installation for this user
    ppath = os.path.realpath(env.APP_DIR_ABS+'/../python')
    ppath = check_command('{0}/bin/python{1}'.format(ppath, APP_PYTHON_VERSION))
    if ppath:
        return ppath
    # Try python2.7 first
    ppath = check_command('python{0}'.format(APP_PYTHON_VERSION))
    if ppath:
        env.PYTHON = ppath
        return ppath


def install_yum(package):
    """
    Install a package using YUM
    """
    errmsg = sudo('yum --assumeyes --quiet install {0}'.format(package),\
                   combine_stderr=True, warn_only=True)
    processCentOSErrMsg(errmsg)


@task
def install_apt(package):
    """
    Install a package using APT

    NOTE: This requires sudo access
    """
    sudo('apt-get -qq -y install {0}'.format(package))


def check_yum(package):
    """
    Check whether package is installed or not

    NOTE: requires sudo access to machine
    """
    with hide('stdout','running','stderr'):
        res = sudo('yum --assumeyes --quiet list installed {0}'.format(package), \
             combine_stderr=True, warn_only=True)
    # print res
    if res.find(package) > 0:
        print "Installed package {0}".format(package)
        return True
    else:
        print "NOT installed package {0}".format(package)
        return False


def check_apt(package):
    """
    Check whether package is installed using APT

    NOTE: This requires sudo access
    """
    with hide('stdout','running'):
        res = sudo('dpkg -L | grep {0}'.format(package))
    if res.find(package) > -1:
        print "Installed package {0}".format(package)
        return True
    else:
        print "NOT installed package {0}".format(package)
        return False


def copy_public_keys():
    """
    Copy the public keys to the remote servers
    """
    env.list_of_users = []
    for file in glob.glob(PUBLIC_KEYS + '/*.pub'):
        filename = '.ssh/{0}'.format(os.path.basename(file))
        user, ext = os.path.splitext(filename)
        env.list_of_users.append(user)
        put(file, filename)


def virtualenv(command):
    """
    Just a helper function to execute commands in the virtualenv
    """
    env.activate = 'source {0}/bin/activate'.format(env.APP_DIR_ABS)
    with cd(env.APP_DIR_ABS):
        run(env.activate + '&&' + command)

@task
def git_clone():
    """
    Clones the repository.
    """
    print(green("Cloning from GitHub..."))
    copy_public_keys()
    with cd(APACHE_ROOT):
        try:
            sudo('git clone https://{1}.git'.format(env.GITUSER, env.GITREPO))
        except:
            gituser = raw_input("Enter git user name")
            sudo('git clone https://{1}.git'.format(gituser,env.GITREPO))

    print(green("Clone complete"))

@task
def git_pull():
    """
    Update repo
    """
    copy_public_keys()
    with cd(APACHE_ROOT + APP_DIR ):
        sudo('git pull')

@task
def git_clone_tar():
    """
    Clones the repository into /tmp and packs it into a tar file

    TODO: This does not work outside iVEC. The current implementation
    is thus using a tar-file, copied over from the calling machine.
    """
    set_env()
    with cd('/tmp'):
        local('cd /tmp && git clone {0}@{1}'.format(env.GITUSER, env.GITREPO))
        local('cd /tmp && tar -cjf {0}.tar.bz2 {0}'.format(APP_DIR))
        tarfile = '{0}.tar.bz2'.format(APP_DIR)
        put('/tmp/{0}'.format(tarfile), tarfile)
        local('rm -rf /tmp/{0}'.format(APP_DIR))  # cleanup local git clone dir
        run('tar -xjf {0} && rm {0}'.format(tarfile))


def processCentOSErrMsg(errmsg):
    if (errmsg == None or len(errmsg) == 0):
        return
    if (errmsg == 'Error: Nothing to do'):
        return
    firstKey = errmsg.split()[0]
    if (firstKey == 'Error:'):
        abort(errmsg)


@task
def system_install():
    """
    Perform the system installation part.

    NOTE: Most of this requires sudo access on the machine(s)
    """
    set_env()

    # Install required packages
    re = run('cat /etc/issue')
    linux_flavor = re.split()
    if (len(linux_flavor) > 0):
        if linux_flavor[0] == 'CentOS':
            linux_flavor = linux_flavor[0]
        elif linux_flavor[0] == 'Amazon':
            linux_flavor = ' '.join(linux_flavor[:2])
    if (linux_flavor in ['CentOS','Amazon Linux']):
        # Update the machine completely
        errmsg = sudo('yum --assumeyes --quiet update', combine_stderr=True, warn_only=True)
        processCentOSErrMsg(errmsg)
        for package in YUM_PACKAGES:
            install_yum(package)

    elif ('Ubuntu' in linux_flavor):
        sudo('apt-get update')
        for package in APT_PACKAGES:
            install_apt(package)
    else:
        abort("Unknown linux flavor detected: {0}".format(re))


@task
def system_check():
    """
    Check for existence of system level packages

    NOTE: This requires sudo access on the machine(s)
    """
    with hide('running','stderr','stdout'):
        set_env()

        re = run('cat /etc/issue')
    linux_flavor = re.split()
    if (len(linux_flavor) > 0):
        if linux_flavor[0] == 'CentOS':
            linux_flavor = linux_flavor[0]
        elif linux_flavor[0] == 'Amazon':
            linux_flavor = ' '.join(linux_flavor[:2])

    summary = True
    if (linux_flavor in ['CentOS','Amazon Linux']):
        for package in YUM_PACKAGES:
            if not check_yum(package):
                summary = False
    elif (linux_flavor == 'Ubuntu'):
        for package in APT_PACKAGES:
            if not check_apt(package):
                summary = False
    else:
        abort("Unknown linux flavor detected: {0}".format(re))
    if summary:
        print "\n\nAll required packages are installed."
    else:
        print "\n\nAt least one package is missing!"


@task
def postfix_config():
    """
    Setup the e-mail system for
    notifications. It requires access to an SMTP server.
    """

    if 'gmail_account' not in env:
        prompt('GMail Account:', 'gmail_account')
    if 'gmail_password' not in env:
        prompt('GMail Password:', 'gmail_password')

    # Setup postfix
    sudo('service sendmail stop')
    sudo('service postfix stop')
    sudo('chkconfig sendmail off')
    sudo('chkconfig sendmail --del')

    sudo('chkconfig postfix --add')
    sudo('chkconfig postfix on')

    sudo('service postfix start')

    sudo('''echo "relayhost = [smtp.gmail.com]:587
    smtp_sasl_auth_enable = yes
    smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
    smtp_sasl_security_options = noanonymous
    smtp_tls_CAfile = /etc/postfix/cacert.pem
    smtp_use_tls = yes
    
    # smtp_generic_maps
    smtp_generic_maps = hash:/etc/postfix/generic
    default_destination_concurrency_limit = 1" >> /etc/postfix/main.cf''')

    sudo('echo "[smtp.gmail.com]:587 {0}@gmail.com:{1}" > /etc/postfix/sasl_passwd'.format(env.gmail_account, env.gmail_password))
    sudo('chmod 400 /etc/postfix/sasl_passwd')
    sudo('postmap /etc/postfix/sasl_passwd')


@task
def user_setup():
    """
    setup YMAC_Return users.
    sort this all
    TODO: sort out the ssh keys
    """

    set_env()
    sudo('groupadd {0}'.format(GROUP), warn_only=True)
    for user in env.USERS:
        sudo('useradd -g {0},www-data -m -s /bin/bash {1}'.format(GROUP, user), warn_only=True)
        sudo('mkdir /home/{0}/.ssh'.format(user), warn_only=True)
        sudo('chmod 700 /home/{0}/.ssh'.format(user))
        sudo('chown -R {0}:{1} /home/{0}/.ssh'.format(user,GROUP))
        home = run('echo $HOME')
        sudo('cp {0}/.ssh/authorized_keys /home/{1}/.ssh/authorized_keys'.format(home, user))
        sudo('chmod 600 /home/{0}/.ssh/authorized_keys'.format(user))
        sudo('chown {0}:{1} /home/{0}/.ssh/authorized_keys'.format(user, GROUP))
    # change to allow group permissions to acces home
        # sudo('chmod g+rwx /home/{0}/'.format(user))
        
    # create YMAC_Return directories and chown to correct user and group
    sudo('mkdir -p {0}'.format(env.APP_DIR_ABS))
    # This not working for some reason
    sudo('chown -R {0}:{1} {2}'.format(env.USERS[0], GROUP, env.APP_DIR_ABS))
    
    # These lines are unnecessary i think
    # sudo('mkdir -p {0}/../YMAC_Return'.format(env.APP_DIR_ABS))
    # sudo('chown {0}:{1} {2}/../YMAC_Return'.format(env.USERS[0], GROUP, env.APP_DIR_ABS))
    # sudo('usermod -a -G {} ec2-user'.format(GROUP))
    print "\n\n******** USER SETUP COMPLETED!********\n\n"


@task
def python_setup():
    """
    Ensure that there is the right version of python available
    If not install it from scratch in user directory.

    INPUT:
    None

    OUTPUT:
    None
    """
    set_env()

    with cd('/tmp'):
        run('wget --no-check-certificate -q {0}'.format(APP_PYTHON_URL))
        base = os.path.basename(APP_PYTHON_URL)
        pdir = os.path.splitext(os.path.splitext(base)[0])[0]
        run('tar -xjf {0}'.format(base))
    ppath = run('echo $PWD') + '/python'
    with cd('/tmp/{0}'.format(pdir)):
        run('./configure --prefix {0};make;make install'.format(ppath))
        ppath = '{0}/bin/python{1}'.format(ppath,APP_PYTHON_VERSION)
    env.PYTHON = ppath
    print "\n\n******** PYTHON SETUP COMPLETED!********\n\n"

@task
def package_install(all=True,package=''):
    """
    Install required python packages.
    """
    if all:
        for p in PIP_PACKAGES:
            sudo('pip install {}'.format(p))
    else:
        sudo('pip install {}'.format(package))

@task
def new_package(package):
    set_env()
    package_install(all=False,package=package)


@task
@serial
def test_env():
    """Configure the test environment on EC2

    Ask a series of questions before deploying to the cloud.

    Allow the user to select if a Elastic IP address is to be used

    TODO: Need to sort out instance names and tags
    """
    puts(blue("\n***** Entering task {0} *****\n".format(inspect.stack()[0][3])))
    if not env.has_key('AWS_PROFILE') or not env.AWS_PROFILE:
        env.AWS_PROFILE = AWS_PROFILE
    if not env.has_key('BRANCH') or not env.BRANCH:
        env.BRANCH = BRANCH
    if not env.has_key('instance_name') or not env.instance_name:
        env.instance_name = INSTANCE_NAME.format(env.BRANCH)
    if not env.has_key('use_elastic_ip') or not env.use_elastic_ip:
        env.use_elastic_ip = ELASTIC_IP
    if not env.has_key('key_filename') or not env.key_filename:
        env.key_filename = AWS_KEY
    if not env.has_key('AMI_NAME') or not env.AMI_NAME:
        env.AMI_NAME = AMI_NAME
    env.instance_name = INSTANCE_NAME.format(env.BRANCH)
    if not env.has_key('User') or not env.User:
        env.User = USERNAME
    env.use_elastic_ip = ELASTIC_IP
    if 'use_elastic_ip' in env:
        use_elastic_ip = to_boolean(env.use_elastic_ip)
    else:
        use_elastic_ip = confirm('Do you want to assign an Elastic IP to this instance: ', False)

    public_ip = None
    if use_elastic_ip:
        if 'public_ip' in env:
            public_ip = env.public_ip
        else:
            public_ip = prompt('What is the public IP address: ', 'public_ip')

    if 'instance_name' not in env:
        prompt('AWS Instance name: ', 'instance_name')

    if env.AMI_NAME in ['CentOS', 'SLES']:
        env.user = 'root'
    elif 'Ubuntu' in env.AMI_NAME:
        env.user = 'ubuntu'
    else:
        env.user = 'ec2-user'
    # Check and create the key_pair if necessary
    aws_create_key_pair()
    # Check user, groups and policies
    create_aws_user_groups()
    # Check and create security group if necessary
    check_create_aws_sec_group()
    # Create the instance in AWS
    tags = 'instance:dev'
    host_names = create_instance(env.instance_name, tags , use_elastic_ip, [public_ip])
    # TODO: test for rds first
    try:
        rds = create_rds(RDS_DATABASE_NAME,'rds')
    except:
        puts("Database exists")
    # TODO: Save rds host somewhere
    try:
        with open(DB_FILE,'a') as rds_file:
            rds_file.write('{DBInstance[Endpoint][Address]}:{DBInstance[Endpoint][Port]}\n'.format(**rds) )
    except:
        rds_client = boto3.client('rds')
        rds = rds_client.describe_db_instances()
        with open(DB_FILE,'a') as rds_file:
            rds_file.write('{DBInstances[0][Endpoint][Address]}:{DBInstances[0][Endpoint][Port]}\n'.format(**rds) )

    env.hosts = host_names
    if not env.host_string:
        env.host_string = env.hosts[0]

    env.key_filename = AWS_KEY
    env.roledefs = {
        'YMAC_Returnmgr' : host_names,
        'YMAC_Return' : host_names,
    }
    puts(green("\n******** EC2 INSTANCE SETUP COMPLETE!********\n"))


@task
def local_deploy():
    """
    Deploy to local system
    """
    local('../YMAC_Return.sh -l')


@task
def user_deploy():
    """
    Deploy the system as a normal user without sudo access
    """
    env.hosts = ['localhost',]
    set_env()
    ppath = check_python()
    if not ppath:
        python_setup()
    else:
        env.PYTHON = ppath
    package_install()


@task
def quick_job():
    if not env.has_key('APP_DIR_ABS') or not env.APP_DIR_ABS:
        env.APP_DIR_ABS = '{0}/{1}/{2}/{3}'.format('/home',USERS[0],'YMAC_Return_portal', APP_DIR)
    
    # check if git repo exists pull else clone
    print(red("Initialising deployment"))
    set_env()
    with settings(user='ubuntu'):
        puts("attempting git_clone")
        git_clone()

@task
def write_apache_config():
    """
    Writes our config file for apache2
    """
    conf_file = """<VirtualHost *:80>
    ServerName  example.com
    ServerAdmin webmaster@example.com
    DocumentRoot /var/www/html/mukurtucms

    <Directory /var/www/html/mukurtucms>
        AllowOverride All
    </Directory>
</VirtualHost>
"""
    with open("default.conf", "w") as apache_conf:
        apache_conf.write(conf_file)

    put("default.conf","/etc/apache2/sites-enabled/", use_sudo=True)

@task
def init_deploy():
    """
    Install the init script for an operational deployment
    Requires user with sudo access
    mukurtucms should be put into /var/www/html I think 
    then tell user to visit

    http://ec2-52-62-205-115.ap-southeast-2.compute.amazonaws.com/mukurtucms/install.php?profile=mukurtu
    """
    # check if git repo exists pull else clone
    # TODO: Create private dir else where and make sure it is settable by www-data 
    print(red("Initialising deployment"))
    set_env()
    with settings(user='ubuntu'):
        # if check_dir(env.APP_DIR_ABS):
        if check_dir(APACHE_ROOT + APP_DIR):
            puts("attempting git pull")
            git_pull()
        else:
            puts("attempting git_clone")
            git_clone()
    puts(green("Fixing mysql"))
    write_apache_config()
    sudo('sudo a2enmod rewrite')
    sudo("sed 's/bind-address/#bind-address/' /etc/mysql/my.cnf > /etc/mysql/my.cnf.new")
    sudo('mv /etc/mysql/my.cnf /etc/mysql/my.cnf.old')
    sudo('mv /etc/mysql/my.cnf.new /etc/mysql/my.cnf')
    sudo('sudo chown -R :www-data /var/www/html/*')
    sudo('cp /etc/php5/apache2/php.ini /etc/php5/apache2/php.ini.orig')
    sudo("sed 's/expose_php = Off/expose_php = Off/' /etc/php5/apache2/php.ini \
        | sed 's/allow_url_fopen = On/allow_url_fopen = Off/' >  /etc/php5/apache2/php.ini")
    sudo("mv /etc/apache2/sites-enabled/default.conf /etc/apache2/sites-enabled/000-default.conf")
    with cd(APACHE_ROOT + APP_DIR):
        sites_dir = 'sites/default/files'
        if check_dir(sites_dir):
            sudo('chmod a+w sites/default/files')
        else:
            sudo("mkdir {}".format(sites_dir))
            sudo('chmod a+w sites/default/files')

        # TODO: 
        #    - We need to set our RDS values in settings.php
        #
        sudo("head -n 572 sites/default/default.settings.php  > sites/default/settings.php")
        sudo("""echo "$databases" = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => '{}',
      'username' => '{}',
      'password' => '{}',
      'host' => '{}',
      'port' => '{}',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);


# mukurtu customizations (generally leave as is)
"$conf"['error_level'] = 0;      >> sites/default/settings.php
            """.format(RDS_DATABASE_NAME, RDS_USER, DEFAULT_PASSWORD, env.db_host,env.db_port))
        

        # sudo('cp sites/default/default.settings.php sites/default/settings.php')
        sudo('chown root:www-data sites/default/settings.php')
        sudo('chmod 664 sites/default/settings.php')
        sudo('chmod a+w sites/default/')

    sudo('service apache2 restart')

    # sudo('service mysql restart')
    # sudo('mkdir -p /etc/supervisor/')
    # sudo('mkdir -p /etc/supervisor/conf.d/')
        
    # check if nginx is running else
    print(red("Server setup and ready to deploy"))
    # Think we have 



@task(alias='run')
def deploy():
    """Runs deployment"""
    set_env()
    env.user ='ec2-user'
    print(red("Beginning Deploy:"))
    # might need setenv 
    # create_db()
    # sudo(virtualenv('supervisorctl restart YMAC_Return'))


    print(blue("Deploy finished check server {}".format(env.host_string)))


@task(alias='update')
def update_deploy():
    """
    Stop app running
    Update git repository and db etc
    TODO: maybe use zc.buildout
    """
    set_env()
    # sudo(virtualenv('supervisorctl restart YMAC_Return'))
    git_pull()

    # Stop Apache if need be
    # restart it 

@task
@serial
def operations_deploy():
    """
    ** MAIN TASK **: Deploy the full operational environment.
    In order to install on an operational host go to any host
    where the application is already running or where you have git-cloned the
    software and issue the command:

    fab -u <super-user> -H <host> operations_deploy

    where <super-user> is a user on the target machine with root priviledges
    and <host> is either the DNS resolvable name of the target machine or
    its IP address.
    """

    if not env.user:
        env.user = 'root'
    # set environment to default, if not specified otherwise.
    set_env()
    system_install()
    if env.postfix:
        postfix_config()
    user_setup()
    with settings(user='ubuntu'):
        ppath = check_python()
        if not ppath:
            python_setup()
        # package_install()
    init_deploy()

@task
def install(standalone=0):
    """
    Install YMAC_Return users and YMAC_Return software on existing machine.
    Note: Requires root permissions!
    """
    set_env()
    user_setup()
    print(green("Setting up python path"))
    print("Users {}".format(env.USERS))
    with settings(user=env.USERS[0]):
        ppath = check_python()
        if not ppath:
            python_setup()
    print(green("Setting up home directory might require chmod"))
    if env.PREFIX != env.HOME: # generate non-standard directory
        sudo('mkdir -p {0}'.format(env.PREFIX))
    # Removing this for the moment so we can use ec2-user to deploy with root permissions
        sudo('chown -R {0}:{1} {2}'.format(env.USERS[0], GROUP, env.PREFIX))
    print(green("Setting up virtual env"))
    # with settings(user=env.USERS[0]):
        # print(green("Installing python packages"))
        # package_install()
        # more installation goes here
    print(red("\n\n******** INSTALLATION COMPLETED!********\n\n"))

@task(alias='hotfix')
def user_fix():
    """
    Fixing weird problem with app_dir_abs being root
    """
    set_env()
    sudo('chown -R {0}:{1} {2}'.format(USERS[0], GROUP, env.APP_DIR_ABS))


@task
def uninstall():
    """
    Uninstall YMAC_Return, YMAC_Return users and init script.
    
    NOTE: This can only be used with a sudo user.
    """
    set_env()
    for u in env.USERS:
        sudo('userdel -r {0}'.format(u), warn_only=True)
    sudo('groupdel {0}'.format(GROUP), warn_only=True)
    sudo('rm -rf {0}'.format(env.PREFIX), warn_only=True)
    sudo('rm -rf {0}'.format(env.APP_DIR_ABS), warn_only=True)
    print "\n\n******** UNINSTALL COMPLETED!********\n\n"

@task
@serial
def test_deploy():
    """
    ** MAIN TASK **: Deploy the full application EC2 test environment.
    """
    test_env()
    # set environment to default for EC2, if not specified otherwise.
    set_env()
    system_install()
    if env.postfix:
        postfix_config()
    # install()
    init_deploy()
    # user_fix()
    # deploy()


@task
def test_server():
    """
    Tests if server is up and running
    """
    set_env()
    try:
        response = urllib2.urlopen(env.host)
    except:
        response = urllib.urlopen(env.host)
    assert response.code == 200

@task
def uninstall_user():
    """
    Uninstall application, users and init script.
    """
    set_env()
    if env.user in ['ec2-user', 'root']:
        for u in env.USERS:
            sudo('userdel -r {0}'.format(u), warn_only=True)
#            sudo('rm /etc/init.d/ngamsServer', warn_only=True)
    else:
        run('rm -rf {0}'.format(env.APP_DIR_ABS))

@task
def assign_ddns():
    """
    This task installs the noip ddns client to the specified host.
    After the installation the configuration step is executed and that
    requires some manual input. Then the noip2 client is started in background.
    
    NOTE: Obviously this should only be carried out for one NGAS deployment!!
    """
    sudo('yum-config-manager --enable epel')
    sudo('yum install -y noip')
    sudo('sudo noip2 -C')
    sudo('chkconfig noip on')
    sudo('service noip start')



