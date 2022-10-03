import boto3
import json
from pprint import pprint

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configurationItem = result['configurationItems'][0]
    return convert_api_configuration(configurationItem)

# Convert from the API model to the original invocation model
def convert_api_configuration(configurationItem):
    for k, v in configurationItem.items():
        if isinstance(v, datetime.datetime):
            configurationItem[k] = str(v)
    configurationItem['awsAccountId'] = configurationItem['accountId']
    configurationItem['ARN'] = configurationItem['arn']
    configurationItem['configurationStateMd5Hash'] = configurationItem['configurationItemMD5Hash']
    configurationItem['configurationItemVersion'] = configurationItem['version']
    configurationItem['configuration'] = json.loads(configurationItem['configuration'])
    if 'relationships' in configurationItem:
        for i in range(len(configurationItem['relationships'])):
            configurationItem['relationships'][i]['name'] = configurationItem['relationships'][i]['relationshipName']
    return configurationItem

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistory API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    if is_oversized_changed_notification(invokingEvent['messageType']):
        configurationItemSummary = check_defined(invokingEvent['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configurationItemSummary['resourceType'], configurationItemSummary['resourceId'], configurationItemSummary['configurationItemCaptureTime'])
    return check_defined(invokingEvent['configurationItem'], 'configurationItem')

# check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem['configurationItemStatus']
    eventLeftScope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

# assume the appropriate execution role that the lambda function was set up with
def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# return printable version of an object (useful for debugging)        
def var_dump(obj):
  newobj=obj
  if '__dict__' in dir(obj):
    newobj=obj.__dict__
    if ' object at ' in str(obj) and not newobj.has_key('__type__'):
      newobj['__type__']=str(obj)
    for attr in newobj:
      newobj[attr]=dump(newobj[attr])
  return newobj

# tag the specified instance with key->value
def tag_instance(instanceId,key,value):
    # EC2_CLIENT instantiated in lambda_handler
    global AWS_EC2_CLIENT

    AWS_EC2_CLIENT.create_tags(Resources=[instanceId], Tags=[{'Key': key,'Value': value}])
    print('Tagged Non-Compliant Instance: ' + instanceId + ' with key->val of ' + key + '->' + value)
    
# stop listed instances
def stop_instances(instanceIds):
    # EC2_CLIENT instantiated in lambda_handler
    global AWS_EC2_CLIENT

    AWS_EC2_CLIENT.stop_instances(InstanceIds=[instanceIds])
    print('Stopped Non-Compliant InstanceIds: ' + instanceIds)

# determine / mark if resource is in/out of compliance
def evaluate_change_notification_compliance(configuration_item, rule_parameters):
    instanceId = str(configuration_item['resourceId']);
    
    check_defined(configuration_item, 'configuration_item')
    check_defined(configuration_item['configuration'], 'configuration_item[\'configuration\']')
    if rule_parameters:
        check_defined(rule_parameters, 'rule_parameters')

    #only checking EC2 instances
    if (configuration_item['resourceType'] != 'AWS::EC2::Instance'):
        return 'NOT_APPLICABLE'

    elif rule_parameters.get('desiredInstanceType'):
        print("CONFIGURATION_ITEM_DUMP",end="\r\n")
        pprint(var_dump(configuration_item))
        # note: desiredInstanceType is set in config rule parameters. You can set multiple
        if (configuration_item['configuration']['instanceType'] in rule_parameters['desiredInstanceType']):
            check_defined(configuration_item['configuration']['tags'],'configuration_item[\'configuration\'][\'tags\']')
            print('tagsDump for instance ID ' + instanceId + ' is set to:')
            pprint(var_dump(configuration_item['configuration']['tags']))
            for i in configuration_item['configuration']['tags']:
                print('tagKEY(' + i['key'] +') for instance ID ' + instanceId + ' is set to:')
                pprint(var_dump(i['key']))
                print('tagVAL(' + i['value'] +') for instance ID ' + instanceId + ' is set to:')
                pprint(var_dump(i['value']))
                if(check_defined(i['key'],'i[\'key\']') and (i['key'] == 'env')):
                        if(check_defined(i['value'],'i[\'value\']') and (i['value'] == 'prod')):
                            # check that this instance has an 'owner' assigned, and if not, assign a default
                            # note: you could easily do similar operations with other tags as well
                            hasOwnerTag = False
                            for j in configuration_item['configuration']['tags']:
                                print('JJJtagKEY(' + j['key'] +') for instance ID ' + instanceId + ' is set to:')
                                pprint(var_dump(j['key']))
                                print('JJJtagVAL(' + j['value'] +') for instance ID ' + instanceId + ' is set to:')
                                pprint(var_dump(j['value']))
                                if(check_defined(j['key'],'j[\'key\']') and (j['key'] == 'owner')):
                                    hasOwnerTag = True
                    
                            if not hasOwnerTag:
                                tag_instance(instanceId,'owner','rich@quicloud.com')
                            return 'COMPLIANT'
                        else:
                            stop_instances(instanceId)
    return 'NON_COMPLIANT'

def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT
    global AWS_EC2_CLIENT

    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    compliance_value = 'NOT_APPLICABLE'

    # instantiate the various clients we'll use
    AWS_CONFIG_CLIENT = get_client('config', event)
    AWS_EC2_CLIENT = get_client('ec2', event)
    
    configuration_item = get_configuration_item(invoking_event)
    if is_applicable(configuration_item, event):
        compliance_value = evaluate_change_notification_compliance(
                configuration_item, rule_parameters)

    response = AWS_CONFIG_CLIENT.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
               'ComplianceType': compliance_value,
               'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])

# This code allows the function to run from Cloud9 IDE (loading event json object)      
import json

with open('./autom8d-foundations/activity-1/event.json') as json_file:
    event_data = json.load(json_file)
print("events.json contains:\r\n" + str(event_data))
context = ""

lambda_handler(event_data,context)
events_json.close()