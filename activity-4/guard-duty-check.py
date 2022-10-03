# set up our imports
# sys,json,logging all used for stdout logging
# re = regular expressions... very useful for txt manipulations we do for CW dashboards
import boto3
import sys
import json
import re
import logging

# init global vars
sns_topic_arn = "arn:aws:sns:YOUR-REGION:YOUR-ACCT-ID:guard-duty-notifier"
high_severity_count = 0
medium_severity_count = 0
low_severity_count = 0

# init our boto clients
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')

# use a log formatter as it's cleaner than those yucky "print" statements we've been using...
logger = logging.getLogger()
for h in logger.handlers:
  logger.removeHandler(h)

# Set up a logging format that we use throughout our logs
h = logging.StreamHandler(sys.stdout)
FORMAT = ' [%(levelname)s]/%(asctime)s/%(name)s - %(message)s'
h.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(h)
logger.setLevel(logging.INFO)

# define some cloudwatch dashboard getters/setters
def get_cw_dashboard(dashboard_name = 'Security'):
    return cloudwatch_client.get_dashboard(DashboardName= dashboard_name)

def put_cw_dashboard(dashboard_name, dashboard_body):
    cloudwatch_client.put_dashboard(DashboardName = dashboard_name,DashboardBody = dashboard_body)

# increment counts and push GuardDuty findings to SNS topic for alerting via SEIM tooling
def increment_counts_email_finding(event):
    global sns_topic_arn
    global high_severity_count
    global medium_severity_count
    global low_severity_count

#    logger.info(json.dumps(event, indent=4))
#    logger.info("SUBJECT:" + event['detail']['title'])
    try:
        # Note: publish() call limits title to only 100 characters, so we trunc it
        response = sns_client.publish(
            TopicArn = sns_topic_arn,
            Message = json.dumps(event,indent=4),
            Subject = event['detail']['title'][:100]
        )
        severity = event['detail']['severity']
        if(severity >= 7):
            high_severity_count += 1
        elif(severity >= 4):
            medium_severity_count += 1
        else:
            low_severity_count += 1
            
        logger.info('SUCCESS: pushed GuardDuty finding to SNS Topic')
        return "Successly pushed message to SNS Topic"
    except KeyError as e:
        logger.error('ERROR: Unable to push to SNS: Check that [1] Topic ARN is valid, [2] IAM Role Permissions allow '.format( str(e) ) )
        logger.error('ERROR: {0}'.format( str(e) ) )


def lambda_handler(event, context):
    global high_severity_count, medium_severity_count,low_severity_count

    # init our counts from dashboard
    dashboard = get_cw_dashboard('Security')
    matches_list = re.findall('[0-9]+',dashboard['DashboardBody'])
    # first 4 matches are height, width, x, y THEN it gets to HS, MS, LS
    high_severity_count = int(matches_list[4]);
    medium_severity_count = int(matches_list[5]);
    low_severity_count = int(matches_list[6]);
#    logger.info(print("MATCHES_LIST:" + str(matches_list) + "HS:"+str(high_severity_count)+" MS:"+str(medium_severity_count)+" LS:"+str(low_severity_count)))

    # send our email out, incre
    increment_counts_email_finding(event)
    
#    logger.info('DASHBOARD-ORIG')
#    logger.info(json.dumps(dashboard['DashboardBody']))    

    # update our dashboard. Note: 'DashboardBody' is just TEXT (though it's JSON text)
    dashboard['DashboardBody'] = re.sub('High\:[0-9]+','High:' + str(high_severity_count), dashboard['DashboardBody'])
    dashboard['DashboardBody'] = re.sub('Medium\:[0-9]+','Medium:' + str(medium_severity_count), dashboard['DashboardBody'])
    dashboard['DashboardBody'] = re.sub('Low\:[0-9]+','Low:' + str(low_severity_count), dashboard['DashboardBody'])
    put_cw_dashboard('Security',dashboard['DashboardBody'])
    
#    logger.info('DASHBOARD-AFTER')
#    logger.info(json.dumps(dashboard['DashboardBody']))    
    
if __name__ == '__main__':
    lambda_handler(None, None)
