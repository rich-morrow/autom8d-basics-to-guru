import gzip
import json
import base64


def lambda_handler(event, context):
    print(f'RAW Logging Event (notice it's Base64 Encoded, and embedded in the 'awslogs' dictionary): {event}')

    # Extract only the "data" portion of our CloudWatch data
    cloudwatch_data = event['awslogs']['data']
    print(f'data: {cloudwatch_data}')

    # Decompress and extract our payload
    compressed_data = base64.b64decode(cloudwatch_data)
    uncompressed_data = gzip.decompress(compressed_data)
    payload = json.loads(uncompressed_data)

    log_events = payload['logEvents']
    # Now, we can finally access the individual events - we will only see "Invalid user" events
    for log_event in log_events:
	# We could now easily take the remote IP and add it to a WAF rule, SG block, etc...
        print(f'LogEvent: {log_event}')