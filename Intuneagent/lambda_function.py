import json
import boto3
import urllib.request
import urllib.parse
import urllib.error
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRETS_MANAGER_SECRET_NAME = ""
REGION = ""


# ─────────────────────────────────────────────
# 1. Fetch secrets from AWS Secrets Manager
# ─────────────────────────────────────────────
def get_intune_secrets():
    client = boto3.client("secretsmanager", region_name=REGION)
    response = client.get_secret_value(SecretId=SECRETS_MANAGER_SECRET_NAME)
    secret = json.loads(response["SecretString"])
    # Expected keys in your secret: clientId, clientSecret, tenantId
    return secret["clientId"], secret["clientSecret"], secret["tenantId"]


# ─────────────────────────────────────────────
# 2. Authenticate with Microsoft Graph (OAuth2)
# ─────────────────────────────────────────────
def get_access_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urllib.request.urlopen(req) as resp:
        token_data = json.loads(resp.read().decode("utf-8"))

    return token_data["access_token"]


# ─────────────────────────────────────────────
# 3. Fetch device compliance from Intune
# ─────────────────────────────────────────────
def get_device_compliance(access_token, device_id=None, user_upn=None):
    """
    Returns compliance state for:
      - A specific device (device_id provided)
      - Devices belonging to a user (user_upn provided)
      - All managed devices (neither provided)
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    select = "id,deviceName,userPrincipalName,complianceState,osVersion,operatingSystem,lastSyncDateTime,managedDeviceOwnerType"

    if device_id:
        params = urllib.parse.urlencode({"$select": select})
        url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{device_id}?{params}"
    elif user_upn:
        params = urllib.parse.urlencode({
            "$filter": f"userPrincipalName eq '{user_upn}'",
            "$select": select
        })
        url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?{params}"
    else:
        params = urllib.parse.urlencode({
            "$select": select,
            "$top": 50
        })
        url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?{params}"

    req = urllib.request.Request(url, headers=headers, method="GET")

    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    # Normalize: single device returns object, list queries return {value: [...]}
    if "value" in data:
        return data["value"]
    else:
        return [data]


# ─────────────────────────────────────────────
# 4. Format compliance result for the agent
# ─────────────────────────────────────────────
def format_compliance_result(devices):
    if not devices:
        return "No managed devices found."

    lines = []
    for d in devices:
        lines.append(
            f"Device: {d.get('deviceName', 'N/A')} | "
            f"User: {d.get('userPrincipalName', 'N/A')} | "
            f"OS: {d.get('operatingSystem', 'N/A')} {d.get('osVersion', '')} | "
            f"Compliance: {d.get('complianceState', 'N/A')} | "
            f"Last Sync: {d.get('lastSyncDateTime', 'N/A')}"
        )
    return "\n".join(lines)


# ─────────────────────────────────────────────
# 5. Parse Bedrock Agent request parameters
# ─────────────────────────────────────────────
def extract_params(event):
    """
    Bedrock Agents pass parameters under event['parameters'] as a list of
    {name, type, value} dicts.  Direct Lambda test events can pass them flat.
    """
    device_id = None
    user_upn = None

    # Bedrock Agent invocation format
    parameters = event.get("parameters", [])
    if isinstance(parameters, list):
        for param in parameters:
            if param.get("name") == "deviceId":
                device_id = param.get("value")
            elif param.get("name") == "userPrincipalName":
                user_upn = param.get("value")

    # Direct test / fallback format
    if not device_id:
        device_id = event.get("deviceId")
    if not user_upn:
        user_upn = event.get("userPrincipalName")

    return device_id, user_upn


# ─────────────────────────────────────────────
# 6. Lambda handler
# ─────────────────────────────────────────────
def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    try:
        # ── Parse parameters ──
        device_id, user_upn = extract_params(event)

        # ── Auth ──
        client_id, client_secret, tenant_id = get_intune_secrets()
        access_token = get_access_token(tenant_id, client_id, client_secret)

        # ── Fetch compliance ──
        devices = get_device_compliance(access_token, device_id=device_id, user_upn=user_upn)
        result_text = format_compliance_result(devices)

        logger.info("Compliance result: %s", result_text)

        # ── Bedrock Agent response format ──
        return {
            "messageVersion": "1.0",
            "response": {
                "actionGroup": event.get("actionGroup", ""),
                "apiPath": event.get("apiPath", "/getDeviceComplianceState"),
                "httpMethod": event.get("httpMethod", "GET"),
                "httpStatusCode": 200,
                "responseBody": {
                    "application/json": {
                        "body": json.dumps({
                            "complianceReport": result_text,
                            "deviceCount": len(devices),
                            "devices": devices   # full structured data for agent reasoning
                        })
                    }
                }
            }
        }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        logger.error("HTTP error: %s – %s", e.code, error_body)
        return _error_response(event, f"Graph API error {e.code}: {error_body}")

    except Exception as e:
        logger.error("Unexpected error: %s", str(e))
        return _error_response(event, str(e))


def _error_response(event, message):
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup", ""),
            "apiPath": event.get("apiPath", "/getDeviceComplianceState"),
            "httpMethod": event.get("httpMethod", "GET"),
            "httpStatusCode": 500,
            "responseBody": {
                "application/json": {
                    "body": json.dumps({"error": message})
                }
            }
        }
    }
