import gzip
import json
import logging
import os


from flask import Flask, request


from log_analytics import LogAnalytics


app = Flask(__name__)


APPLICATION_JSON = {"ContentType": "application/json"}
FAILURE_RESPONSE = json.dumps({"success": False})
SUCCESS_RESPONSE = json.dumps({"success": True})


MAPPING = json.load(open("mapping.json"))
CUSTOM_MAPPING = {
    "Rule": "DeviceCustomString1",
    "URLCategory": "DeviceCustomString2",
    "AuthMethod": "DeviceCustomString3",
    "ThreatID": "DeviceCustomString4",
    "ThreatCategory": "DeviceCustomString5",
    "DirectionOfAttack": "DeviceCustomString6",
}


ENV = ("DCE_URL", "DCR_ID", "DCR_STREAM")


def check_env(env_vars):
    vars = {}

    for env in env_vars:
        env_value = os.environ.get(env)
        if not env_value:
            print(f"Environment variable {env} not set")
            return None
        else:
            vars[env] = env_value

    return vars


def remap_log(log):
    new_log = {new: log[old] for old, new in MAPPING.items() if old in log}

    for old, new in CUSTOM_MAPPING.items():
        if old in log:
            new_log[new] = log[old]

            custom_label = f"{new}Label"
            new_log[custom_label] = old

    # Build AdditionalExtensions from endpoint metadata fields
    endpoint_fields = {
        "EndpointOSType": log.get("EndpointOSType"),
        "EndpointOSVersion": log.get("EndpointOSVersion"),
        "Portal": log.get("Portal"),
    }

    # Only include fields that have non-empty values
    additional_extensions = [
        f"{key}={value}"
        for key, value in endpoint_fields.items()
        if value is not None and str(value).strip()
    ]

    if additional_extensions:
        new_log["AdditionalExtensions"] = ";".join(additional_extensions)

    return new_log


@app.route("/", methods=["POST"])
def func():
    vars = check_env(ENV)

    if not vars:
        return FAILURE_RESPONSE, 400, APPLICATION_JSON

    body = request.get_data()

    try:
        decompressed = gzip.decompress(body)
    except gzip.BadGzipFile:
        logging.error("Body sent not gzipped")
        return FAILURE_RESPONSE, 400, APPLICATION_JSON

    decomp_body_length = len(decompressed)

    if decomp_body_length == 0:
        if len(body) == 0:
            logging.error(f"Decompressed: {decompressed} vs Body: {body}")
            return FAILURE_RESPONSE, 400, APPLICATION_JSON
        else:
            return FAILURE_RESPONSE, 500, APPLICATION_JSON

    try:
        data = json.loads(decompressed)
    except json.decoder.JSONDecodeError:
        return FAILURE_RESPONSE, 400, APPLICATION_JSON

    logs_to_send = []

    for log in data:
        new_log = remap_log(log)
        logs_to_send.append(new_log)

    log_analytics = LogAnalytics(
        vars["DCE_URL"],
        vars["DCR_ID"],
        vars["DCR_STREAM"],
    )
    log_analytics.upload(logs_to_send)

    return SUCCESS_RESPONSE, 200, APPLICATION_JSON


@app.route("/health", methods=["GET"])
def health():
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON


if __name__ == "__main__":
    app.run()
