# File: cloudconvert_consts.py
#
# Copyright (c) 2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
CLOUDCONVERT_STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format."
    "Resetting the state file with the default format. Please try again."
)
# Test Connectivity endpoints
CLOUDCONVERT_CONNECTION_MSG = 'Querying endpoint to verify the credentials provided'
TEST_CONNECTIVITY_URL = 'https://api.cloudconvert.com/v2/users/me'
CLOUDCONVERT_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed'
CLOUDCONVERT_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed'
# Asset config parameters
CLOUDCONVERT_CONFIG_API_KEY = 'api_key'  # pragma: allowlist secret
# Get file info from vault
CLOUDCONVERT_ERR_FILE_NOT_IN_VAULT = "Could not find specified vault ID in vault"
# Get dictionary
GET_DICTIONARY_URL = 'https://api.cloudconvert.com/v2/convert/formats'
# Get link
GET_LINK_URL = "https://api.cloudconvert.com/v2/tasks?page=1&filter\\[job_id\\]="
# Import task
IMPORT_TASK_URL = "https://storage.cloudconvert.com/tasks"
# Initialize job
INITIALIZE_JOB_URL = "https://api.cloudconvert.com/v2/jobs"
# Get error message from exception
CLOUDCONVERT_ERROR_CODE_MESSAGE = "Error code unavailable"
CLOUDCONVERT_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters"
TYPE_ERROR_MESSAGE = "Error occurred while connecting to the HTTP server. " \
                     "Please check the asset configuration and|or the action parameters"
DEFAULT_TIMEOUT_SECONDS = 60   # in seconds
