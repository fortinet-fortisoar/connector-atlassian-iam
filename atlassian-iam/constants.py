""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

messages_codes = {
    400: 'Invalid input',
    401: 'Unauthorized: Invalid credentials',
    500: 'Invalid input',
    404: 'Invalid input',
    'ssl_error': 'SSL certificate validation failed',
    'timeout_error': 'The request timed out while trying to connect to the remote server. Invalid Server URL.'
}



operator_mapping = {
    "does not equal": "neq",
    "does not start with": "doesnotstartwith",
    "equals": "eq",
    "starts with": "startswith",
    "contains": "contains"
}



action_input_parameters = {
    "create_user": ["userName", "emails", "title", "department", "organization", "active", "custom_filter"],
    "get_users": [],
    "update_user": ["userId", "userName", "emails", "title", "department", "organization", "custom_filter"],
    "deactivate_user": ["userId"]

}


