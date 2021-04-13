import os

AWG_API_KEY = os.environ.get('AWG_API_KEY')
AWG_BASE_URL = os.environ.get('AWG_BASE_URL')
AWG_USER_NAME = os.environ.get('AWG_USER_NAME')

# run performance tests
RUN_PERFORMANCE_TESTS = os.environ.get('RUN_PERFORMANCE_TESTS', 'False')
