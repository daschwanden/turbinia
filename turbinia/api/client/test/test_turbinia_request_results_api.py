"""
    Turbinia API Server

    Turbinia API server  # noqa: E501

    The version of the OpenAPI document: 1.0.0
    Generated by: https://openapi-generator.tech
"""


import unittest

import turbinia_api_lib
from turbinia_api_lib.api.turbinia_request_results_api import TurbiniaRequestResultsApi  # noqa: E501


class TestTurbiniaRequestResultsApi(unittest.TestCase):
    """TurbiniaRequestResultsApi unit test stubs"""

    def setUp(self):
        self.api = TurbiniaRequestResultsApi()  # noqa: E501

    def tearDown(self):
        pass

    def test_get_request_output(self):
        """Test case for get_request_output

        Get Request Output  # noqa: E501
        """
        pass

    def test_get_task_output(self):
        """Test case for get_task_output

        Get Task Output  # noqa: E501
        """
        pass


if __name__ == '__main__':
    unittest.main()