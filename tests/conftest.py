from datetime import datetime
from unittest.mock import patch

import pytest
from mockito import unstub


@pytest.fixture(autouse=True)
def log(caplog, pytestconfig):
    if pytestconfig.getoption("verbose") > 0:
        caplog.set_level('DEBUG')
    else:
        caplog.set_level('INFO')


@pytest.fixture
def frozentime():
    dt = datetime(2022, 1, 1, 12, 34)
    with patch('requests_auth_aws_sigv4.datetime') as mock_datetime:
        mock_datetime.utcnow.return_value = dt
        yield dt

