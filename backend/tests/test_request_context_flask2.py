"""
Tests for request context utilities with Flask 2.x compatibility

This test verifies that request context utilities work correctly with Flask 2.x,
which removed _request_ctx_stack in favor of using flask.g for request-scoped data.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, g
from utils.request_context import (
    _get_request_id,
    get_request_context,
    set_request_metadata,
    get_request_metadata,
    get_request_start_time,
    get_request_duration
)


class TestRequestContextFlask2Compatibility:
    """Test request context utilities work with Flask 2.x"""

    def test_get_request_id_within_context(self, app):
        """Test request ID generation within Flask request context"""
        with app.test_request_context('/test'):
            request_id = _get_request_id()
            assert request_id is not None
            assert isinstance(request_id, str)
            assert len(request_id) == 36  # UUID4 format

            # Calling again should return same ID
            request_id2 = _get_request_id()
            assert request_id == request_id2

    def test_get_request_id_outside_context(self):
        """Test request ID returns None outside request context"""
        request_id = _get_request_id()
        assert request_id is None

    def test_get_request_context_returns_g(self, app):
        """Test that get_request_context returns flask.g in Flask 2.x"""
        with app.test_request_context('/test'):
            ctx = get_request_context()
            assert ctx is not None
            # In Flask 2.x, we use g for request-scoped storage
            assert ctx is g

    def test_get_request_context_outside_context(self):
        """Test get_request_context returns None outside request"""
        ctx = get_request_context()
        assert ctx is None

    def test_set_and_get_request_metadata(self, app):
        """Test storing and retrieving request metadata"""
        with app.test_request_context('/test'):
            # Set metadata
            set_request_metadata('user_id', 123)
            set_request_metadata('ip_address', '192.168.1.1')
            set_request_metadata('user_agent', 'test-browser')

            # Retrieve metadata
            assert get_request_metadata('user_id') == 123
            assert get_request_metadata('ip_address') == '192.168.1.1'
            assert get_request_metadata('user_agent') == 'test-browser'

            # Test default value for missing key
            assert get_request_metadata('missing_key', 'default') == 'default'

    def test_request_metadata_isolation(self, app):
        """Test that request metadata is isolated per request"""
        with app.test_request_context('/test1'):
            set_request_metadata('request', 'first')
            first_value = get_request_metadata('request')

        # New request context should not have previous metadata
        with app.test_request_context('/test2'):
            second_value = get_request_metadata('request')
            assert second_value is None
            set_request_metadata('request', 'second')
            assert get_request_metadata('request') == 'second'

    def test_get_request_start_time(self, app):
        """Test request start time tracking"""
        with app.test_request_context('/test'):
            start_time = get_request_start_time()
            assert start_time is not None

            # Should return same instance on subsequent calls
            start_time2 = get_request_start_time()
            assert start_time == start_time2

    def test_get_request_duration(self, app):
        """Test request duration calculation"""
        import time

        with app.test_request_context('/test'):
            # Initialize start time
            get_request_start_time()

            # Wait a tiny bit
            time.sleep(0.01)

            duration = get_request_duration()
            assert duration is not None
            assert duration > 0
            assert duration >= 0.01  # At least 10ms

    def test_request_duration_without_start_time(self, app):
        """Test request duration returns None if start time not set"""
        with app.test_request_context('/test'):
            # Don't call get_request_start_time()
            duration = get_request_duration()
            assert duration is None

    def test_metadata_outside_request_context(self):
        """Test metadata functions return None/default outside request context"""
        set_request_metadata('key', 'value')  # Should not raise error
        value = get_request_metadata('key')
        assert value is None

        value_with_default = get_request_metadata('key', 'default')
        assert value_with_default == 'default'

    def test_integration_with_flask_app(self, app, client):
        """Test request context works in actual Flask application"""
        @app.route('/test-context')
        def test_context():
            request_id = _get_request_id()
            set_request_metadata('test', 'value')
            return {
                'request_id': request_id,
                'test_metadata': get_request_metadata('test')
            }

        response = client.get('/test-context')
        assert response.status_code == 200
        data = response.get_json()
        assert 'request_id' in data
        assert data['request_id'] is not None
        assert data['test_metadata'] == 'value'

    def test_multiple_concurrent_requests(self, app):
        """Test that request contexts don't interfere with each other"""
        results = []

        with app.test_request_context('/request1'):
            set_request_metadata('name', 'request1')
            results.append(get_request_metadata('name'))

        with app.test_request_context('/request2'):
            # Should not see previous request's metadata
            assert get_request_metadata('name') is None
            set_request_metadata('name', 'request2')
            results.append(get_request_metadata('name'))

        assert results == ['request1', 'request2']

    def test_flask_g_compatibility(self, app):
        """
        Test that using flask.g directly is compatible with our utilities

        This ensures our implementation correctly uses flask.g for storage
        """
        with app.test_request_context('/test'):
            # Set via our utility
            set_request_metadata('via_utility', 'test')

            # Should be accessible via flask.g
            assert hasattr(g, 'request_metadata')
            assert g.request_metadata['via_utility'] == 'test'

            # Set directly on g
            g.direct_value = 'direct'

            # Should be accessible
            assert g.direct_value == 'direct'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
