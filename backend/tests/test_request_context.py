"""
Tests for request context utilities
Validates Flask 2.2+ compatibility with updated g-based context handling
"""
import pytest
import sys
import os
from datetime import datetime
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.request_context import (
    _get_request_id,
    get_request_context,
    set_request_metadata,
    get_request_metadata,
    get_request_start_time,
    get_request_duration
)


class TestRequestContext:
    """Test request context utilities with Flask 2.2+ compatibility"""

    def test_request_id_generation(self, app):
        """Test that request ID is generated in request context"""
        with app.test_request_context():
            request_id = _get_request_id()
            assert request_id is not None
            assert isinstance(request_id, str)
            assert len(request_id) > 0

            # Request ID should be consistent within same context
            request_id_2 = _get_request_id()
            assert request_id == request_id_2

    def test_request_id_outside_context(self):
        """Test that request ID returns None outside request context"""
        request_id = _get_request_id()
        assert request_id is None

    def test_get_request_context(self, app):
        """Test getting request context"""
        with app.test_request_context():
            ctx = get_request_context()
            assert ctx is not None
            # Flask 2.2+ uses g object
            from flask import g
            assert ctx is g

    def test_get_request_context_outside(self):
        """Test getting request context outside request"""
        ctx = get_request_context()
        assert ctx is None

    def test_set_and_get_request_metadata(self, app):
        """Test setting and getting request metadata"""
        with app.test_request_context():
            # Set metadata
            set_request_metadata('user_id', 123)
            set_request_metadata('action', 'test_action')
            set_request_metadata('ip_address', '192.168.1.1')

            # Get metadata
            assert get_request_metadata('user_id') == 123
            assert get_request_metadata('action') == 'test_action'
            assert get_request_metadata('ip_address') == '192.168.1.1'

    def test_get_request_metadata_default(self, app):
        """Test getting request metadata with default value"""
        with app.test_request_context():
            # Non-existent key should return default
            assert get_request_metadata('nonexistent', 'default') == 'default'
            assert get_request_metadata('nonexistent') is None

    def test_get_request_metadata_outside_context(self):
        """Test getting metadata outside request context"""
        result = get_request_metadata('any_key', 'default')
        assert result == 'default'

    def test_request_start_time(self, app):
        """Test request start time tracking"""
        with app.test_request_context():
            start_time = get_request_start_time()
            assert start_time is not None
            assert isinstance(start_time, datetime)

            # Should return same time within same context
            start_time_2 = get_request_start_time()
            assert start_time == start_time_2

    def test_request_start_time_outside_context(self):
        """Test request start time outside context"""
        start_time = get_request_start_time()
        assert start_time is None

    def test_request_duration(self, app):
        """Test request duration calculation"""
        with app.test_request_context():
            # Initialize start time
            get_request_start_time()

            # Wait a small amount of time
            time.sleep(0.01)

            # Get duration
            duration = get_request_duration()
            assert duration is not None
            assert isinstance(duration, float)
            assert duration >= 0.01

    def test_request_duration_without_start_time(self, app):
        """Test duration when start time not set"""
        with app.test_request_context():
            # Don't initialize start time
            duration = get_request_duration()
            assert duration is None

    def test_request_duration_outside_context(self):
        """Test duration outside request context"""
        duration = get_request_duration()
        assert duration is None


class TestRequestContextIntegration:
    """Integration tests for request context with actual Flask app"""

    def test_before_request_initializes_context(self, client, sample_user, auth_headers):
        """Test that before_request hook initializes context properly"""
        # Make a request to trigger before_request
        response = client.get('/api/projects', headers=auth_headers)

        # The request should complete successfully
        # (context initialization happens automatically)
        assert response.status_code in [200, 401, 404]

    def test_multiple_requests_different_contexts(self, app):
        """Test that different requests get different contexts"""
        request_ids = []

        with app.test_request_context():
            id1 = _get_request_id()
            request_ids.append(id1)

        with app.test_request_context():
            id2 = _get_request_id()
            request_ids.append(id2)

        # Each request should have a unique ID
        assert len(request_ids) == 2
        assert request_ids[0] != request_ids[1]

    def test_metadata_isolation_between_requests(self, app):
        """Test that metadata doesn't leak between requests"""
        with app.test_request_context():
            set_request_metadata('user_id', 123)
            assert get_request_metadata('user_id') == 123

        # New context should not have previous metadata
        with app.test_request_context():
            assert get_request_metadata('user_id') is None


class TestFlaskCompatibility:
    """Test Flask 2.2+ specific compatibility"""

    def test_g_object_availability(self, app):
        """Test that Flask g object is properly used"""
        with app.test_request_context():
            from flask import g

            # Initialize request ID (stores in g)
            request_id = _get_request_id()

            # Should be accessible via g
            assert hasattr(g, 'request_id')
            assert g.request_id == request_id

    def test_has_request_context_function(self, app):
        """Test that has_request_context works properly"""
        from flask import has_request_context

        # Outside context
        assert has_request_context() is False

        # Inside context
        with app.test_request_context():
            assert has_request_context() is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
