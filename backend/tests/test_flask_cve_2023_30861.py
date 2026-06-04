"""
Tests to verify Flask CVE-2023-30861 remediation

CVE-2023-30861: Flask session cookie caching vulnerability
This test verifies that Flask 2.3.2+ correctly sets the 'Vary: Cookie' header
to prevent proxy caching issues with session cookies.

Vulnerability Details:
- Affects Flask < 2.2.5 and Flask 2.3.x < 2.3.2
- When session.permanent = True and SESSION_REFRESH_EACH_REQUEST is enabled,
  vulnerable versions fail to set 'Vary: Cookie' header on session refresh
- This could allow proxies to cache and serve one client's session to others

The fix ensures 'Vary: Cookie' is always set when sessions are used.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, session, make_response


class TestFlaskCVE202330861:
    """Test Flask CVE-2023-30861 vulnerability remediation"""

    def test_flask_version_is_patched(self):
        """Verify Flask version is >= 2.2.5 or >= 2.3.2"""
        import flask
        version = tuple(int(x) for x in flask.__version__.split('.')[:3])

        # Check if version is patched (>= 2.2.5 or >= 2.3.2)
        is_patched = (
            (version >= (2, 2, 5) and version < (2, 3, 0)) or  # 2.2.5+
            (version >= (2, 3, 2))                              # 2.3.2+
        )

        assert is_patched, f"Flask {flask.__version__} is vulnerable to CVE-2023-30861"

    def test_session_vary_cookie_header_with_permanent_session(self):
        """
        Test that 'Vary: Cookie' header is set when using permanent sessions

        This is the core vulnerability scenario from CVE-2023-30861:
        - session.permanent = True
        - SESSION_REFRESH_EACH_REQUEST = True (default)
        - Session is NOT accessed/modified during request

        Vulnerable versions would NOT set 'Vary: Cookie', allowing proxy caching
        Fixed versions ALWAYS set 'Vary: Cookie' when sessions are enabled
        """
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test-secret-key-for-cve-test'
        app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Default setting

        @app.route('/test-endpoint')
        def test_endpoint():
            """Endpoint that uses permanent session but doesn't access it"""
            session.permanent = True
            # Intentionally NOT accessing or modifying session data
            # This is the vulnerable scenario
            return 'test response'

        with app.test_client() as client:
            # First request to establish session
            response = client.get('/test-endpoint')

            # Verify response has Vary: Cookie header
            # This prevents proxies from caching responses with session cookies
            assert 'Vary' in response.headers, \
                "Response missing 'Vary' header - CVE-2023-30861 vulnerability"

            vary_header = response.headers.get('Vary', '').lower()
            assert 'cookie' in vary_header, \
                f"'Vary' header does not include 'Cookie': {vary_header} - CVE-2023-30861 vulnerability"

    def test_session_vary_cookie_header_with_cache_control(self):
        """
        Test that proper cache control headers prevent proxy caching

        While the vulnerability requires Cache-Control NOT to be set,
        this test verifies that when properly configured, both Vary
        and Cache-Control headers are present for defense in depth.
        """
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test-secret-key-for-cve-test'
        app.config['SESSION_REFRESH_EACH_REQUEST'] = True

        @app.route('/private-endpoint')
        def private_endpoint():
            """Endpoint with explicit cache control"""
            session.permanent = True
            response = make_response('private content')
            response.headers['Cache-Control'] = 'private, no-cache, no-store, must-revalidate'
            return response

        with app.test_client() as client:
            response = client.get('/private-endpoint')

            # Verify both Vary and Cache-Control headers are present
            assert 'Vary' in response.headers, "Missing 'Vary' header"
            assert 'Cookie' in response.headers.get('Vary', ''), "Vary header missing 'Cookie'"
            assert 'Cache-Control' in response.headers, "Missing 'Cache-Control' header"
            assert 'private' in response.headers.get('Cache-Control', '').lower(), \
                "Cache-Control should mark response as private"

    def test_session_without_permanent_flag(self):
        """
        Test session handling without permanent flag

        Verifies that even without session.permanent = True,
        Flask still handles session cookies appropriately.
        """
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test-secret-key-for-cve-test'

        @app.route('/non-permanent-session')
        def non_permanent_session():
            """Endpoint using non-permanent session"""
            session['user_id'] = 'test123'
            return 'session set'

        with app.test_client() as client:
            response = client.get('/non-permanent-session')

            # Should still have Set-Cookie header for session
            assert 'Set-Cookie' in response.headers, "Session cookie not set"

            # Should have Vary header when session is modified
            if 'Vary' in response.headers:
                assert 'Cookie' in response.headers.get('Vary', ''), \
                    "If Vary header is present, it should include Cookie"

    def test_werkzeug_version_compatibility(self):
        """Verify Werkzeug version is compatible with Flask 2.3.2"""
        import werkzeug
        version = tuple(int(x) for x in werkzeug.__version__.split('.')[:3])

        # Flask 2.3.2 requires Werkzeug >= 2.3.0
        assert version >= (2, 3, 0), \
            f"Werkzeug {werkzeug.__version__} is incompatible with Flask 2.3.2"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
