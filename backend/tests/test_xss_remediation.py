"""
Tests for XSS vulnerability remediation in jinja_filters.role_badge
This test suite validates that the Stored XSS vulnerability in the admin dashboard
has been properly fixed by ensuring user-controlled role data is escaped.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.jinja_filters import role_badge
from markupsafe import Markup, escape


class TestRoleBadgeXSSRemediation:
    """Test XSS vulnerability remediation in role_badge filter"""

    def test_role_badge_escapes_basic_xss_script_tag(self):
        """Test that script tags in role are escaped"""
        # Mock context object
        context = type('obj', (object,), {})()

        malicious_role = '<script>alert("XSS")</script>'
        result = role_badge(context, malicious_role)

        # The result should not contain unescaped script tags
        assert '<script>alert("XSS")</script>' not in result
        # Should contain escaped version
        assert '&lt;script&gt;' in result
        assert '&lt;/script&gt;' in result

    def test_role_badge_escapes_img_tag_with_onerror(self):
        """Test that img tags with onerror are escaped"""
        context = type('obj', (object,), {})()

        malicious_role = '<img src=x onerror=alert("XSS")>'
        result = role_badge(context, malicious_role)

        # Should not contain unescaped img tag
        assert '<img src=x onerror=alert("XSS")>' not in result
        # Should contain escaped version
        assert '&lt;img' in result
        assert 'onerror' not in result or 'onerror=' not in result

    def test_role_badge_escapes_event_handler_attributes(self):
        """Test that event handler attributes are escaped"""
        context = type('obj', (object,), {})()

        malicious_role = '" onmouseover="alert(1)"'
        result = role_badge(context, malicious_role)

        # Should not contain unescaped event handlers
        assert 'onmouseover="alert(1)"' not in result
        # Should be properly escaped
        assert '&quot;' in result or '&#34;' in result

    def test_role_badge_escapes_javascript_protocol(self):
        """Test that javascript: protocol is escaped"""
        context = type('obj', (object,), {})()

        malicious_role = 'javascript:alert("XSS")'
        result = role_badge(context, malicious_role)

        # Should not contain unescaped javascript protocol
        # The colon should be present but the content should be safe
        escaped_result = str(result)
        # Verify it's within the span and properly escaped
        assert '<span class="badge badge-secondary">' in escaped_result
        assert '</span>' in escaped_result

    def test_role_badge_escapes_svg_with_script(self):
        """Test that SVG elements with scripts are escaped"""
        context = type('obj', (object,), {})()

        malicious_role = '<svg onload=alert(1)>'
        result = role_badge(context, malicious_role)

        # Should not contain unescaped SVG tag
        assert '<svg onload=alert(1)>' not in result
        assert '&lt;svg' in result

    def test_role_badge_handles_legitimate_admin_role(self):
        """Test that legitimate admin role works correctly"""
        context = type('obj', (object,), {})()

        result = role_badge(context, 'admin')

        # Should generate proper badge with danger color
        assert '<span class="badge badge-danger">admin</span>' in result
        assert 'admin' in result

    def test_role_badge_handles_legitimate_project_manager_role(self):
        """Test that legitimate project_manager role works correctly"""
        context = type('obj', (object,), {})()

        result = role_badge(context, 'project_manager')

        # Should generate proper badge with primary color
        assert '<span class="badge badge-primary">project_manager</span>' in result

    def test_role_badge_handles_legitimate_team_member_role(self):
        """Test that legitimate team_member role works correctly"""
        context = type('obj', (object,), {})()

        result = role_badge(context, 'team_member')

        # Should generate proper badge with secondary color
        assert '<span class="badge badge-secondary">team_member</span>' in result

    def test_role_badge_handles_unknown_role_safely(self):
        """Test that unknown roles are handled safely with default color"""
        context = type('obj', (object,), {})()

        result = role_badge(context, 'unknown_role')

        # Should use secondary color for unknown roles
        assert '<span class="badge badge-secondary">unknown_role</span>' in result
        # Should still escape the role value
        assert 'unknown_role' in result

    def test_role_badge_escapes_html_entities(self):
        """Test that HTML entities are properly escaped"""
        context = type('obj', (object,), {})()

        malicious_role = '&lt;script&gt;alert(1)&lt;/script&gt;'
        result = role_badge(context, malicious_role)

        # Should double-escape to prevent interpretation
        assert '&amp;lt;' in result or '&lt;script&gt;' not in str(result).replace('&amp;lt;', '&lt;')

    def test_role_badge_escapes_quotes_and_special_chars(self):
        """Test that quotes and special characters are escaped"""
        context = type('obj', (object,), {})()

        malicious_role = '"><script>alert("XSS")</script><span class="'
        result = role_badge(context, malicious_role)

        # Should escape quotes and angle brackets
        assert '"><script>' not in result
        assert '&quot;&gt;&lt;script&gt;' in result or '&#34;&gt;&lt;script&gt;' in result

    def test_role_badge_prevents_attribute_injection(self):
        """Test that attribute injection attempts are escaped"""
        context = type('obj', (object,), {})()

        malicious_role = '" class="malicious" data-evil="true'
        result = role_badge(context, malicious_role)

        # Should not allow injection of additional attributes
        # The malicious class should be escaped
        assert 'class="malicious"' not in result
        # Should contain escaped quotes
        assert '&quot;' in result or '&#34;' in result

    def test_role_badge_escapes_style_attribute_injection(self):
        """Test that style attribute injection is prevented"""
        context = type('obj', (object,), {})()

        malicious_role = '" style="display:none" data-x="'
        result = role_badge(context, malicious_role)

        # Should not allow style injection
        assert 'style="display:none"' not in result
        # Should be properly escaped
        assert '&quot;' in result or '&#34;' in result

    def test_role_badge_with_null_or_empty_role(self):
        """Test behavior with null or empty role values"""
        context = type('obj', (object,), {})()

        # Test with empty string
        result = role_badge(context, '')
        assert '<span class="badge badge-secondary"></span>' in result

        # Test with None - should still produce valid HTML
        result = role_badge(context, None)
        assert '<span class="badge badge-secondary">' in result

    def test_role_badge_escapes_data_uri_xss(self):
        """Test that data URI XSS attempts are escaped"""
        context = type('obj', (object,), {})()

        malicious_role = 'data:text/html,<script>alert("XSS")</script>'
        result = role_badge(context, malicious_role)

        # Should not contain unescaped data URI
        assert '<script>alert("XSS")</script>' not in result
        # Angle brackets should be escaped
        assert '&lt;script&gt;' in result

    def test_role_badge_escapes_encoded_xss_attempts(self):
        """Test that URL-encoded XSS attempts are handled safely"""
        context = type('obj', (object,), {})()

        malicious_role = '%3Cscript%3Ealert(1)%3C/script%3E'
        result = role_badge(context, malicious_role)

        # Should preserve the encoded string safely (escape won't decode it)
        assert '<script>' not in result
        # The percent-encoded string should be present and safe
        assert '%3Cscript%3E' in result

    def test_role_badge_prevents_context_breaking(self):
        """Test that attempts to break out of HTML context are prevented"""
        context = type('obj', (object,), {})()

        malicious_role = '</span><script>alert(1)</script><span>'
        result = role_badge(context, malicious_role)

        # Should not allow breaking out of the span context
        assert '</span><script>alert(1)</script><span>' not in result
        # Should contain escaped tags
        assert '&lt;/span&gt;&lt;script&gt;' in result


class TestAdminDashboardXSSProtection:
    """Integration tests for admin dashboard XSS protection"""

    def test_admin_dashboard_with_malicious_user_role(self, app, client, db_session):
        """Test that admin dashboard properly escapes malicious role values"""
        from models import User

        # Create a user with malicious XSS in role field
        malicious_user = User(
            username='attacker',
            email='attacker@example.com',
            role='<script>alert("XSS")</script>'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        # Request the admin dashboard
        response = client.get('/admin')

        # Should return 200 OK
        assert response.status_code == 200

        # The response should not contain unescaped script tags
        response_data = response.data.decode('utf-8')
        assert '<script>alert("XSS")</script>' not in response_data

        # Should contain escaped version
        assert '&lt;script&gt;' in response_data or 'script' not in response_data

    def test_admin_dashboard_with_multiple_malicious_users(self, app, client, db_session):
        """Test admin dashboard with multiple users having malicious roles"""
        from models import User

        # Create multiple users with different XSS payloads
        xss_payloads = [
            '<img src=x onerror=alert(1)>',
            '"><script>alert(2)</script>',
            '<svg onload=alert(3)>',
            'javascript:alert(4)'
        ]

        for i, payload in enumerate(xss_payloads):
            user = User(
                username=f'attacker{i}',
                email=f'attacker{i}@example.com',
                role=payload
            )
            user.set_password('password123')
            db_session.add(user)

        db_session.commit()

        # Request the admin dashboard
        response = client.get('/admin')
        assert response.status_code == 200

        response_data = response.data.decode('utf-8')

        # None of the payloads should be present in unescaped form
        for payload in xss_payloads:
            assert payload not in response_data

        # Should contain escaped angle brackets
        assert '&lt;' in response_data or '&#60;' in response_data

    def test_admin_dashboard_with_legitimate_roles_still_works(self, app, client, db_session):
        """Test that legitimate roles still display correctly after fix"""
        from models import User

        # Create users with legitimate roles
        legitimate_roles = ['admin', 'project_manager', 'team_member']

        for i, role in enumerate(legitimate_roles):
            user = User(
                username=f'user{i}',
                email=f'user{i}@example.com',
                role=role
            )
            user.set_password('password123')
            db_session.add(user)

        db_session.commit()

        # Request the admin dashboard
        response = client.get('/admin')
        assert response.status_code == 200

        response_data = response.data.decode('utf-8')

        # Should contain all legitimate role names
        assert 'admin' in response_data
        assert 'project_manager' in response_data
        assert 'team_member' in response_data

        # Should contain badge markup
        assert 'badge badge-danger' in response_data  # admin badge
        assert 'badge badge-primary' in response_data  # project_manager badge
        assert 'badge badge-secondary' in response_data  # team_member badge


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
