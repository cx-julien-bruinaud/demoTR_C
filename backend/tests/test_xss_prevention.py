"""
Tests for XSS prevention in Jinja2 filters and admin dashboard
This test suite validates the fix for Stored XSS vulnerability (CWE-79)
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template_string
from models import db, User, Project, Task
from utils.jinja_filters import role_badge


class TestRoleBadgeXSSPrevention:
    """Test that role_badge filter properly escapes HTML to prevent XSS"""

    def test_role_badge_escapes_script_tags(self):
        """Test that script tags in role are escaped"""
        from jinja2 import Template
        from markupsafe import escape

        # Create a mock context
        class MockContext:
            pass

        context = MockContext()

        # Test malicious role with script tag
        malicious_role = '<script>alert("XSS")</script>'
        result = role_badge(context, malicious_role)

        # Verify script tag is escaped and not executable
        assert '<script>' not in result
        assert '&lt;script&gt;' in result
        assert 'alert' in result  # The text should still be there, but escaped
        assert 'badge' in result  # Badge HTML should still be present

    def test_role_badge_escapes_img_onerror(self):
        """Test that img tags with onerror are escaped"""
        from jinja2 import Template

        class MockContext:
            pass

        context = MockContext()

        # Test malicious role with img onerror XSS
        malicious_role = '<img src=x onerror="alert(1)">'
        result = role_badge(context, malicious_role)

        # Verify img tag is escaped
        assert '<img' not in result
        assert '&lt;img' in result
        assert 'onerror' in result  # Text present but escaped
        assert 'badge' in result

    def test_role_badge_escapes_event_handlers(self):
        """Test that event handlers are escaped"""
        class MockContext:
            pass

        context = MockContext()

        # Test malicious role with event handler
        malicious_role = '" onload="alert(\'XSS\')'
        result = role_badge(context, malicious_role)

        # Verify quotes are escaped
        assert 'onload' in result
        assert '&quot;' in result or '&#34;' in result
        # Should not have executable onload attribute
        assert 'onload="alert' not in result

    def test_role_badge_escapes_html_entities(self):
        """Test that HTML entities are properly escaped"""
        class MockContext:
            pass

        context = MockContext()

        # Test role with HTML special characters
        malicious_role = '"><script>alert(document.cookie)</script>'
        result = role_badge(context, malicious_role)

        # Verify all special characters are escaped
        assert '&quot;' in result or '&#34;' in result
        assert '&gt;' in result
        assert '&lt;script&gt;' in result

    def test_role_badge_normal_roles_work(self):
        """Test that normal, legitimate roles still work correctly"""
        class MockContext:
            pass

        context = MockContext()

        # Test valid roles
        for role in ['admin', 'project_manager', 'team_member']:
            result = role_badge(context, role)
            assert f'<span class="badge' in result
            assert role in result
            assert 'badge-danger' in result or 'badge-primary' in result or 'badge-secondary' in result

    def test_role_badge_unknown_role_handled(self):
        """Test that unknown roles default to secondary badge"""
        class MockContext:
            pass

        context = MockContext()

        # Test unknown but safe role
        result = role_badge(context, 'custom_role')
        assert 'badge-secondary' in result
        assert 'custom_role' in result


class TestAdminDashboardXSSPrevention:
    """Test that admin dashboard properly prevents XSS attacks"""

    def test_admin_dashboard_with_malicious_user_role(self, app, db_session):
        """Test admin dashboard with XSS in user role field"""
        with app.app_context():
            # Create user with malicious role
            malicious_user = User(
                username='attacker',
                email='attacker@example.com',
                role='<script>alert("XSS")</script>'
            )
            malicious_user.set_password('password123')
            db_session.add(malicious_user)
            db_session.commit()

            # Register jinja filters
            from utils.jinja_filters import (
                format_datetime, user_display_name, truncate,
                md5_hash, request_id_filter, format_file_size, role_badge
            )
            app.jinja_env.filters['format_datetime'] = format_datetime
            app.jinja_env.filters['user_display_name'] = user_display_name
            app.jinja_env.filters['truncate'] = truncate
            app.jinja_env.filters['md5_hash'] = md5_hash
            app.jinja_env.filters['request_id_filter'] = request_id_filter
            app.jinja_env.filters['format_file_size'] = format_file_size
            app.jinja_env.filters['role_badge'] = role_badge

            # Define admin_dashboard route
            @app.route('/admin')
            def admin_dashboard():
                users = User.query.all()
                projects = Project.query.all()
                tasks = Task.query.all()
                return render_template_string(
                    '{% for user in users %}{{ user.role|role_badge|safe }}{% endfor %}',
                    users=users,
                    projects=projects,
                    tasks=tasks,
                    request_id='test-request-id'
                )

            # Make request to admin dashboard
            with app.test_client() as client:
                response = client.get('/admin')
                html = response.data.decode('utf-8')

                # Verify script tag is escaped
                assert '<script>alert("XSS")</script>' not in html
                assert '&lt;script&gt;' in html
                # Badge HTML should still be present
                assert 'badge' in html

    def test_admin_dashboard_with_malicious_username(self, app, db_session):
        """Test admin dashboard with XSS in username field"""
        with app.app_context():
            # Create user with malicious username
            malicious_user = User(
                username='<img src=x onerror="alert(1)">',
                email='test@example.com',
                role='admin'
            )
            malicious_user.set_password('password123')
            db_session.add(malicious_user)
            db_session.commit()

            # Register jinja filters
            from utils.jinja_filters import user_display_name
            app.jinja_env.filters['user_display_name'] = user_display_name

            # Create a simple template to test username display
            @app.route('/test-username')
            def test_username():
                users = User.query.all()
                # Note: user_display_name returns plain text, which Jinja2 auto-escapes
                return render_template_string(
                    '{% for user in users %}{{ user|user_display_name }}{% endfor %}',
                    users=users
                )

            # Make request
            with app.test_client() as client:
                response = client.get('/test-username')
                html = response.data.decode('utf-8')

                # Jinja2 auto-escapes by default, so img tag should be escaped
                assert '<img' not in html or '&lt;img' in html

    def test_admin_dashboard_multiple_xss_attempts(self, app, db_session):
        """Test admin dashboard with multiple XSS vectors"""
        with app.app_context():
            # Create multiple users with different XSS payloads
            xss_payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(2)</script>',
                '<img src=x onerror=alert(3)>',
                'javascript:alert(4)',
                '<svg onload=alert(5)>',
                '<iframe src="javascript:alert(6)">',
            ]

            for i, payload in enumerate(xss_payloads):
                user = User(
                    username=f'user{i}',
                    email=f'user{i}@example.com',
                    role=payload
                )
                user.set_password('password123')
                db_session.add(user)

            db_session.commit()

            # Register jinja filters
            from utils.jinja_filters import role_badge
            app.jinja_env.filters['role_badge'] = role_badge

            # Define test route
            @app.route('/test-xss')
            def test_xss():
                users = User.query.all()
                return render_template_string(
                    '{% for user in users %}{{ user.role|role_badge|safe }}{% endfor %}',
                    users=users
                )

            # Make request
            with app.test_client() as client:
                response = client.get('/test-xss')
                html = response.data.decode('utf-8')

                # Verify none of the XSS payloads are present in executable form
                assert '<script>alert(1)</script>' not in html
                assert '<script>alert(2)</script>' not in html
                assert 'onerror=alert(3)' not in html
                assert '<svg onload=alert(5)>' not in html
                assert '<iframe src="javascript:alert(6)">' not in html

                # Verify escaped versions are present
                assert '&lt;script&gt;' in html or '&lt;' in html

    def test_admin_dashboard_preserves_functionality(self, app, db_session, sample_user):
        """Test that XSS fix doesn't break normal functionality"""
        with app.app_context():
            # Register jinja filters
            from utils.jinja_filters import role_badge
            app.jinja_env.filters['role_badge'] = role_badge

            # Define test route
            @app.route('/test-normal')
            def test_normal():
                users = User.query.all()
                return render_template_string(
                    '{% for user in users %}{{ user.role|role_badge|safe }}{% endfor %}',
                    users=users
                )

            # Make request
            with app.test_client() as client:
                response = client.get('/test-normal')
                html = response.data.decode('utf-8')

                # Verify normal role is displayed correctly
                assert 'team_member' in html
                assert 'badge' in html
                assert 'badge-secondary' in html


class TestXSSRegressionPrevention:
    """Tests to prevent regression of the XSS vulnerability"""

    def test_data_flow_from_database_to_template(self, app, db_session):
        """Test complete data flow: DB -> Query -> Template rendering"""
        with app.app_context():
            # Create user with XSS payload in role (simulating stored XSS)
            xss_user = User(
                username='xss_test',
                email='xss@test.com',
                role='<script>document.location="http://evil.com"</script>'
            )
            xss_user.set_password('test123')
            db_session.add(xss_user)
            db_session.commit()

            # Query database (simulating line 139 of app.py)
            users = User.query.all()

            # Verify data was stored
            assert len(users) > 0
            assert any('<script>' in u.role for u in users)

            # Register role_badge filter
            from utils.jinja_filters import role_badge
            app.jinja_env.filters['role_badge'] = role_badge

            # Render template (simulating line 141 of app.py)
            @app.route('/test-dataflow')
            def test_dataflow():
                all_users = User.query.all()
                return render_template_string(
                    '{% for user in users %}{{ user.role|role_badge|safe }}{% endfor %}',
                    users=all_users
                )

            with app.test_client() as client:
                response = client.get('/test-dataflow')
                html = response.data.decode('utf-8')

                # Critical assertion: Script should be escaped in output
                assert '<script>document.location=' not in html
                assert '&lt;script&gt;' in html

    def test_edge_case_empty_role(self):
        """Test edge case with empty role"""
        class MockContext:
            pass

        context = MockContext()

        # Test with empty string
        result = role_badge(context, '')
        assert 'badge' in result
        assert 'badge-secondary' in result

    def test_edge_case_none_role(self):
        """Test edge case with None role"""
        class MockContext:
            pass

        context = MockContext()

        # Test with None - this might raise an exception, which is acceptable
        try:
            result = role_badge(context, None)
            # If it doesn't raise, verify it's safe
            assert 'badge' in result
        except (TypeError, AttributeError):
            # It's acceptable to raise an error for None
            pass

    def test_special_characters_in_role(self):
        """Test various special characters in role"""
        class MockContext:
            pass

        context = MockContext()

        special_chars = [
            '&', '<', '>', '"', "'", '/', '\\',
            '&#', '&lt;', '&gt;', '&quot;', '&#x27;'
        ]

        for char in special_chars:
            result = role_badge(context, char)
            # Verify the character is either escaped or safe
            assert 'badge' in result
            # Original dangerous chars should not appear unescaped
            if char in ['<', '>', '"', "'"]:
                assert char not in result or f'badge-{char}' not in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
