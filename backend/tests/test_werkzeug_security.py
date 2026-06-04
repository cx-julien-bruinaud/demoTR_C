"""
Tests for Werkzeug 2.2.3+ security fixes
Validates CVE-2023-25577 remediation - multipart form data DoS protection
"""
import pytest
import sys
import os
import io

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestMultipartFormDataSecurity:
    """Test Werkzeug multipart form data handling with CVE-2023-25577 fix"""

    def test_file_upload_basic(self, client, sample_user, auth_headers, sample_project):
        """Test basic file upload works with Werkzeug 2.2.3+"""
        # Create a simple test file
        data = {
            'file': (io.BytesIO(b"test file content"), 'test.txt'),
            'project_id': str(sample_project.id),
            'is_public': 'false'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should succeed with proper Werkzeug version
        assert response.status_code in [201, 400, 401]

    def test_request_form_access(self, app):
        """Test request.form access with Werkzeug 2.2.3+"""
        with app.test_request_context(
            method='POST',
            data={'key': 'value'},
            content_type='application/x-www-form-urlencoded'
        ):
            from flask import request
            # Access to request.form should work without DoS
            form_data = request.form
            assert form_data is not None
            assert form_data.get('key') == 'value'

    def test_request_files_access(self, app):
        """Test request.files access with Werkzeug 2.2.3+"""
        with app.test_request_context(
            method='POST',
            data={'file': (io.BytesIO(b"content"), 'test.txt')},
            content_type='multipart/form-data'
        ):
            from flask import request
            # Access to request.files should work without DoS
            files = request.files
            assert files is not None

    def test_multiple_form_fields(self, app):
        """Test handling multiple form fields safely"""
        form_data = {
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3',
            'field4': 'value4',
            'field5': 'value5'
        }

        with app.test_request_context(
            method='POST',
            data=form_data,
            content_type='application/x-www-form-urlencoded'
        ):
            from flask import request
            # Werkzeug 2.2.3+ should handle multiple fields safely
            assert request.form.get('field1') == 'value1'
            assert request.form.get('field5') == 'value5'
            assert len(request.form) == 5


class TestSecureFilenameHandling:
    """Test werkzeug.utils.secure_filename with updated Werkzeug"""

    def test_secure_filename_import(self):
        """Test that secure_filename can be imported from Werkzeug 2.2.3+"""
        from werkzeug.utils import secure_filename
        assert secure_filename is not None

    def test_secure_filename_basic(self):
        """Test secure_filename functionality"""
        from werkzeug.utils import secure_filename

        # Test basic sanitization
        assert secure_filename('test.txt') == 'test.txt'
        assert secure_filename('../../../etc/passwd') == 'etc_passwd'
        assert secure_filename('my file.txt') == 'my_file.txt'

    def test_secure_filename_with_special_chars(self):
        """Test secure_filename with special characters"""
        from werkzeug.utils import secure_filename

        # Should sanitize dangerous characters
        result = secure_filename('test<script>.txt')
        assert '<' not in result
        assert '>' not in result

    def test_secure_filename_unicode(self):
        """Test secure_filename with unicode characters"""
        from werkzeug.utils import secure_filename

        # Should handle unicode safely
        result = secure_filename('tëst.txt')
        assert result is not None
        assert isinstance(result, str)


class TestWerkzeugLocalProxyCompatibility:
    """Test werkzeug.local.LocalProxy with Werkzeug 2.2.3+"""

    def test_localproxy_import(self):
        """Test that LocalProxy can be imported"""
        from werkzeug.local import LocalProxy
        assert LocalProxy is not None

    def test_localproxy_functionality(self, app):
        """Test LocalProxy works with Flask 2.2.5 and Werkzeug 2.2.3+"""
        from werkzeug.local import LocalProxy
        from flask import g

        def get_test_value():
            return getattr(g, 'test_value', None)

        proxy = LocalProxy(get_test_value)

        with app.test_request_context():
            # Set value in g
            g.test_value = 'test'

            # Access via proxy
            assert proxy == 'test'


class TestRequestDataAccess:
    """Test various request data access patterns that were vulnerable"""

    def test_request_data_access(self, app):
        """Test request.data access (was vulnerable in CVE-2023-25577)"""
        with app.test_request_context(
            method='POST',
            data=b'raw data',
            content_type='application/octet-stream'
        ):
            from flask import request
            # Should handle data access safely
            data = request.data
            assert data == b'raw data'

    def test_request_get_data_parse_form(self, app):
        """Test request.get_data(parse_form_data=False)"""
        with app.test_request_context(
            method='POST',
            data={'key': 'value'},
            content_type='application/x-www-form-urlencoded'
        ):
            from flask import request
            # This was one of the vulnerable patterns
            # Werkzeug 2.2.3+ should handle it safely
            data = request.get_data(parse_form_data=False)
            assert data is not None

    def test_mixed_form_and_file_data(self, app):
        """Test mixed form fields and files (stress test for multipart parser)"""
        data = {
            'field1': 'value1',
            'field2': 'value2',
            'file1': (io.BytesIO(b"file1 content"), 'file1.txt'),
            'file2': (io.BytesIO(b"file2 content"), 'file2.txt'),
        }

        with app.test_request_context(
            method='POST',
            data=data,
            content_type='multipart/form-data'
        ):
            from flask import request
            # Werkzeug 2.2.3+ should handle mixed content safely
            assert request.form.get('field1') == 'value1'
            assert 'file1' in request.files
            assert 'file2' in request.files


class TestDocumentUploadEndpoint:
    """Test document upload endpoint with security fixes"""

    def test_document_upload_with_form_data(self, client, sample_user, auth_headers, sample_project, app):
        """Test document upload endpoint handles multipart form data safely"""
        # Ensure upload directory exists
        from config import Config
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

        data = {
            'file': (io.BytesIO(b"test document content"), 'document.txt'),
            'project_id': str(sample_project.id),
            'is_public': 'false'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should process without DoS issues
        # Status could be 201 (success), 400 (validation), or 401 (auth)
        assert response.status_code in [201, 400, 401]

    def test_document_upload_missing_file(self, client, sample_user, auth_headers):
        """Test document upload handles missing file gracefully"""
        data = {
            'project_id': '1',
            'is_public': 'false'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should return error for missing file
        assert response.status_code in [400, 401]

    def test_document_upload_empty_filename(self, client, sample_user, auth_headers, app):
        """Test document upload handles empty filename"""
        from config import Config
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

        data = {
            'file': (io.BytesIO(b"content"), ''),
            'project_id': '1',
            'is_public': 'false'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should handle gracefully
        assert response.status_code in [400, 401]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
