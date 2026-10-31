import unittest
from unittest.mock import patch
from fastapi import HTTPException
from pydantic import ValidationError
import app
from models import RegulatorySettings
from generator import inline

class RegressionTests(unittest.TestCase):
    def test_failed_scan_does_not_generate_report(self):
        with patch('app.scan_domain',return_value={'error':'Unavailable'}), patch('app.generate_pdf_report') as pdf:
            with self.assertRaises(HTTPException) as error:
                app.run_scan('example.com')
            self.assertEqual(error.exception.status_code,502)
            pdf.assert_not_called()

    def test_scan_identifier_cannot_escape_directory(self):
        with self.assertRaises(HTTPException) as error:
            app.generate_document('dpa','../../profile')
        self.assertEqual(error.exception.status_code,400)

    def test_download_cannot_escape_directory(self):
        with self.assertRaises(HTTPException):
            app.download_file('..\\app.py')

    def test_pdf_text_is_escaped_before_formatting(self):
        self.assertEqual(inline('**Čistoća & zaštita** <b>'), '<b>Čistoća &amp; zaštita</b> &lt;b&gt;')

    def test_schedule_uses_selected_frequency(self):
        with patch.object(app.scheduler,'add_job') as add:
            app.configure_schedule(RegulatorySettings(check_frequency='weekly'))
            self.assertEqual(add.call_args.kwargs['hours'],168)
        with self.assertRaises(ValidationError):
            RegulatorySettings(check_frequency='invalid')

if __name__ == '__main__':
    unittest.main()
