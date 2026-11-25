import unittest
from datetime import datetime, timezone
from appsecctl.reports import report_filename, export_archive_filename

class ReportFilenameTests(unittest.TestCase):
    def test_image_and_zip_names(self):
        when = datetime(2026,11,25,9,29,28,tzinfo=timezone.utc)
        name = report_filename("pipeline","1234-abcd",{"pipeline":{"requested_image":"mirror.example:5000/team/nginx:latest"}},when=when)
        self.assertEqual(name,"appsec-image-mirror.example-5000-team-nginx-latest-20261125T092928Z-1234-abcd.html")
        self.assertEqual(export_archive_filename(when),"appsec-selected-reports-20261125T092928Z.zip")
    def test_repository_safe_name(self):
        name = report_filename("security_job","id",{"job":{"target":"https://git.example/a/b.git"}}, "sarif",
            datetime(2026,11,25,tzinfo=timezone.utc))
        self.assertEqual(name,"appsec-repository-git.example-a-b.git-20261125T000000Z-id.sarif")
