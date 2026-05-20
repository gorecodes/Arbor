import unittest
from pathlib import Path

import arbor.main as web_main


REPO_ROOT = Path(__file__).resolve().parents[2]


class CspMigrationTests(unittest.TestCase):
    def test_csp_header_drops_unsafe_eval(self):
        csp = web_main._SECURITY_HEADERS["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-eval", csp)

    def test_frontend_markup_uses_csp_safe_component_resolution(self):
        index_html = (REPO_ROOT / "frontend" / "alpine" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn('x-data="loginComponent()"', index_html)
        self.assertNotIn('x-data="dashboardComponent()"', index_html)
        self.assertNotIn("x-html=", index_html)
        self.assertNotIn("@click=\"navigateTo(", index_html)
        self.assertNotIn("@click=\"navigateBack()", index_html)
        self.assertNotIn(":style=\"`", index_html)
        self.assertNotIn("?.", index_html)
        self.assertNotIn("??", index_html)
        self.assertIn('x-data="loginComponent"', index_html)
        self.assertIn('x-data="dashboardComponent"', index_html)
        self.assertIn('x-ref="compileCatsHost"', index_html)

    def test_frontend_registers_components_with_alpine_data(self):
        app_js = (REPO_ROOT / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        for name in (
            "loginComponent",
            "appShellComponent",
            "dashboardComponent",
            "packageListComponent",
            "useFlagsExplorerComponent",
            "searchComponent",
            "depGraphComponent",
            "packageDetailComponent",
            "jobsViewComponent",
            "uninstallComponent",
            "installComponent",
            "updatesComponent",
            "overlayViewComponent",
        ):
            self.assertIn(f"Alpine.data('{name}'", app_js)


if __name__ == "__main__":
    unittest.main()
