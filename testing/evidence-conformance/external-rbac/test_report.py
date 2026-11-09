import unittest
from report import Refused, assess, assess_all


def html(method="GET", verdict="VALID", principal="reader"):
    return ('<table id="table"><thead><tr><th></th><th></th>'
            f'<th colspan="2">{principal}</th></tr><tr>'
            '<th>Method</th><th>URL</th><th>Authorization</th><th>Access control</th>'
            '</tr></thead><tbody><tr>'
            f'<td>{method}</td><td><a href="http://localhost/admin/keys">'
            'http://localhost/admin/keys</a></td><td>Authorized</td>'
            f'<td class="{verdict}">localized label</td></tr></tbody></table>')


class Accounting(unittest.TestCase):
    def assess(self, data, method="GET", principals=("reader",)):
        return assess(data, method, "http://localhost/admin/keys", principals)

    def test_upstream_valid_is_preserved(self):
        self.assertEqual(self.assess(html())[0]["upstream_result"], "VALID")

    def test_wrong_method_cannot_cover_missing_verb(self):
        with self.assertRaises(Refused):
            self.assess(html(), method="POST")

    def test_illegal_unknown_or_missing_class_fail(self):
        for verdict in ("ILLEGAL", "UNKNOWN", "", "valid"):
            with self.subTest(verdict=verdict), self.assertRaises(Refused):
                self.assess(html(verdict=verdict))

    def test_empty_duplicate_or_wrong_users_fail(self):
        for users in ((), ("reader", "reader"), ("full",), ("reader", "full")):
            with self.subTest(users=users), self.assertRaises(Refused):
                self.assess(html(), principals=users)

    def test_missing_extra_truncated_reports_fail(self):
        for data in ("", html()+html(), html().replace('</table>', ''),
                     html().replace('<td>Authorized</td>', '')):
            with self.subTest(data=data), self.assertRaises(Refused):
                self.assess(data)

    def test_multiple_operations_must_be_separate_reports(self):
        data = html().replace('</tbody>', '<tr><td>POST</td></tr></tbody>')
        with self.assertRaises(Refused):
            self.assess(data)

    def test_full_roster_cannot_drop_method_or_duplicate_report(self):
        uri = "http://localhost/admin/keys"
        roster = [("GET", uri, ["reader"]), ("POST", uri, ["reader"])]
        get = ("GET", uri, html())
        post = ("POST", uri, html(method="POST"))
        self.assertEqual(len(assess_all([get, post], roster)), 2)
        for reports, expected in (([get], roster), ([get, get], roster),
                                  ([get, post, post], roster), ([], []),
                                  ([get], [roster[0], roster[0]])):
            with self.subTest(reports=reports), self.assertRaises(Refused):
                assess_all(reports, expected)


if __name__ == '__main__':
    unittest.main()
