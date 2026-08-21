from unittest import mock

from django.test import TestCase, override_settings


@override_settings(
    BADGR_BLACKLIST_API_KEY="test-key",
    BADGR_BLACKLIST_QUERY_ENDPOINT="http://blacklist.example.test/query",
)
class BlacklistTimeoutTests(TestCase):
    def test_query_recipient_id_passes_a_timeout(self):
        from mainsite import blacklist

        with mock.patch("mainsite.blacklist.requests.get") as mock_get:
            mock_get.return_value = mock.Mock(status_code=200, json=lambda: [])
            blacklist.api_query_recipient_id(
                "email",
                "test@example.test",
                "http://blacklist.example.test/query",
                "test-key",
            )

        self.assertIn("timeout", mock_get.call_args.kwargs)
        self.assertIsNotNone(mock_get.call_args.kwargs["timeout"])

    def test_submit_recipient_id_passes_a_timeout(self):
        from mainsite import blacklist

        with mock.patch("mainsite.blacklist.requests.post") as mock_post:
            mock_post.return_value = mock.Mock(status_code=200)
            blacklist.api_submit_recipient_id("email", "test@example.test")

        self.assertIn("timeout", mock_post.call_args.kwargs)
        self.assertIsNotNone(mock_post.call_args.kwargs["timeout"])

    def test_a_timeout_is_treated_the_same_as_a_connection_error(self):
        from mainsite import blacklist
        import requests

        with mock.patch(
            "mainsite.blacklist.requests.get",
            side_effect=requests.exceptions.Timeout,
        ):
            with self.assertRaises(Exception) as ctx:
                blacklist.api_query_is_in_blacklist("email", "test@example.test")

        self.assertEqual(str(ctx.exception), "Blacklist failed to respond")
