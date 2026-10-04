from pathlib import Path
from unittest.mock import MagicMock

from palo_alto_automation import PrismaAccessClient, PrismaSettings, find_url_list_key, update_edl

SETTINGS = PrismaSettings(
    client_id="sa@123.iam.panserviceaccount.com",
    client_secret="s",
    tsg_id="123",
    category_id="cat-1",
)


def json_response(body):
    response = MagicMock()
    response.ok = True
    response.content = b"{}"
    response.json.return_value = body
    return response


def make_client(category):
    session = MagicMock()
    session.post.return_value = json_response({"access_token": "tok"})
    session.request.side_effect = lambda method, url, **kw: json_response(
        {"data": category} if method == "GET" else {}
    )
    return PrismaAccessClient(SETTINGS, session=session), session


def test_find_url_list_key_prefers_known_names():
    assert find_url_list_key({"name": "x", "tags": [], "list": ["a"]}) == "list"
    assert find_url_list_key({"name": "x", "domains": ["a"]}) == "domains"


def test_add_domains_reports_changes_and_reuses_token():
    client, session = make_client({"name": "SOC Block", "list": ["old.example"]})
    result = client.update_domains("cat-1", "Bad.Example, old.example", "add")
    assert result == {
        "action": "add",
        "changed": ["bad.example"],
        "already_present": ["old.example"],
        "total_after": 2,
    }
    put = session.request.call_args_list[-1]
    assert put.args[0] == "PUT" and put.kwargs["json"]["list"] == ["bad.example", "old.example"]
    assert session.post.call_count == 1


def test_remove_without_match_does_not_put():
    client, session = make_client({"name": "SOC Block", "list": ["old.example"]})
    result = client.update_domains("cat-1", "missing.example", "remove")
    assert result["not_found"] == ["missing.example"]
    assert [call.args[0] for call in session.request.call_args_list] == ["GET"]


def test_edl_update(tmp_path):
    path = str(tmp_path / "ip_list.txt")
    assert update_edl(path, "198.51.100.7, 203.0.113.9/24, bogus", "add") == {
        "action": "add",
        "changed": ["198.51.100.7", "203.0.113.0/24"],
        "invalid": ["bogus"],
        "total_after": 2,
    }
    assert update_edl(path, "198.51.100.7", "remove")["changed"] == ["198.51.100.7"]
    assert Path(path).read_text() == "203.0.113.0/24\n"
