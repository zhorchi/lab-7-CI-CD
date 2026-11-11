from unittest.mock import Mock, patch

from security_examples.demo import check_host, lookup_user


def test_lookup_user_passes_input_as_sql_parameter():
    cursor = Mock()
    user_id = "1 OR 1=1"
    cursor.fetchone.return_value = ("Alice",)

    result = lookup_user(cursor, user_id)

    cursor.execute.assert_called_once_with(
        "SELECT name FROM users WHERE id = ?",
        (user_id,),
    )
    cursor.fetchone.assert_called_once_with()
    assert result == ("Alice",)


def test_check_host_passes_argument_list_without_shell():
    host = "localhost; echo injected"
    with patch("security_examples.demo.subprocess.run") as run:
        result = check_host(host)

    run.assert_called_once_with(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
    )
    assert result is run.return_value
