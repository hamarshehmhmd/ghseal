import pytest

from ghseal import dotenv


def test_parse_basic_forms():
    env = dotenv.parse('A=1\nexport B=two\nC="x y"\nD=\'lit $X \\n\'\n# c\n\nE=val # comment\nF=\n')
    assert env == {"A": "1", "B": "two", "C": "x y", "D": "lit $X \\n", "E": "val", "F": ""}


def test_double_quote_escapes_and_multiline():
    env = dotenv.parse('K="a\\nb\\"c\\\\"\nPEM="-----BEGIN-----\nline2\n-----END-----"\nZ=1')
    assert env["K"] == 'a\nb"c\\'
    assert env["PEM"] == "-----BEGIN-----\nline2\n-----END-----"
    assert env["Z"] == "1"


def test_hash_inside_value_kept():
    assert dotenv.parse("URL=http://x/#frag\nP='a # b'")["P"] == "a # b"
    assert dotenv.parse("URL=http://x/#frag")["URL"] == "http://x/#frag"


def test_crlf_and_later_wins():
    assert dotenv.parse("A=1\r\nA=2\r\n") == {"A": "2"}


def test_errors():
    with pytest.raises(dotenv.DotenvError, match="unterminated"):
        dotenv.parse('A="open\nB=2')
    with pytest.raises(dotenv.DotenvError, match="line 2"):
        dotenv.parse("A=1\nthis is not env")


def test_set_key_replace_append_and_quote():
    t = "A=1\nB=2\n"
    assert dotenv.parse(dotenv.set_key(t, "A", "new value")) == {"A": "new value", "B": "2"}
    t2 = dotenv.set_key(t, "C", 'q"uote\nnl')
    assert dotenv.parse(t2)["C"] == 'q"uote\nnl'
    assert t2.endswith("\n")


def test_set_key_replaces_multiline_value():
    t = 'A=1\nPEM="l1\nl2"\nB=2\n'
    out = dotenv.set_key(t, "PEM", "short")
    assert dotenv.parse(out) == {"A": "1", "PEM": "short", "B": "2"}
    assert "l2" not in out


def test_set_key_rejects_bad_name_and_unset():
    with pytest.raises(dotenv.DotenvError):
        dotenv.set_key("", "1BAD", "x")
    assert dotenv.parse(dotenv.unset_key("A=1\nB=2\n", "A")) == {"B": "2"}
