from inboxtrue.cli import addresses


def test_addresses():
    assert list(addresses(['a@x.com', 'b@x.com'], [])) == ['a@x.com', 'b@x.com']
    assert list(addresses([], ['a@x.com\n', '\n', '# note\n', ' b@x.com '])) == ['a@x.com', 'b@x.com']
    assert list(addresses(['z@x.com', '-'], ['a@x.com\n'])) == ['z@x.com', 'a@x.com']
