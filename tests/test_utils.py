"""
Test the `utils` module
"""

import os

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def compare(user, dct):
    if 'disabled' in dct:
        assert dct['disabled'] == user.is_disabled()
        del dct['disabled']
    if 'computer_account' in dct:
        assert dct['computer_account'] == user.is_computer_account()
        del dct['computer_acccount']
    for k, v in dct.items():
        assert getattr(user, k) == v


def test_user():
    from hashcathelper.utils import User
    test_cases = {
        'group.local\\Administrator:': dict(
            username='Administrator',
            upn_suffix='group.local',
            password='',
            disabled=False,
        ),

        r'contoso.local\User01313:1313:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)': dict(  # noqa
            username='User01313',
            upn_suffix='contoso.local',
            password=None,
            comment='(status=Disabled)',
            disabled=True,
        ),
    }
    for line, expected in test_cases.items():
        u = User(line)
        print(u)
        compare(u, expected)
