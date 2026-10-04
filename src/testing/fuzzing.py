from hypothesis import given
from hypothesis import strategies as st


@given(
    username=st.text(),
    password=st.text(),
)
def test_login_input_never_crashes(
    username: str,
    password: str,
):

    assert isinstance(username, str)
    assert isinstance(password, str)