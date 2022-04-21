from wsgiref.validate import validator
import pytest
from password_validators.password_validator import (
    HasNumberValidator, 
    HasSpecialCharValidator, 
    HasUpperCharValidator, 
    HasLowerCharValidator, 
    LengthValidator,
    HaveIBeenPwndValidator,
    ValidationError,
    PasswordValidator
)

def test_if_HasNumberValidator_positive():
    # given
    validator = HasNumberValidator('ab7cd')

    # when
    result = validator.is_valid()

    # then
    assert result is True

def test_if_Has_Number_Validator_negative():
    # given
    validator = HasNumberValidator('abcd')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain number' in str(error.value)


"""Test for Special characters"""

def test_if_HasSpecialCharValidator_positive():
    # given
    validator = HasSpecialCharValidator('ab*cd')

    # when
    result = validator.is_valid()

    # then
    assert result is True

def test_if_HasSpecialCharValidator_negative():
    # given
    validator = HasSpecialCharValidator('abcd')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain special character' in str(error.value)

"""Test for Upper Validator"""

def test_if_HasUpperCharValidator_positive():
    # given
    validator = HasUpperCharValidator('Admin')

    # when
    result = validator.is_valid()

    # then
    assert result is True

def test_if_HasUpperCharValidator_negative():
    # given
    validator = HasUpperCharValidator('@dmin')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least one lower letter' in str(error.value)


"""Test for Lower Validator"""

def test_if_HasLowerCharValidator_positive():
    # given
    validator = HasLowerCharValidator('a123@dmin')

    # when
    result = validator.is_valid()

    # then
    assert result is True

def test_if_HasLowerCharValidator_negative():
    # given
    validator = HasLowerCharValidator('@241')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least one upper letter' in str(error.value)


"""Test for Length Validator"""

def test_if_HasLength_positive():
    # given
    validator = LengthValidator('12345678')

    # when
    result = validator.is_valid()

    # then
    assert result is True

def test_if_HasLengthValidator_negative():
    # given
    validator = LengthValidator('@241')

    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password is too short! Must contain 8 or more characters' in str(error.value)

"""test if have i been pwnd"""

def test_have_i_been_pwnd_validator_positive(requests_mock):
    data = '200E348AEB5660FC2140AEC35850C4DA997:7\n\\r004F038BBA345C1FFECD6B8F087E0614E35:1'
    requests_mock.get('https://api.pwnedpasswords.com/range/D033E', text=data)
    validator = HaveIBeenPwndValidator('admin')
    assert validator.is_valid() is True

def test_have_i_been_pwnd_validator_negative(requests_mock):
    # text: admin
    # hash: D033E22AE348AEB5660FC2140AEC35850C4DA997
    data = '22AE348AEB5660FC2140AEC35850C4DA997:8\n\r004F038BBA345C1FFECD6B8F087E0614E35:1'
    requests_mock.get('https://api.pwnedpasswords.com/range/D033E', text=data)
    validator = HaveIBeenPwndValidator('admin')
    # when
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'This password is leaked! Choose another one' in str(error.value)


    """Test password validator"""

def test_password_validator_positive():
    validator = PasswordValidator('Admin123*q@Q')
    assert validator.is_valid() is True

def test_password_validator_negative():
    validator = PasswordValidator('admin123*q@q')

    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain one or more upper letters' in str(error.value)
