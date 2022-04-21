"""Collection of password validators"""
from abc import ABC, abstractmethod
from hashlib import sha1
import re
from requests import get

class ValidationError(Exception):
    """Exception for validation error"""


class Validator(ABC):
    """Interface for validators"""
    @abstractmethod
    def __init__(self, text):
        """Force to implement __init__ method"""

    @abstractmethod
    def is_valid(self):
        """Force to implement is_valid method"""


class LengthValidator(Validator):
    """Validator that checks if password have min. 8 letters"""
    def __init__(self, text, min_length = 8):
        self.text = text
        self.min_length = min_length

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text is not valid because password must have 8 or more letters

        Returns:
            bool: text is long enough
        """
        if len(self.text) >= self.min_length:
            return True

        raise ValidationError('Password is too short! Must contain 8 or more characters')


class HasNumberValidator(Validator):
    """Validator that checks if number appears in text"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text is not valid because there is no number in text

        Returns:
            bool: has number in text
        """
        for number in self.text:
            if re.search(r"\d", number):
                return True
        raise ValidationError('Password must contain number')


class HasSpecialCharValidator(Validator):
    """Validator that checks if special character appears in text"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text is not valid because there is no special character in text

        Returns:
            bool: has special character in text
        """
        for character in self.text:
            if re.findall("[@!#$%^&*]", character):
                return True
        raise ValidationError('Password must contain special character')


class HasUpperCharValidator(Validator):
    """Validator that checks if upper letter appears in text"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text is not valid because there is no upper letter in text

        Returns:
            bool: has upper letter in text
        """
        if any([character.isupper() for character in self.text]):
            return True
        raise ValidationError('Password must contain at least one upper letter')


class HasLowerCharValidator(Validator):
    """Validator that checks if lower letter appears in text"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: text is not valid because there is no lower letter in text

        Returns:
            bool: has lower letter in text
        """
        for lower in self.text:
            if lower.islower():
                return True
        raise ValidationError('Password must contain at least one upper letter')


class HaveIBeenPwndValidator(Validator):
    """Validator that checks if password is safe"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidationError: your password has been leaked

        Returns:
            bool: password is safe
        """
        hash_of_password = sha1(self.password.encode('utf-8')).hexdigest().upper()
        response = get(f'https://api.pwnedpasswords.com/range/{hash_of_password[:5]}')

        for line in response.text.splitlines():
            found_hash, _ = line.split(':')
            if found_hash == hash_of_password[5:]:
                raise ValidationError('This password is leaked! Choose another one')
        return True


class PasswordValidator(Validator):
    """Validator that checks if all requirements are passed"""
    def __init__(self, password):
        self.password = password
        self.validators = [
            LengthValidator,
            HasNumberValidator,
            HasSpecialCharValidator,
            HasUpperCharValidator,
            HasLowerCharValidator,
            HaveIBeenPwndValidator
        ]

    def is_valid(self):
        """Checks if password is valid

        Returns:
            bool: return true if password passed all requirements
        """
        for class_name in self.validators:
            validator = class_name(self.password)
            if validator.is_valid() is False:
                return False
        return True


#validator = PasswordValidator('qwerty')
#print(validator.is_valid())
