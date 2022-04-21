from ast import Pass
from password_validators.password_validator import PasswordValidator, ValidationError


with open('check_passwords.txt') as input_file, open('safe_passwords.txt', 'w') as output_file:
    for password in input_file:
        try:
            validator = PasswordValidator(password.strip())
            validator.is_valid()
            output_file.write(password.strip() + '\n')
        except ValidationError as error:
            print(password, error)
