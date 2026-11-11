def is_prime(number: int) -> bool:
    if number < 2:
        return False

    for divisor in range(2, int(number**0.5) + 1):
        if number % divisor == 0:
            return False

    return True

def is_even(number: int) -> bool:
    return number % 2 == 0