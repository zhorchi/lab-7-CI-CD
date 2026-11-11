def calculate_score(points: int, multiplier: int) -> int:
    if points < 0:
        return 0

    return points * multiplier