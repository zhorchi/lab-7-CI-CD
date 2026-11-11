from app.new_feature import calculate_score


def test_calculate_score():
    assert calculate_score(10, 2) == 20


def test_calculate_score_negative():
    assert calculate_score(-10, 2) == 0