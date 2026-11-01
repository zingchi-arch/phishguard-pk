from phishguard.preprocessing import normalize_message, detect_language

def test_all_three_languages():
    assert detect_language('Your appointment is confirmed.')=='English'
    assert detect_language('Aap ka account band ho sakta hai')=='Roman Urdu'
    assert detect_language('آپ کا اکاؤنٹ بند ہو سکتا ہے')=='Urdu'

def test_roman_normalization():
    assert normalize_message('kia')=='kya'
    assert normalize_message('kiya')=='kya'

def test_urdu_letter_normalization():
    assert normalize_message('اپكى')==normalize_message('اپکی')

def test_preserve_negations():
    assert 'not' in normalize_message('Do not share',remove_stopwords=True)
