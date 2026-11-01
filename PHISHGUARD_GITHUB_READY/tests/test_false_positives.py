"""Regression tests for user-reported normal message and high-signal scam signals."""
from phishguard.inference import analyze_message

def test_user_reported_meeting_is_safe():
    msg = 'Hi Ahmed, our meeting is scheduled for tomorrow at 10 AM. Please bring your documents. Thank you!'
    result = analyze_message(msg)
    assert result['verdict'] == 'Safe', result
    assert result['language_detected'] == 'English'
    assert result['safety_rule_floor'] == 0

def test_normal_roman_urdu():
    assert analyze_message('Aap ki appointment kal 5 baje hai. Shukriya.')['verdict'] == 'Safe'

def test_normal_urdu():
    assert analyze_message('آپ کی اپائنٹمنٹ کل شام پانچ بجے ہے۔ شکریہ۔')['verdict'] == 'Safe'

def test_roman_urdu_banking_bait_still_flagged():
    msg = 'Mubarak ho! Apka 50000 rupay ka inaam nikla hai. Inaam lene ke liye apni bank details bhejein.'
    assert analyze_message(msg)['verdict'] == 'Scam'

def test_urdu_banking_bait_still_flagged():
    msg = 'مبارک ہو! آپ نے پچاس ہزار روپے کا انعام جیت لیا ہے۔ انعام حاصل کرنے کے لیے اپنی بینک کی معلومات فراہم کریں۔'
    assert analyze_message(msg)['verdict'] == 'Scam'

def test_english_urgent_verification_still_flagged():
    assert analyze_message('Your bank account may be closed. Please verify your identity immediately.')['verdict'] == 'Scam'
