"""Regression on newly found Step46 false negatives and truthful reporting."""
from phishguard.inference import analyze_message
from phishguard.pakistan_rules import assess_pakistani_context
from scripts.step46_e2e_suite import evaluate
from scripts.step46_submission_audit import audit,generate_markdown


def test_fia_avoid_arrest_is_threat_not_advice():
    message='FIA case registered. Pay Rs 25000 today to avoid arrest: https://fia.gov.pk.evil.invalid'
    assert any(x.rule_id=='PK_GOV_THREAT_PAY' for x in assess_pakistani_context(message))
    assert analyze_message(message)['verdict']=='Scam'


def test_job_visa_wallet_advance_fee():
    message='Sarkari job approve ho gai hai. Processing fee Rs 8000 JazzCash par bhejo.'
    assert any(x.rule_id=='PK_JOB_VISA_WALLET_FEE' for x in assess_pakistani_context(message))
    assert analyze_message(message)['verdict']=='Scam'


def test_normal_job_application_is_not_automatically_scamming():
    message='Your job application is approved. Please check the official careers portal.'
    assert not any(x.rule_id=='PK_JOB_VISA_WALLET_FEE' for x in assess_pakistani_context(message))


def test_fraud_education_does_not_trigger_gov_threat():
    message='Scam alert: FIA does not ask you to pay a fine to avoid arrest over WhatsApp.'
    assert not any(x.rule_id=='PK_GOV_THREAT_PAY' for x in assess_pakistani_context(message))


def test_36_multilingual_synthetic_qa():
    report,rows=evaluate()
    assert len(rows)==36
    assert report['qa_pass']==36
    assert all(report['api_checks'].values())
    assert all(x['source_type']=='HAND_AUTHORED_SYNTHETIC_QA' and x['eligible_for_external_accuracy']=='NO' for x in rows)


def test_audit_never_misrepresents_final_readiness():
    report=audit()
    assert len(report['requirements'])==10
    assert report['final_university_acceptance_ready'] is False
    assert any(r['pdf_requirement']==9 and r['status']=='BLOCKED' for r in report['requirements'])
    assert 'not a validated fraud detector' in generate_markdown(report)
