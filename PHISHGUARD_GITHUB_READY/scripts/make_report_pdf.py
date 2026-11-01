"""Generate readable draft FYP PDF from ACTUAL tested demo metrics."""
from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.platypus import (SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,
                                Image,KeepTogether,HRFlowable,ListFlowable,ListItem)
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT,TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import cm
ROOT=Path(__file__).resolve().parents[1]
report=ROOT/'reports/PhishGuard_PK_FYP_Report_DRAFT.pdf'
metrics=json.loads((ROOT/'reports/text_metrics.json').read_text())
url_metrics=json.loads((ROOT/'reports/url_demo_metrics.json').read_text())
selected=next(r for r in metrics['test_results'] if r['model']==metrics['best_by_validation'])

font='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
fontb='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
pdfmetrics.registerFont(TTFont('DejaVu',font))
pdfmetrics.registerFont(TTFont('DejaVuBold',fontb))
NAVY=colors.HexColor('#0B1727');DARK=colors.HexColor('#24384F');MINT=colors.HexColor('#00A27B');GRAY=colors.HexColor('#687586');LINE=colors.HexColor('#DBE4E8');SOFT=colors.HexColor('#EAF7F3')
ss=getSampleStyleSheet()
ss.add(ParagraphStyle(name='CoverT',fontName='DejaVuBold',fontSize=27,leading=35,alignment=TA_CENTER,textColor=NAVY,spaceAfter=14))
ss.add(ParagraphStyle(name='CoverSub',fontName='DejaVu',fontSize=13,leading=20,alignment=TA_CENTER,textColor=DARK))
ss.add(ParagraphStyle(name='H1D',fontName='DejaVuBold',fontSize=16,leading=23,textColor=NAVY,spaceAfter=11,spaceBefore=5))
ss.add(ParagraphStyle(name='H2D',fontName='DejaVuBold',fontSize=11,leading=16,textColor=DARK,spaceAfter=7,spaceBefore=9))
ss.add(ParagraphStyle(name='BodyD',fontName='DejaVu',fontSize=8.4,leading=14,textColor=DARK,spaceAfter=8))
ss.add(ParagraphStyle(name='TinyD',fontName='DejaVu',fontSize=7.25,leading=11,textColor=DARK,spaceAfter=4))
ss.add(ParagraphStyle(name='SmallLight',fontName='DejaVu',fontSize=7.8,leading=12,textColor=GRAY,spaceAfter=6))
ss.add(ParagraphStyle(name='ReportWarn',fontName='DejaVuBold',fontSize=8.7,leading=14,textColor=colors.HexColor('#865318'),spaceAfter=6))
styles=ss
story=[]
def p(s,style='BodyD'):story.append(Paragraph(s,styles[style]))
def h(s):p(s,'H1D')
def hh(s):p(s,'H2D')
def sp(n=8):story.append(Spacer(1,n))
def page():story.append(PageBreak())
def tbl(rows,widths=None,header=True):
    t=Table([[Paragraph(str(c),styles['TinyD']) for c in r] for r in rows],colWidths=widths,repeatRows=1 if header else 0,hAlign='LEFT')
    cmds=[('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),8),
          ('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),7),
          ('BOTTOMPADDING',(0,0),(-1,-1),7),('GRID',(0,0),(-1,-1),.4,LINE)]
    if header:cmds+=[('BACKGROUND',(0,0),(-1,0),SOFT)]
    t.setStyle(TableStyle(cmds));story.append(t);sp(12)
def bullets(lines):
    for item in lines:p('&#8226; '+item,'BodyD')

def arch_diagram(out):
    fig,ax=plt.subplots(figsize=(9,2.9))
    ax.set_xlim(0,10);ax.set_ylim(0,4);ax.axis('off')
    boxes=[(0.3,1.7,1.6,0.6,'Message\ninput'),(2.4,2.7,2.2,0.6,'NLP + TF-IDF'),
           (2.4,.7,2.2,.6,'URL extraction'),(5.2,2.7,2.2,0.6,'Text model'),
           (5.2,.7,2.2,.6,'URL model'),(7.9,1.7,1.85,.6,'Verdict +\nreasons')]
    for x,y,w,hh_,text in boxes:
        ax.add_patch(plt.Rectangle((x,y),w,hh_,facecolor='#EAF7F3',edgecolor='#007D66',linewidth=1.5))
        ax.text(x+w/2,y+hh_/2,text,ha='center',va='center',fontsize=9)
    def arr(a,b):ax.annotate('',xy=b,xytext=a,arrowprops={'arrowstyle':'->','lw':1.3,'color':'#475569'})
    for a,b in [((1.9,2.0),(2.4,3.0)),((1.9,2.0),(2.4,1.0)),((4.6,3),(5.2,3)),((4.6,1),(5.2,1)),((7.4,3),(7.9,2)),((7.4,1),(7.9,2))]:arr(a,b)
    fig.tight_layout(pad=.2);fig.savefig(out,dpi=180,bbox_inches='tight');plt.close(fig)
arch_diagram(ROOT/'reports/architecture_diagram.png')

# COVER
sp(90)
p('FINAL YEAR PROJECT | DRAFT RESEARCH REPORT','CoverSub')
sp(25)
p('PhishGuard-PK','CoverT')
p('Multilingual Scam Message and URL Risk Detection','CoverSub')
p('English | Roman Urdu | Urdu','CoverSub')
sp(45)
story.append(HRFlowable(width='72%',thickness=1.7,color=MINT,hAlign='CENTER'))
sp(30)
p('Project type: BS Computer Science final-year project prototype','CoverSub')
p('Build date: 1 November 2026','CoverSub')
p('Student name / institution / supervisor: to be completed by the project owner','CoverSub')
sp(55)
p('<b>Research integrity notice</b>','BodyD')
p('The supplied application runs, but the currently available training labels are provisional and some cases are synthetic. This draft is not an externally validated security-system report or an advisor-approved thesis.','BodyD')
page()

h('01 | Executive summary and objectives')
p('PhishGuard-PK is a multilingual educational prototype for assessing user-supplied SMS, WhatsApp, email and social-media message text. It supports English, Roman Urdu and Urdu-script input. An offline URL inspector, a probabilistic text model, safety indicators, and explanatory features combine into a user-facing Safe / Suspicious / Scam verdict.')
hh('System objectives')
bullets(['Accept all three languages and normalize Roman Urdu spelling and common Urdu Unicode variants.',
         'Compare three machine-learning baselines with a grouped train/validation/test split.',
         'Inspect link features without opening suspected websites; support optional WHOIS registration age.',
         'Show a numerical risk <b>indicator</b>, plain-language rationale, and reproducible SHAP examples.',
         'Expose analysis through a simple web interface and FastAPI <b>POST /analyze</b>.'])
hh('High-level architecture')
story.append(Image(str(ROOT/'reports/architecture_diagram.png'),width=16*cm,height=5.2*cm))
p('Input text is screened by the language-aware text pipeline and a separate offline URL-analysis branch. The merged output includes a verdict, language estimate, risk indicator and reasons.','SmallLight')
hh('Scope boundary')
p('The prototype accepts pasted text and URLs, not screenshot OCR, voice, video or direct access to WhatsApp accounts. It does not fetch suspicious websites. Telegram integration is optional in the supplied requirements and has not been added.')
page()

h('02 | Data sources and provenance')
p('The starting audit contained 8,155 source records from earlier research, reduced to 7,353 distinct records after redaction. These are source <b>candidates</b>, not automatically verified Safe / Suspicious / Scam ground truth.')
tbl([['Stage','Rows','Interpretation'],['Prior audit source rows','8,155','Source-record inventory'],
     ['Deduplicated source candidates','7,353','Provisional public-source labels only'],
     ['Development training rows','5,750','Selected weak-label candidates plus 213 synthetic examples'],
     ['Training-approved examples','0','No independent individual-label review completed']],widths=[5.3*cm,2.2*cm,8.1*cm])
hh('Development corpus composition')
tbl([['Language field','Safe','Scam','Suspicious'],['English','977','44','15'],
     ['Roman Urdu','607','427','15'],['Urdu','35','44','15'],
     ['Unverified Latin','2,476','1,095','0']],widths=[5.3*cm,3.4*cm,3.4*cm,3.4*cm])
p('The Unverified Latin category must not be mislabeled as English. Genuine Urdu-script and Suspicious examples are particularly underrepresented. A portion of the development corpus is source-labeled but not individually reviewed; 213 examples were written as synthetic illustrations of documented local scam formats.')
hh('Crucial labeling exclusion')
p('Promotional messages and generic spam are NOT automatically phishing. Ambiguous source-label categories were excluded rather than silently reclassified as Suspicious/Scam. Original provenance and group identifiers are retained in the CSVs.')
page()

h('03 | Model methodology')
hh('Text normalization')
p('Unicode NFKC and selected Urdu character variants are normalized. Roman Urdu spellings such as kia/kiya/kya are mapped consistently. URL, phone and email indicators are preserved as tokens. Numbers are generalized. Optional stopword removal retains important negation terms.')
hh('Feature extraction')
p('Character-based TF-IDF n-grams of lengths 3-5 represent text. The approach is tolerant of some spelling variation and code-mixing. The trained baseline estimators are Complement Naive Bayes, calibrated Linear SVM and Random Forest.')
hh('Reproducible split and selection')
p(f'Grouping by message-template family reduced simple near-duplicate leakage. Split counts: train <b>{metrics["split_counts"]["train"]}</b>, validation <b>{metrics["split_counts"]["validation"]}</b>, test <b>{metrics["split_counts"]["test"]}</b>. The intended allocation is approximately 70/15/15; actual group sizes cause small deviations. Best model was selected by <b>validation macro F1</b>, then evaluated on the weak-label holdout.')
hh('Why macro F1 matters')
p('Accuracy can look high when Safe and Scam dominate. Macro F1 averages F1 equally across Safe, Suspicious and Scam, exposing weak performance on the smallest class. Validation results and test results are kept separate in this repository.')
hh('Multilingual transformer')
p('An optional reproducible XLM-RoBERTa training script, with GPU-aware Hugging Face Trainer code, is included. It was <b>not</b> executed in the local CPU build, and no transformer results are claimed.')
page()

h('04 | Experimental results - provisional labels')
p('<b>Important:</b> The following figures measure agreement with weak public source labels and synthetic scenarios. They do NOT constitute verified real-world fraud-detection accuracy.','ReportWarn')
test_results=metrics['test_results']
rows=[['Model','Weak test accuracy','Weak test macro F1']]
for r in test_results:rows.append([r['model'],f'{r["accuracy"]*100:.2f}%',f'{r["f1_macro"]:.3f}'])
tbl(rows,widths=[6.3*cm,4.5*cm,4.8*cm])
p(f'On the validation partition, <b>{metrics["best_by_validation"]}</b> ranked first by macro F1. Its weak-label test accuracy was <b>{selected["accuracy"]*100:.2f}%</b>, and macro F1 was <b>{selected["f1_macro"]:.3f}</b>. Its Suspicious-class F1 was only <b>{metrics["classification_report_provisional"]["Suspicious"]["f1-score"]:.3f}</b> on nine test examples.')
story.append(Image(str(ROOT/'reports/confusion_matrix.png'),width=10.1*cm,height=8.3*cm))
p('A strong-looking overall accuracy hides important minority-class errors. The language-specific weak test for Urdu had 18 examples (largely synthetic), with only 44.4% accuracy; it is not ready for security use.','SmallLight')
page()

h('05 | URL analysis and combined risk')
hh('URL features')
p('The URL module extracts web links using a regular expression and inspects URL length, HTTPS, special characters, hyphens, digits, IP addresses, shortened links, subdomain depth, suspicious keywords, punycode and optional domain registration age.')
p('The project never visits a supplied URL. WHOIS domain-age lookup is coded but disabled by default. Domain age is explicitly unknown when a lookup is unavailable; no date is invented.')
hh('Classifier and indicator')
p('The URL Random Forest was trained and tested only on generated examples using safe hostnames and reserved invalid domains. The resulting synthetic-fixture metric is not evidence of real-world phishing performance. It is combined with transparent offline rules as a URL risk indicator.')
p('Without a URL, the combined risk follows text-model signal. With a URL, a 70% text / 30% URL composition is used. A separate safety rule may raise the indicator for obvious requests for OTPs, passwords or bank details paired with prizes/threats. The output 0-100 is an <b>indicative score</b>, not a calibrated probability.')
hh('Why HTTPS does not prove trust')
p('A phishing page may present a valid HTTPS certificate. The scheme is just one feature and must never be treated as an allow-list.')
hh('Security / privacy')
p('Private and reserved IPs are rejected for optional external WHOIS queries. The live demo does not browse submitted URLs or log message histories. Public-share Colab links require explicit privacy caution.')
page()

h('06 | Explainability, API and web interface')
hh('User-facing explanations')
p('Users see the verdict, detected language, risk indicator, suspicious patterns and URL-feature warnings. These descriptions are pattern-based, human-readable reasons; they are not falsely presented as SHAP scores.')
hh('SHAP explanations')
p('The included script successfully computed text-token SHAP contributions to a selected prediction and Tree SHAP contributions from the URL Random Forest. Actual feature-attribution CSV outputs are included. SHAP explanations reflect the limitations of their underlying, provisionally trained models.')
p('Run: <b>python scripts/run_shap.py "You won a prize, verify now at https://bit.ly/claim-bonus"</b>')
hh('REST API')
p('The FastAPI endpoint is <b>POST /analyze</b>, accepting JSON with a message and returning verdict, risk indicator, detected language, class scores, extracted URLs and explanations. Validation rejects blank or very long messages. GET /health provides a status response.')
hh('Example input and output')
p('<b>Input (Roman Urdu):</b> Apka account band hoga, foran apna OTP bhejein.')
p('<b>Observed demo response:</b> Scam, indicative risk 85/100. The safety-rule floor detected an urgent sensitive-data request, overriding weak model confidence. It is a demo result, not a confirmed classification of a real received message.')
hh('User interface')
p('The Gradio UI has a message box, Check Message button, color-coded result, written explanation, URLs and JSON details. A Colab notebook provides a temporary web link, while local launch operates entirely on a user machine.')
page()

h('07 | Tests, failure analysis and limitations')
hh('Automated tests')
p('The current build passed <b>18 automated pytest checks</b> across Unicode normalization, language heuristic, URL parsing, offline safety, data splits, API input validation, and representative trilingual messages. Unit tests do not replace independent evaluation against new real-world scams.')
hh('Major failure modes')
bullets(['Only nine provisional Suspicious cases landed in the current holdout; Suspicious F1 was very weak.',
         'Urdu-script model generalization is poor and real independently confirmed Urdu phishing texts are scarce.',
         'Some public source Fraud labels appear questionable, and no individual label was approved by a reviewer.',
         'Synthetic training examples can inflate performance or create misleading feature patterns.',
         'Random Forest URL fixture uses generated URLs, producing unrealistically strong test performance.',
         'Heuristic language detection may confuse Roman Urdu with English and mixed-language messages.'])
hh('Ethical handling')
p('Collect only consented or appropriately licensed public messages; mask names, phone numbers, OTPs, passwords and tracking links. Never open malicious URLs during collection. Keep private data out of public repositories. Do not claim certainty or present the tool as an alternative to contacting the real bank/provider.')
hh('Research conclusion')
p('The implementation demonstrates a complete software architecture for three-language scam risk screening and explanation. It does <b>not</b> yet establish an academically defensible detection rate on independently labeled Pakistani real-world messages.')
page()

h('08 | Reproduction and required next experiments')
hh('How to run')
p('Install Python 3.10 or newer. Extract the ZIP, install requirements, then run <b>python run.py</b>; open <b>http://127.0.0.1:7860</b>. For backend docs run <b>uvicorn phishguard.api:app --port 8000</b> then visit <b>http://127.0.0.1:8000/docs</b>. Run <b>python -m pytest -q</b> for tests.')
hh('Requirements not yet independently satisfied')
bullets(['Independently review a genuinely representative three-language 3,000-5,000 message dataset; do not count synthetic examples as real.',
         'Create a locked, separate collection of 50-100 genuinely new, redacted, manually verified messages and complete external error analysis.',
         'Train XLM-RoBERTa on a free/available GPU, then compare with baselines using the same reviewed split.',
         'Obtain properly labeled and licensed URL datasets to replace synthetic URL fixtures; calibrate risk probabilities.',
         'Check source licences, publish to the student-owned GitHub account, and adapt the report to the institution\'s format.'])
hh('Repository orientation')
p('Key files: `phishguard/preprocessing.py`, `phishguard/urls.py`, `phishguard/inference.py`, `phishguard/api.py`, `phishguard/ui.py`, `scripts/train_text.py`, `scripts/train_urls.py`, `scripts/run_shap.py`, `scripts/train_transformer.py`, `data/`, `reports/`, `tests/`, and `colab/`.')
hh('Research and tool references')
p('Original project requirements PDF (user-provided); UCI SMS Spam Collection; Zenodo Roman Urdu candidate dataset; Pak Spam Guard public dataset; Pakistan 2026 SMS research dataset; documentation for scikit-learn, SHAP, Hugging Face Transformers, FastAPI and Gradio. Verify each source license and exact bibliographic details before thesis submission.','TinyD')


def footer(canvas,doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE);canvas.line(2*cm,1.6*cm,A4[0]-2*cm,1.6*cm)
    canvas.setFont('DejaVu',7);canvas.setFillColor(GRAY)
    canvas.drawString(2*cm,1.25*cm,'PhishGuard-PK | Research prototype | Draft - weak-label metrics')
    canvas.drawRightString(A4[0]-2*cm,1.25*cm,str(doc.page))
    canvas.restoreState()

doc=SimpleDocTemplate(str(report),pagesize=A4,rightMargin=2*cm,leftMargin=2*cm,
                      topMargin=2*cm,bottomMargin=2.2*cm,title='PhishGuard-PK FYP Report - Draft',
                      author='PhishGuard-PK Project',subject='Research prototype and honest evaluation')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
print('Created',report,report.stat().st_size)
