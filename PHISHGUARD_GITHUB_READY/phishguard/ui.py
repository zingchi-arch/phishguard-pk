"""Colab-compatible Gradio interface for PhishGuard-PK.

The primary responsive website is served through FastAPI via `python run_web.py`.
This interface adds public Gradio sharing and the same single/batch capabilities.
"""
import html
import os
import tempfile
import pandas as pd
import gradio as gr
from .inference import analyze_message

EXAMPLES = [
    ['Hi Ahmed, our meeting is scheduled for tomorrow at 10 AM. Please bring your documents.'],
    ['Mubarak ho! Apka inaam nikla hai. Foran apni bank details bhejein.'],
    ['مبارک ہو! آپ نے انعام جیت لیا ہے۔ رقم لینے کے لیے اپنی بینک کی معلومات فراہم کریں۔'],
    ['Your bank account has been blocked, verify at http://bank-security.example/verify-login'],
]


def render(message):
    if not message or not str(message).strip():
        return '<p>Enter a message for analysis.</p>', {}
    try:
        result = analyze_message(message)
        verdict = result['verdict']
        score = result['risk_score']
        colors = {'Safe':('#106a56','#ecfaf3'), 'Suspicious':('#97600c','#fff7e8'), 'Scam':('#ad3845','#fff0f2')}
        fg,bg = colors.get(verdict,('#334155','#f1f5f9'))
        explanation = ''.join('<li>'+html.escape(x)+'</li>' for x in result.get('explanation', []))
        url_html = ''.join('<li><code>'+html.escape(x['url'])+'</code> &nbsp; '+str(x['risk_indicator'])+'/100</li>' for x in result.get('urls', []))
        terms = ''.join('<span style="display:inline-block;background:#fff1c6;border-radius:6px;padding:5px 8px;margin:3px">'+html.escape(x)+'</span>' for x in result.get('highlighted_terms', []))
        out = f'''<section style="border:1px solid #d6e5df;border-radius:14px;padding:22px;background:white">
            <div style="padding:16px 20px;border-radius:11px;background:{bg};color:{fg}">
                <strong style="font-size:26px">{html.escape(verdict)}</strong><br>
                <span>Risk indicator: <strong>{score}/100</strong></span>
            </div>
            <p><b>Language:</b> {html.escape(result['language_detected'])}</p>
            <h4>Why this result?</h4><ul>{explanation}</ul>
            <h4>Warning words</h4><p>{terms or 'No strong keyword matches'}</p>
            {('<h4>Links inspected offline</h4><ul>'+url_html+'</ul>') if url_html else ''}
            <p style="color:#677b75;font-size:12px">Development screening only. A Safe result is not proof of authenticity; indicators are not calibrated probabilities.</p>
        </section>'''
        return out,result
    except (RuntimeError,ValueError) as exc:
        return '<p>Unable to analyze. Please check input and model files.</p>', {'error':str(exc)}


def csv_cell(value):
    s=str(value)
    return "'"+s if s.lstrip().startswith(('=','+','-','@')) else s


def batch_file(filepath):
    if not filepath:
        return pd.DataFrame(), None, 'Upload a .csv file with column `message`.'
    if not str(filepath).lower().endswith('.csv') or os.path.getsize(filepath)>1_000_000:
        return pd.DataFrame(),None,'Only CSV files under 1 MB are accepted.'
    try:
        frame=pd.read_csv(filepath,dtype=str,keep_default_na=False)
        columns={str(c).lower().strip():c for c in frame.columns}
        if 'message' not in columns:raise ValueError('CSV must contain a message column.')
        messages=[str(s).strip() for s in frame[columns['message']] if str(s).strip()]
        if not 1<=len(messages)<=100:raise ValueError('CSV must contain 1-100 nonempty messages.')
        if any(len(s)>10000 for s in messages):raise ValueError('Message length must be <= 10000 characters.')
        rows=[]
        for m in messages:
            result=analyze_message(m)
            rows.append({'message':csv_cell(m),'language':result['language_detected'],
                        'verdict':result['verdict'],'risk_indicator':result['risk_score'],
                        'url_count':len(result.get('urls',[])),
                        'explanation':csv_cell(' | '.join(result['explanation']))})
        output=pd.DataFrame(rows)
        tmp=tempfile.NamedTemporaryFile(prefix='phishguard_batch_',suffix='.csv',delete=False)
        tmp.close();output.to_csv(tmp.name,index=False)
        return output,tmp.name,f'Analyzed {len(output)} messages. Download results below.'
    except (ValueError,UnicodeError,KeyError) as exc:
        return pd.DataFrame(),None,str(exc)


def build_ui():
    with gr.Blocks(title='PhishGuard-PK') as demo:
        gr.Markdown('''# 🛡️ PhishGuard-PK
**Know the risk before you click.**  English · Roman Urdu · اردو

Screen SMS, WhatsApp, email and social messages, including suspicious URLs. **Never paste passwords, OTPs or confidential information.**''')
        with gr.Tabs():
            with gr.Tab('🔎 Single message'):
                message=gr.Textbox(label='Enter message / پیغام لکھیں',lines=5,max_lines=12,placeholder='Paste a message to analyze...')
                button=gr.Button('Analyze message',variant='primary')
                result=gr.HTML(label='Analysis')
                details=gr.JSON(label='Detailed API output')
                button.click(render,inputs=message,outputs=[result,details])
                message.submit(render,inputs=message,outputs=[result,details])
                gr.Examples(examples=EXAMPLES,inputs=message)
            with gr.Tab('📂 Batch CSV'):
                gr.Markdown('Upload UTF-8 CSV with `message` column, up to 100 messages. Output contains a verdict, risk indicator and reasons for each row. No URLs are opened.')
                upload=gr.File(label='Upload message CSV',file_types=['.csv'],type='filepath')
                run=gr.Button('Analyze CSV',variant='primary')
                notice=gr.Markdown()
                table=gr.Dataframe(label='Batch results',interactive=False)
                download=gr.File(label='Download CSV results')
                run.click(batch_file,inputs=upload,outputs=[table,download,notice])
        gr.Markdown('''**Important:** Academic research build. Text labels are provisional; offline URL screening is primarily rule-based; the scores are not verified probabilities. A Safe label does **not** guarantee a message is trustworthy.''')
    return demo
