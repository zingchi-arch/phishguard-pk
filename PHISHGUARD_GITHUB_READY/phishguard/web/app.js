'use strict';
const $=(selector)=>document.querySelector(selector);
const samples={
 safe:'Hi Ahmed, our meeting is scheduled for tomorrow at 10 AM. Please bring your documents. Thank you!',
 roman:'Mubarak ho! Apka 50000 rupay ka inaam nikla hai. Inaam lene ke liye apni bank details bhejein.',
 urdu:'مبارک ہو! آپ نے پچاس ہزار روپے کا انعام جیت لیا ہے۔ انعام حاصل کرنے کے لیے اپنی بینک کی معلومات فراہم کریں۔',
 link:'Dear customer, your bank account is blocked. Verify immediately at http://bank-security.example/verify-login'
};
let last=null;let batch=[];let lastAnalyzedMessage="";let requestSequence=0;
function text(el,value){el.textContent=value;}
function dom(tag,cls,value){const e=document.createElement(tag);if(cls)e.className=cls;if(value!==undefined)text(e,String(value));return e;}
function clearChildren(el){while(el.firstChild)el.removeChild(el.firstChild)}
function showError(msg){const e=$('#error');text(e,msg);e.hidden=false}
function hideError(){$('#error').hidden=true}
function switchTab(which){const single=which==='single';$('#single-panel').hidden=!single;$('#batch-panel').hidden=single;$('#single-tab').classList.toggle('active',single);$('#batch-tab').classList.toggle('active',!single);$('#single-tab').setAttribute('aria-selected',String(single));$('#batch-tab').setAttribute('aria-selected',String(!single));}
$('#single-tab').onclick=()=>switchTab('single');$('#batch-tab').onclick=()=>switchTab('batch');
$('#message').addEventListener('input',()=>{
 text($('#counter'),`${$('#message').value.length} / 10,000`);
 requestSequence++;last=null;lastAnalyzedMessage='';$('#result').hidden=true;
 $('#model-evidence').hidden=true;$('#explain-model').hidden=true;hideError();
});
$('#clear').onclick=()=>{$('#message').value='';$('#message').dispatchEvent(new Event('input'));$('#result').hidden=true;last=null;hideError();$('#message').focus();};
document.querySelectorAll('.example').forEach(b=>b.onclick=()=>{$('#message').value=samples[b.dataset.sample];$('#message').dispatchEvent(new Event('input'));$('#message').focus();});
async function post(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});let j;try{j=await r.json()}catch{throw new Error('Server response was not readable.')}if(!r.ok)throw new Error((typeof j.detail==='string'?j.detail:JSON.stringify(j.detail))||'Unable to analyze');return j}
function render(result){last=result;$('#result').hidden=false;
 $('#link-caution').hidden=!(result.urls && result.urls.length);
 $('#model-evidence').hidden=true;clearChildren($('#model-evidence'));
 $('#explain-model').hidden=!!result.url_only_input||lastAnalyzedMessage.length>900;const v=result.verdict;const cls=v.toLowerCase();const verdict=$('#verdict');text(verdict,v);verdict.className=`verdict ${cls}`;text($('#score'),Number(result.risk_score).toFixed(1));text($('#result-language'),`Detected language: ${result.language_detected}`);let fill=$('#meter-fill');fill.style.width=`${Math.min(100,Math.max(0,result.risk_score))}%`;fill.style.background=v==='Safe'?'#19a87c':v==='Suspicious'?'#e7a33a':'#d54a54';
 const reasons=$('#reasons');clearChildren(reasons);(result.explanation||[]).forEach(x=>reasons.appendChild(dom('li','',x)));
 const term=$('#terms');clearChildren(term);if(!result.highlighted_terms?.length)term.appendChild(dom('span','nothing','No specific warning words highlighted'));else result.highlighted_terms.forEach(x=>term.appendChild(dom('span','',x)));
 const urls=$('#urls');clearChildren(urls);text($('#url-count'),`(${result.urls?.length||0})`);if(!result.urls?.length)urls.appendChild(dom('p','muted small','No links found in this message.'));else result.urls.forEach(u=>{
  const card=dom('div','url-card');
  card.append(dom('div','url-text',u.url),
    dom('div','url-score',`Structural risk indicator: ${u.risk_indicator}/100`),
    dom('div','url-status','Not authenticated or opened. A low number is not a safety guarantee.'));
  urls.appendChild(card)
 });
 const signals=$('#signals');clearChildren(signals);[ ['Text risk',result.text_risk_indicator], ['Highest URL risk',result.url_risk_indicator===null?'N/A':result.url_risk_indicator], ['Safety rule minimum',result.safety_rule_floor] ].forEach(([a,b])=>signals.appendChild(dom('div','',`${a}: ${b}`)));
}
$('#check').onclick=async()=>{
 hideError();const m=$('#message').value.trim();
 if(!m){showError('Please enter a message to check.');return}
 const myRequest=++requestSequence;const btn=$('#check');
 btn.disabled=true;text(btn,'Analyzing...');
 try{
   const data=await post('/analyze',{message:m});
   // A mobile user may edit the field while this fetch is running. Never show
   // a result for old text, or allow exporting the stale message as a PDF.
   if(myRequest!==requestSequence)return;
   lastAnalyzedMessage=m;render(data);
   $('#result').scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){if(myRequest===requestSequence)showError(e.message)}
 finally{btn.disabled=false;btn.innerHTML='Analyze message <svg class="icon"><use href="#i-arrow"></use></svg>'}
};
$('#message').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter')$('#check').click()});

// Research-only, on-demand explanation of the TEXT model's Scam-class score.
// This is deletion sensitivity, NOT SHAP/LIME or an explanation of the full verdict.
$('#explain-model').onclick=async()=>{
 if(!last || !lastAnalyzedMessage || last.url_only_input)return;
 const original=lastAnalyzedMessage, version=requestSequence;
 const button=$('#explain-model'),panel=$('#model-evidence');
 button.disabled=true;text(button,'Analyzing words...');
 try{
   const data=await post('/analyze/explain',{message:original});
   if(version!==requestSequence||original!==lastAnalyzedMessage)return;
   clearChildren(panel);
   panel.appendChild(dom('h4','', 'Text model word sensitivity (experimental)'));
   panel.appendChild(dom('p','', 'Removing a word can change the model score. This is not a verified reason for fraud, SHAP or LIME, and does not explain URL or rule decisions.'));
   const a=data.model_attribution;
   if(a && a.method==='local_token_deletion_NOT_SHAP_OR_LIME'){
     const words=[...(a.positive_evidence||[]),...(a.negative_evidence||[])];
     if(words.length){
       const ul=dom('ul');
       words.forEach(w=>{const value=Number(w.change_in_scam_model_score_points);
         ul.appendChild(dom('li','',`${w.token}: ${value>=0?'+':''}${value.toFixed(1)} score points`));});
       panel.appendChild(ul);
     }else panel.appendChild(dom('p','', 'No large single-word changes were detected.'));
   }else panel.appendChild(dom('p','', 'This input has no text-model explanation.'));
   panel.hidden=false;
 }catch(err){
   if(version===requestSequence){clearChildren(panel);panel.appendChild(dom('p','',`Explanation unavailable: ${err.message}`));panel.hidden=false;}
 }finally{button.disabled=false;text(button,'Explain text model (experimental)');}
};
// Publisher/source-labelled research evidence only. Never display it as
// independent real-world model accuracy or as a live URL reputation service.
(async()=>{
 try{
  const r=await fetch('/research-status',{headers:{'Accept':'application/json'}});
  if(!r.ok)return;const x=await r.json();
  if(!x || x.status!=='research_diagnostics_only')return;
  const target=$('#research-results');clearChildren(target);
  const stats=dom('div','research-stats');
  const a=dom('span','', '');a.appendChild(dom('strong','',`${x.structural_openphish_warnings} / ${x.openphish_source_urls}`));a.appendChild(dom('small','', 'OpenPhish entries warned by current URL rules (provider sample)'));
  const b=dom('span','', '');b.appendChild(dom('strong','',`${x.experimental_model_tranco_warnings} / ${x.tranco_popular_domains}`));b.appendChild(dom('small','', 'Tranco homepage proxies warned by rejected experimental AI'));
  stats.append(a,b);target.appendChild(stats);
  target.appendChild(dom('p','', 'The experimental URL model is NOT deployed. Provider labels and popular domains are not independently validated safe/unsafe ground truth. Risk scores are not calibrated probabilities.'));
 }catch{ /* Static research note stays visible if status endpoint is unavailable. */ }
})();

function save(name,content,type){const b=new Blob([content],{type}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000)}
$('#export-json').onclick=()=>{if(last)save('phishguard_analysis.json',JSON.stringify(last,null,2),'application/json')};
$('#export-pdf').onclick=async()=>{
  if(!last)return;
  const btn=$('#export-pdf');
  btn.disabled=true;
  const previous=btn.innerHTML;
  btn.textContent='Preparing PDF...';
  try {
    if(!window.PhishGuardPDF)throw Error('PDF module unavailable. Please reload the page.');
    await window.PhishGuardPDF.save({result:last,message:$('#message').value});
  } catch(err) { showError('PDF export failed: '+err.message); }
  finally {btn.disabled=false;btn.innerHTML=previous;}
};
function escapeCSV(s){let x=String(s??'');if(/^[\s]*[=+@-]/.test(x))x="'"+x;return '"'+x.replaceAll('"','""')+'"'}
$('#sample-csv').onclick=()=>save('phishguard_sample_messages.csv','message\n'+Object.values(samples).map(escapeCSV).join('\n'),'text/csv');
// RFC-4180-style CSV parser handles quoted commas, escaped quotes and line breaks.
function parseCSV(raw){let rows=[],row=[],value='',quote=false;for(let i=0;i<raw.length;i++){const c=raw[i];if(c==='"'){if(quote&&raw[i+1]==='"'){value+='"';i++}else quote=!quote}else if(c===','&&!quote){row.push(value);value=''}else if((c==='\n'||c==='\r')&&!quote){if(c==='\r'&&raw[i+1]==='\n')i++;row.push(value);if(row.some(x=>x!==''))rows.push(row);row=[];value=''}else value+=c;}if(quote)throw Error('CSV has an unclosed quoted value.');row.push(value);if(row.some(x=>x!==''))rows.push(row);return rows;}
$('#batch-run').onclick=async()=>{const file=$('#csv-file').files[0],msg=$('#batch-message');$('#batch-results').hidden=true;if(!file){text(msg,'Please choose a CSV file first.');return}if(file.size>1024*1024){text(msg,'CSV is too large. Use a file smaller than 1MB.');return}const btn=$('#batch-run');btn.disabled=true;text(btn,'Analyzing...');try{let rows=parseCSV((await file.text()).replace(/^\uFEFF/,''));if(rows.length<2)throw Error('CSV must contain a header and at least one row.');const col=rows[0].findIndex(x=>x.trim().toLowerCase()==='message');if(col<0)throw Error('CSV must include a column called message.');const messages=rows.slice(1).map(r=>(r[col]||'').trim()).filter(Boolean);if(messages.length<1||messages.length>100)throw Error('Upload 1 to 100 nonempty messages.');let data=await post('/analyze/batch',{messages});batch=data.results;const tbody=$('#batch-rows');clearChildren(tbody);batch.forEach(x=>{const tr=dom('tr');const r=x.result||{};[x.row,x.message,r.language_detected||'N/A',r.verdict||'Error',r.risk_score??'',r.urls?.length??0].forEach((val,i)=>{const td=dom('td');if(i===3){td.appendChild(dom('span',`badge badge-${String(val).toLowerCase()}`,val))}else text(td,val);tr.appendChild(td)});tbody.appendChild(tr)});text($('#batch-title'),`${data.count} messages analyzed`);text(msg,'Results ready. Download the CSV to review them offline.');$('#batch-results').hidden=false;}catch(e){text(msg,`Error: ${e.message}`)}finally{btn.disabled=false;btn.innerHTML='Analyze CSV <svg class="icon"><use href="#i-arrow"></use></svg>'}};
$('#download-csv').onclick=()=>{if(!batch.length)return;const header=['row','message','language','verdict','risk_indicator','url_count','explanation'];const records=batch.map(x=>{const r=x.result||{};return[x.row,x.message,r.language_detected||'',r.verdict||'Error',r.risk_score??'',r.urls?.length||0,(r.explanation||[]).join(' | ')].map(escapeCSV).join(',')});save('phishguard_batch_results.csv',[header.join(','),...records].join('\r\n'),'text/csv;charset=utf-8')};
