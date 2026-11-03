'use strict';
const $=(selector)=>document.querySelector(selector);
const samples={
 safe:'Hi Ahmed, our meeting is scheduled for tomorrow at 10 AM. Please bring your documents. Thank you!',
 roman:'Mubarak ho! Apka 50000 rupay ka inaam nikla hai. Inaam lene ke liye apni bank details bhejein.',
 urdu:'مبارک ہو! آپ نے پچاس ہزار روپے کا انعام جیت لیا ہے۔ انعام حاصل کرنے کے لیے اپنی بینک کی معلومات فراہم کریں۔',
 link:'Dear customer, your bank account is blocked. Verify immediately at http://bank-security.example/verify-login'
};
let last=null;let batch=[];let lastAnalyzedMessage="";let requestSequence=0;
const EXPECTED_ENGINE='step59-intent-hybrid-v1';
const EXPECTED_DEEP_AI='step61-openrouter-free-hybrid-v1';
function text(el,value){el.textContent=value;}
function dom(tag,cls,value){const e=document.createElement(tag);if(cls)e.className=cls;if(value!==undefined)text(e,String(value));return e;}
function clearChildren(el){while(el.firstChild)el.removeChild(el.firstChild)}
// Check the actual BACKEND release. Static frontend changes alone are not proof
// that Vercel is running the new inference engine.
(async()=>{
  const node=$('#engine-tag');
  if(!node)return;
  try{
    const response=await fetch('/health',{cache:'no-store'});
    const data=response.ok?await response.json():{};
    if(data.release_id===EXPECTED_ENGINE && data.intent_ai_available){
      text(node, data.deep_ai_release_id===EXPECTED_DEEP_AI ? 'Step 61 · Deep AI ready' : 'Intent AI active · Step 59');
    }else{
      text(node,'Old backend detected · update pending');
      node.closest('.tag')?.setAttribute('title','The live server has not deployed the Step 59 intent engine.');
    }
    const optin=$('#deep-ai-optin');
    if(data.deep_ai_release_id===EXPECTED_DEEP_AI && data.deep_ai_configured===true){
      optin.disabled=false;
    }else if(data.deep_ai_release_id===EXPECTED_DEEP_AI){
      optin.title='Deep AI not configured by site owner';
    }else{
      optin.title='Deep AI not available on this backend';
    }
  }catch{text(node,'Engine version unavailable');}
})();
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
 const deepPanel=$('#deep-ai-result');clearChildren(deepPanel);deepPanel.hidden=true;
 if(result.deep_ai){
   deepPanel.hidden=false;
   const ai=result.deep_ai;
   if(ai.status==='complete'){
     deepPanel.appendChild(dom('strong','',`${ai.external_provider||'External AI'} (${ai.model||'open model'}) second opinion: ${ai.remote_verdict} · ${ai.intent.replaceAll('_',' ')}`));
     deepPanel.appendChild(dom('p','',`Local AI: ${ai.local_verdict} · Combined result: ${result.verdict}. ${ai.reason}`));
     deepPanel.appendChild(dom('p','muted small',ai.fusion_note));
   }else{
     deepPanel.appendChild(dom('strong','', 'Deep AI unavailable, local analysis shown'));
     const provider=ai.external_provider||'External AI';
     const label=({not_configured:'Owner has not configured the external AI key',rate_limited:`${provider} free limit reached`,app_rate_limited:'Demo Deep AI allowance temporarily reached',network_unavailable:`${provider} network unavailable`,credential_error:`${provider} key rejected`,provider_error:`${provider} provider error`,invalid_provider_response:`${provider} response could not be verified`})[ai.status]||`${provider} unavailable`;
     deepPanel.appendChild(dom('p','',`${label}. External AI was not used for this result.`));
   }
 }
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
 const signals=$('#signals');clearChildren(signals);[ ['Raw text-model indicator (before context)',result.text_risk_indicator], ['Highest URL risk',result.url_risk_indicator===null?'N/A':result.url_risk_indicator], ['Safety rule minimum',result.safety_rule_floor], ['Credential-sharing context',result.credential_request_detected?'Request detected':(result.security_advice_guard_applied?'Protective advice': 'Not established')], ['AI message intent',({protect:'Safety advice',request:'Credential request',mixed:'Mixed warning + request',other:'Other or uncertain',unavailable:'Model unavailable'})[result.intent_ai?.label]||'Legacy engine'], ['Backend release',result.engine_release||'OLD BACKEND / NOT UPDATED'] ].forEach(([a,b])=>signals.appendChild(dom('div','',`${a}: ${b}`)));
 displayOfficialReference(result.official_contact_reference);
}
// Only a small fixed registry of official publisher/bank pages is checked.
// Never navigate to URLs or numbers supplied inside a suspicious message.
function displayOfficialReference(info){
 const panel=$('#official-contact-evidence');clearChildren(panel);
 const useful=info && (info.contact_numbers_found || info.unrecognised_url_hosts || info.official_domain_link_matches);
 panel.hidden=!useful;
 if(!useful)return;
 panel.appendChild(dom('strong','',`${info.organization}: official contact reference`));
 const labels={
  number_not_in_limited_reference:'The number is not in our limited reference list. This is NOT proof it is fake.',
  unrecognised_claimed_link:'The supplied link is not on the listed official domain. Do not open it from the message.',
  number_in_official_reference_not_sender_verified:'The number matches a published reference. This does NOT authenticate the message sender.',
  official_domain_match_sender_not_verified:'The link uses a listed official domain, but the sender is NOT authenticated.',
  no_contact_reference_to_compare:'No contact details to compare.'
 };
 panel.appendChild(dom('p','',labels[info.status]||'Contact and sender identity not authenticated.'));
 const source=dom('a','','Check official source');
 source.href=info.official_source_url;source.target='_blank';source.rel='noopener noreferrer';
 panel.appendChild(source);
 const status=dom('p','official-online-status','');status.id='official-online-status';panel.appendChild(status);
}
async function crosscheckOfficialSource(message, info, sequence){
 if(!info || !(info.contact_numbers_found||info.unrecognised_url_hosts||info.official_domain_link_matches))return;
 const status=$('#official-online-status');if(!status)return;
 text(status,'Checking published official page...');
 try{
  const check=await post('/verify/contact',{message});
  if(sequence!==requestSequence || !status.isConnected)return;
  const labels={
   number_appears_on_checked_page:'Number appears on the checked official page. Sender still unverified.',
   number_not_found_on_this_page_INCONCLUSIVE:'Number not found on this official page. This is NOT proof of fraud.',
   no_phone_to_crosscheck:'No phone number to cross-check; compare the domain with the official website.',
   official_page_unavailable:'Official page could not be checked live.',
   official_page_too_large:'Official source was too large for the limited checker.',
   official_page_not_html:'Official source could not be text-checked.',
   source_not_allowlisted:'Official source could not be safely checked.'
  };
  text(status,labels[check.online_status]||'No conclusive online contact verification available.');
 }catch{
  if(sequence===requestSequence && status.isConnected)text(status,'Official-page check unavailable; verify independently.');
 }
}
$('#check').onclick=async()=>{
 hideError();const m=$('#message').value.trim();
 if(!m){showError('Please enter a message to check.');return}
 const myRequest=++requestSequence;const btn=$('#check');
 btn.disabled=true;text(btn,'Analyzing...');
 try{
   const useDeep=$('#deep-ai-optin').checked && !$('#deep-ai-optin').disabled;
   if(useDeep && m.length>2000)throw new Error('Deep AI accepts up to 2,000 characters. Untick Deep AI for longer messages.');
   const data=await post(useDeep?'/analyze/deep':'/analyze',useDeep?{message:m,consent_external_processing:true}:{message:m});
   // A mobile user may edit the field while this fetch is running. Never show
   // a result for old text, or allow exporting the stale message as a PDF.
   if(myRequest!==requestSequence)return;
   lastAnalyzedMessage=m;render(data);
   // The answer renders immediately; the limited official-page check is extra evidence.
   void crosscheckOfficialSource(m,data.official_contact_reference,myRequest);
   if(data.engine_release!==EXPECTED_ENGINE){
     showError('Old detection backend is still active. The Step 59 fix has NOT been deployed yet.');
   }
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
  const latest=x.latest_uploaded_dataset_status;
  if(latest && latest.urlphish_records_after_dedup){
    target.appendChild(dom('p','', `New research audit: ${latest.urlphish_records_after_dedup.toLocaleString()} URL-Phish records and ${latest.sms1000_research_records} SMS candidates reviewed. Experimental URL ML stayed OFF after ${latest.urlphish_constructed_deeplink_warnings}/${latest.urlphish_constructed_deeplink_probes} constructed deep-link warnings. No independently verified Urdu-script holdout in the supplied SMS sheet.`));
  }
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
