'use strict';
/*
  PhishGuard-PK local PDF exporter.
  Creates A4, multipage rasterized PDFs directly in the visitor's browser.
  No hosted PDF service, no API key, and no message content sent elsewhere.
  Canvas keeps Urdu/Roman Urdu letter shaping correct; report text is not selectable.
*/
(() => {
  const WIDTH=1240, HEIGHT=1754, EDGE=88, FOOTER=1652;
  const enc=new TextEncoder();
  const pages=[];
  let canvas, ctx, y;
  const palette={ink:'#123126',muted:'#637d6c',green:'#086740',border:'#dcebe1',pale:'#edf9f1',safe:'#087e52',scam:'#bd3c43',suspicious:'#a96e12'};
  const clamp=(n,a,b)=>Math.min(b,Math.max(a,Number(n)||0));
  const roundRect=(x,top,w,h,r=20)=>{
    ctx.beginPath();
    if(ctx.roundRect)ctx.roundRect(x,top,w,h,r);
    else {ctx.rect(x,top,w,h);}
  };
  function setFont(size=24,bold=false){ctx.font=`${bold?'700':'400'} ${size}px 'Arial','Noto Sans Arabic','Noto Naskh Arabic',sans-serif`;}
  function write(value,x,yy,{size=24,bold=false,color=palette.ink,align='left',rtl=false}={}){
    ctx.save();setFont(size,bold);ctx.fillStyle=color;ctx.textAlign=align;ctx.direction=rtl?'rtl':'ltr';ctx.fillText(String(value??''),x,yy);ctx.restore();
  }
  function newPage(){
    canvas=document.createElement('canvas');canvas.width=WIDTH;canvas.height=HEIGHT;
    ctx=canvas.getContext('2d',{alpha:false});ctx.fillStyle='#ffffff';ctx.fillRect(0,0,WIDTH,HEIGHT);
    ctx.fillStyle=palette.green;ctx.fillRect(0,0,WIDTH,17);
    write('PHISHGUARD',EDGE,107,{size:37,bold:true});
    write('PK',371,107,{size:26,bold:true,color:palette.green});
    write('MESSAGE & LINK ANALYSIS',WIDTH-EDGE,106,{size:17,bold:true,color:palette.muted,align:'right'});
    ctx.strokeStyle=palette.border;ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(EDGE,132);ctx.lineTo(WIDTH-EDGE,132);ctx.stroke();
    y=180;pages.push({canvas,ctx});
  }
  function ensure(height=50){if(y+height>FOOTER)newPage()}
  function heading(title){ensure(92);y+=32;write(title,EDGE,y,{size:25,bold:true});y+=23;}
  function breakLines(text,maxWidth,fontSize=24,bold=false){
    setFont(fontSize,bold);
    const output=[];
    String(text??'').split(/\r?\n/).forEach(paragraph=>{
      if(!paragraph.trim()){output.push('');return;}
      const words=paragraph.split(/\s+/);
      let line='';
      const add=(word)=>{
        if(ctx.measureText(word).width<=maxWidth)return [word];
        const parts=[];let p='';
        for(const character of Array.from(word)){
          if(p&&ctx.measureText(p+character).width>maxWidth){parts.push(p);p=character;}else p+=character;
        }
        if(p)parts.push(p);return parts;
      };
      words.forEach(word=>add(word).forEach(chunk=>{
        const next=line?line+' '+chunk:chunk;
        if(line&&ctx.measureText(next).width>maxWidth){output.push(line);line=chunk;}
        else line=next;
      }));
      if(line)output.push(line);
    });
    return output;
  }
  function paragraph(str,{size=23,bold=false,color=palette.ink,gap=8,indent=0,lineHeight=34}={}){
    const rtl=/[\u0600-\u06FF]/.test(String(str??''));
    const maxWidth=WIDTH-2*EDGE-indent;
    const lines=breakLines(str,maxWidth,size,bold);
    for(const line of lines){ensure(lineHeight+8);y+=lineHeight;
      if(line)write(line,rtl?WIDTH-EDGE:EDGE+indent,y,{size,bold,color,align:rtl?'right':'left',rtl});
    }
    y+=gap;
  }
  function sectionCard(height,color,outline){
    ensure(height+18);
    ctx.save();roundRect(EDGE,y,WIDTH-EDGE*2,height,24);ctx.fillStyle=color;ctx.fill();
    if(outline){ctx.strokeStyle=outline;ctx.lineWidth=2;ctx.stroke()}
    ctx.restore();
  }
  function preparePageFooter(){
    pages.forEach(({canvas:c,ctx:context},idx)=>{
      const prev=ctx;ctx=context;
      ctx.strokeStyle=palette.border;ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(EDGE,1698);ctx.lineTo(WIDTH-EDGE,1698);ctx.stroke();
      write('Research-stage assessment. A Safe result does not guarantee authenticity.',EDGE,1726,{size:17,color:palette.muted});
      write(`${idx+1} / ${pages.length}`,WIDTH-EDGE,1726,{size:18,bold:true,color:palette.green,align:'right'});
      ctx=prev;
    });
  }
  function decodeBase64(encoded){
    const raw=atob(encoded);const out=new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);return out;
  }
  function buildPDF(){
    const parts=[];let position=0;const offsets=[0];
    function push(part){const bytes=typeof part==='string'?enc.encode(part):part;parts.push(bytes);position+=bytes.length;}
    function object(id,content){offsets[id]=position;push(`${id} 0 obj\n`);push(content);push('\nendobj\n');}
    push('%PDF-1.4\n%PDFGEN\n');
    object(1,'<< /Type /Catalog /Pages 2 0 R >>');
    const ids=pages.map((_,i)=>5+i*3);
    object(2,`<< /Type /Pages /Kids [${ids.map(id=>id+' 0 R').join(' ')}] /Count ${pages.length} >>`);
    pages.forEach(({canvas:c},i)=>{
      const imgId=3+i*3,streamId=4+i*3,pageId=5+i*3;
      const jpg=decodeBase64(c.toDataURL('image/jpeg',.89).split(',')[1]);
      offsets[imgId]=position;
      push(`${imgId} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${WIDTH} /Height ${HEIGHT} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpg.length} >>\nstream\n`);
      push(jpg);push('\nendstream\nendobj\n');
      const cmd=`q\n595 0 0 842 0 0 cm\n/Im${i} Do\nQ\n`;
      object(streamId,`<< /Length ${enc.encode(cmd).length} >>\nstream\n${cmd}endstream`);
      object(pageId,`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /XObject << /Im${i} ${imgId} 0 R >> >> /Contents ${streamId} 0 R >>`);
    });
    const xref=position,total=2+pages.length*3;
    push(`xref\n0 ${total+1}\n0000000000 65535 f \n`);
    for(let n=1;n<=total;n++)push(`${String(offsets[n]).padStart(10,'0')} 00000 n \n`);
    push(`trailer\n<< /Size ${total+1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`);
    return new Blob(parts,{type:'application/pdf'});
  }
  async function save({result,message}){
    if(!result||!result.verdict)throw Error('No analysis result is available.');
    pages.length=0;newPage();
    write('Analysis report',EDGE,y,{size:50,bold:true});y+=44;
    paragraph('Generated locally on '+new Date().toLocaleString('en-GB'),{size:20,color:palette.muted,gap:24});
    const status=String(result.verdict);
    const statusColor=status==='Safe'?palette.safe:status==='Suspicious'?palette.suspicious:palette.scam;
    const background=status==='Safe'?'#e8f8ee':status==='Suspicious'?'#fff4dc':'#fff0f0';
    sectionCard(169,background);
    write('ASSESSMENT',EDGE+26,y+41,{size:18,color:palette.muted,bold:true});
    write(status,EDGE+25,y+104,{size:49,color:statusColor,bold:true});
    write(`${clamp(result.risk_score,0,100).toFixed(1)} / 100`,WIDTH-EDGE-26,y+105,{size:39,bold:true,align:'right',color:statusColor});
    y+=193;
    paragraph('Detected language: '+String(result.language_detected||'Not available'),{size:22,bold:true});
    heading('Submitted message');
    paragraph(message||'(No message provided)',{size:24,lineHeight:39,gap:14});
    heading('Why this result?');
    const explanations=Array.isArray(result.explanation)?result.explanation:[];
    if(!explanations.length)paragraph('No specific explanation was returned.',{color:palette.muted});
    explanations.forEach((reason,i)=>paragraph(`${i+1}. ${reason}`,{size:22,lineHeight:34,gap:6}));
    heading('Flagged words');
    paragraph((result.highlighted_terms||[]).join(', ')||'No specific warning words highlighted.',{size:22});
    heading('URLs inspected');
    const urls=Array.isArray(result.urls)?result.urls:[];
    if(!urls.length)paragraph('No URLs found in this message.',{size:22,color:palette.muted});
    urls.forEach((url,i)=>{paragraph(`${i+1}. ${url.url||''}`,{size:21,lineHeight:32,gap:2});paragraph('URL risk indicator: '+String(url.risk_indicator??'N/A')+' / 100',{size:19,color:palette.muted,gap:11});});
    heading('Model indicators');
    paragraph(`Text risk indicator: ${result.text_risk_indicator??'N/A'} / 100`,{size:21,gap:1});
    paragraph(`Highest URL risk: ${result.url_risk_indicator??'N/A'}`,{size:21,gap:1});
    paragraph(`Safety rule minimum: ${result.safety_rule_floor??'N/A'}`,{size:21,gap:11});
    heading('How to act safely');
    paragraph('Do not share OTPs, passwords or bank details. Avoid opening unknown links. Confirm urgent requests using verified official channels.',{size:21,color:palette.muted});
    heading('Research limitations');
    paragraph('This is an experimental academic classifier. Risk scores are NOT calibrated probabilities. False positives and false negatives are possible. Do not treat this report as proof that a message is safe or fraudulent.',{size:20,color:palette.muted});
    preparePageFooter();
    const blob=buildPDF();
    const url=URL.createObjectURL(blob),anchor=document.createElement('a');
    anchor.href=url;anchor.download=`PhishGuard-PK_Analysis_${new Date().toISOString().slice(0,10)}.pdf`;
    document.body.appendChild(anchor);anchor.click();anchor.remove();
    window.setTimeout(()=>URL.revokeObjectURL(url),15000);
    return {pages:pages.length,bytes:blob.size};
  }
  window.PhishGuardPDF={save};
})();
