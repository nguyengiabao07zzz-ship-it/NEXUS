let token, state, tab = 'overview', renderVersion=0, monitorTimer=null;
const $ = s => document.querySelector(s);
const titles = {overview:'Tổng quan',logs:'Đọc và gom log',case:'Ca thử',evidence:'Bằng chứng',run:'Lần chạy',supersede:'Loại run nhập sai',candidate:'Phiên bản rule',check:'Kiểm thử rule',redact:'Xử lý dữ liệu',lab:'Kết nối Wazuh',history:'Lịch sử AI'};
const schemas = {
 case:[['title','Tên ca thử'],['technique','Mã ATT&CK (ví dụ T1059)'],['source','Nguồn lựa chọn kỹ thuật'],['split','Tập dữ liệu','development|held_out'],['environment','Phiên bản và cấu hình lab','text'],['criteria','Điều kiện thực thi, phát hiện và cửa sổ quan sát','text']],
 evidence:[['label','Tên bằng chứng'],['origin','Nguồn dữ liệu','fixture|lab'],['role','Vai trò bằng chứng','execution|source_log|manager_log|alert'],['content','Nội dung bằng chứng (lưu cục bộ)','text']],
 supersede:[['target_id','Run nhập sai cần loại khỏi số đếm','@run'],['reason','Lý do loại; tạo run mới riêng nếu cần','text'],['by','Người ghi nhận']],
 run:[['case_id','Ca thử','@case'],['phase','Giai đoạn','baseline|tuned'],['candidate_id','Candidate (bắt buộc cho tuned)','?candidate'],['execution','Thực thi','unknown|success|failed|blocked'],['execution_evidence','Bằng chứng thực thi','?evidence'],['observation_evidence','Bằng chứng kiểm tra log / alert','?evidence'],['log_present','Có log liên quan?','unknown|yes|no'],['alert_matches','Có cảnh báo phù hợp?','unknown|yes|no'],['notes','Điều kiện quan sát và lý do kết luận','text']],
 candidate:[['title','Tên phiên bản rule'],['case_id','Ca thử nguồn','@case'],['parent_id','Phiên bản trước (nếu có)','?candidate'],['xml','Rule XML: group chứa rule','text'],['rationale','Lý do và bằng chứng liên quan','text'],['playbook','Playbook xử lý cho rule','text']],
 check:[['candidate_id','Candidate được kiểm tra','@candidate'],['step','Bước','load|logtest|replay|benign|regression'],['result','Kết quả ghi nhận thủ công','pass|fail|na'],['evidence_id','Bằng chứng','@evidence'],['notes','Người chạy, cấu hình, lệnh và giới hạn','text']]
};
function node(tag, text, parent, cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;if(parent)parent.append(n);return n;}
const connectionErrors={not_configured:'Chưa cấu hình kết nối indexer.',invalid_config:'Cấu hình indexer không hợp lệ.',credentials_missing:'Chưa nhập mật khẩu cho phiên chạy app.',ca_invalid:'Không đọc được CA đã cấu hình.',authentication_failed:'Xác thực indexer không thành công.',permission_denied:'Tài khoản chưa có quyền đọc nguồn này.',index_unavailable:'Nguồn index chưa tồn tại hoặc chưa sẵn sàng.',tls_error:'Không xác minh được chứng chỉ TLS; kiểm tra CA và tên máy trong URL.',network_error:'Không kết nối được indexer; kiểm tra VM, địa chỉ và cổng.',query_timed_out:'Truy vấn hết thời gian; chưa có kết quả đầy đủ.',partial_results:'Indexer trả thiếu shard; không dùng làm kết quả đầy đủ.',response_too_large:'Dữ liệu vượt giới hạn; giảm số event hoặc cửa sổ đọc.',invalid_response:'Dữ liệu trả về chưa đúng định dạng được hỗ trợ.',http_error:'Indexer trả lỗi HTTP.'};
Object.assign(connectionErrors,{ai_not_configured:'Chưa cấu hình OpenAI; vẫn có thể xem dữ liệu đã xử lý.',ai_invalid_config:'Cấu hình AI không hợp lệ.',ai_key_missing:'Chưa nhập API key cho phiên app này.',ai_busy:'Đang có một yêu cầu AI; chờ kết quả trước khi gửi thêm.',ai_storage_error:'Không ghi được hồ sơ phân tích tại máy; không tự gửi lại.',ai_auth_failed:'OpenAI chưa chấp nhận API key.',ai_permission_denied:'API key chưa có quyền dùng model này.',ai_rate_or_quota:'API bị giới hạn tốc độ hoặc quota; không tự thử lại.',ai_http_error:'OpenAI trả lỗi; kiểm tra model/cấu hình/quota tại tài khoản.',ai_network_error:'Chưa nhận được kết quả API; không tự gửi lại vì request có thể đã được xử lý.',ai_response_too_large:'Phản hồi AI vượt giới hạn.',ai_incomplete:'Model chưa trả kết quả hoàn chỉnh; thử chọn ít event hoặc điều chỉnh giới hạn sau khi xem chi phí.',ai_refused:'Model từ chối yêu cầu phân tích.',ai_invalid_output:'Kết quả AI sai cấu trúc hoặc dẫn event không tồn tại; không dùng làm kết luận.'});
connectionErrors.ai_tls_error='Không xác minh được chứng chỉ HTTPS tới OpenAI; kiểm tra kho CA của Python/Windows.';
Object.assign(connectionErrors,{codex_not_found:'Chưa tìm thấy Codex CLI trên PATH. Cài Codex CLI hoặc kiểm tra ứng dụng Codex đã cài cho tài khoản Windows này.',codex_login_required:'Codex CLI cần đăng nhập ChatGPT: chạy codex login, không nhập API key.',codex_status_failed:'Chưa kiểm tra được đăng nhập Codex CLI.',codex_start_failed:'Không khởi động được Codex CLI.',codex_timeout:'Codex quá thời gian chờ 180 giây; chưa biết dịch vụ đã xử lý đến đâu. Không tự gửi lại.',codex_run_failed:'Codex CLI không trả kết quả hoàn chỉnh. Kiểm tra đăng nhập, model, mạng và hạn mức Codex.',codex_unexpected_tool:'Codex trả sự kiện dùng công cụ ngoài luồng phân tích; kết quả đã bị từ chối.'});
async function api(path, data){const r=await fetch(path,{method:data?'POST':'GET',headers:{'X-Nexus-Token':token,'Content-Type':'application/json'},...(data?{body:JSON.stringify(data)}:{})});const b=await r.json();if(!r.ok)throw Error(connectionErrors[b.code]||b.error||r.status);return b;}
function notice(text){$('#notice').textContent=text;}
function download(name,data,type='application/json'){
 const url=URL.createObjectURL(new Blob([typeof data==='string'?data:JSON.stringify(data,null,2)],{type}));const link=node('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function downloadBundle(candidate){
 const response=await fetch('/api/rules/bundle/'+candidate.id,{headers:{'X-Nexus-Token':token}});
 if(!response.ok)throw Error((await response.json()).error||'Không xuất được bundle');
 const url=URL.createObjectURL(await response.blob()),link=node('a');link.href=url;link.download='NEXUS-rule-'+candidate.id+'.zip';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function showAIResult(result,parent){
 if(result.draft){
  const draft=result.draft;node('h3','Bản nháp rule — chưa kiểm thử trên Wazuh',parent);node('p',draft.title+' · '+draft.status,parent);node('p',draft.rationale,parent);node('p','Dẫn chứng: '+draft.evidence_refs.join(', '),parent);
  if(draft.xml)node('pre',draft.xml,parent);
  for(const [title,values] of [['Giả định',draft.assumptions],['Kiểm thử hoạt động bình thường',draft.benign_tests],['Giới hạn',draft.limitations]]){node('h4',title,parent);const list=node('ul',undefined,parent);for(const value of values)node('li',value,list);}
  if(draft.status==='proposed'&&result.request_id){const save=node('button','Tôi đã xem: lưu candidate development',parent);save.onclick=async()=>{save.disabled=true;try{const candidate=await api('/api/ai/save-candidate',{request_id:result.request_id,confirmed:true});node('p','Đã lưu candidate '+candidate.id+'. Chưa áp lên Wazuh.',parent);const exportButton=node('button','Tải bundle rule để kiểm thử Ubuntu lab',parent);exportButton.onclick=()=>downloadBundle(candidate).catch(e=>notice(e.message));state=await api('/api/state');}catch(e){node('p',e.message,parent);save.disabled=false;}};}
 }else{
  node('h3','Nhận định AI — cần người kiểm tra',parent);node('p',result.analysis.summary,parent);
  const labels={suspicious:'Nghi vấn',possibly_benign:'Có thể lành tính',insufficient_context:'Chưa đủ ngữ cảnh'};
  for(const finding of result.analysis.findings){const article=node('article',undefined,parent);node('h3',`${finding.title} · ${finding.severity}`,article);node('p',`Nhận định: ${labels[finding.assessment]||finding.assessment} · Dẫn chứng: ${finding.evidence_refs.join(', ')}`,article);node('p',finding.explanation,article);const list=node('ul',undefined,article);for(const check of finding.recommended_checks)node('li',check,list);}
  for(const limitation of result.analysis.limitations)node('p',limitation,parent);
 }
 node('p',`Token ghi nhận: ${JSON.stringify(result.usage)}. Nhận định chưa là ground truth; chưa thực thi hành động hoặc áp rule.`,parent);
 const exportButton=node('button','Xuất kết quả JSON nội bộ',parent);exportButton.onclick=()=>download('nexus-analysis-'+(result.request_id||'result')+'.json',result);
}
function analysisPanel(collection,parent,viewVersion){
 const panel=node('section',undefined,parent,'ai-panel');node('h2','Phân tích bằng AI',panel);
 node('p','Chọn tối đa 20 event theo vị trí bên dưới. Tạo preview chỉ xử lý tại máy; chỉ nút gửi sau khi xác nhận mới gọi dịch vụ AI đã cấu hình.',panel);
 const label=node('label','Vị trí event cần phân tích, ví dụ 1,2,3',panel),selection=node('input',undefined,label);selection.value='1';
 const purposeLabel=node('label','Mục đích',panel),purpose=node('select',undefined,purposeLabel);
 for(const [value,text] of [['triage','Phân tích và ưu tiên cảnh báo'],['rule_draft','Đề xuất rule cho ca development']]){const option=node('option',text,purpose);option.value=value;}
 const caseLabel=node('label','Ca development (chỉ dùng khi đề xuất rule)',panel),caseSelect=node('select',undefined,caseLabel);node('option','— Chọn ca development —',caseSelect).value='';
 for(const item of state.records.filter(x=>x.kind==='case'&&x.split==='development'))node('option',item.title,caseSelect).value=item.id;
 const textLabel=node('label',undefined,panel,'consent'),includeText=node('input',undefined,textLabel);includeText.type='checkbox';node('span','Thêm mô tả rule và trích đoạn log đã xử lý. Văn bản vẫn có thể chứa thông tin riêng: phải kiểm từng nội dung trong preview trước khi gửi.',textLabel);
 const status=node('p','Đang đọc cấu hình AI…',panel);let keyReady=false,refreshSend=()=>{};
 api('/api/ai/status').then(config=>{if(!panel.isConnected)return;keyReady=!!config.key_available;status.textContent=!config.configured?'Chưa cấu hình AI. Dùng --setup-codex để chọn Codex CLI hoặc --setup-ai để chọn OpenAI API.':config.provider==='codex_cli'?`Codex CLI · ${config.model} · ${keyReady?'Đã đăng nhập ChatGPT; dùng hạn mức Codex':connectionErrors[config.readiness_code]||'Chưa sẵn sàng'} · Giới hạn token API không áp dụng.`:`OpenAI API · ${config.model} · Output tối đa ${config.max_output_tokens} token · API key: ${keyReady?'đã nhập':'chưa nhập'}`;refreshSend();}).catch(e=>{status.textContent=e.message;});
 const prepare=node('button','Tạo preview dữ liệu gửi AI',panel);prepare.type='button';
 const previewArea=node('div',undefined,panel),resultArea=node('div',undefined,panel);let active=null;
 const invalidate=()=>{active=null;previewArea.replaceChildren();resultArea.replaceChildren();};
 for(const input of [selection,purpose,caseSelect,includeText])input.oninput=invalidate;
 prepare.onclick=async()=>{prepare.disabled=true;previewArea.replaceChildren();resultArea.replaceChildren();active=null;const selected=selection.value;try{
  if(!/^\s*\d+(?:\s*,\s*\d+)*\s*$/.test(selected))throw Error('Nhập các vị trí event, ngăn cách bằng dấu phẩy.');
  if(purpose.value==='rule_draft'&&!caseSelect.value)throw Error('Tạo/chọn ca development trong mục Ca thử trước khi sinh rule.');
  const options={include_text:includeText.checked,purpose:purpose.value,...(purpose.value==='rule_draft'?{case_id:caseSelect.value}:{})};
  const signature=JSON.stringify(options);
  const preview=await api('/api/ai/preview',{snapshot_id:collection.snapshot_id,event_indexes:selected.split(',').map(value=>Number(value.trim())),...options});
  if(signature!==JSON.stringify({include_text:includeText.checked,purpose:purpose.value,...(purpose.value==='rule_draft'?{case_id:caseSelect.value}:{})}))return;
  if(renderVersion!==viewVersion||!panel.isConnected||selected!==selection.value)return;
  active=preview;
  node('p',preview.notice,previewArea);node('p',`Đích: ${preview.destination??'chưa cấu hình'} · Model: ${preview.model??'chưa chọn'} · Preview hết hạn sau 15 phút.`,previewArea);
  node('p',`Trường bị chặn/cần xem: ${preview.review_flags.join(', ')||'không có cờ; vẫn cần kiểm preview'}`,previewArea);
  node('h3','Đúng nội dung request sẽ gửi (không gồm API key)',previewArea);node('pre',JSON.stringify(preview.request??preview.redacted_content,null,2),previewArea);
  const local=node('details',undefined,previewArea);node('summary','Đối chiếu E1, E2… với event nguồn — giữ tại máy',local);node('pre',JSON.stringify(preview.local_references,null,2),local);
  const isCodex=preview.provider==='codex_cli';
  const consentLabel=node('label',undefined,previewArea,'consent'),consent=node('input',undefined,consentLabel);consent.type='checkbox';node('span',isCodex?'Tôi đã kiểm preview và đồng ý gửi đúng dữ liệu này tới dịch vụ Codex qua CLI tại máy, sử dụng hạn mức tài khoản ChatGPT.':'Tôi đã kiểm preview và đồng ý gửi đúng dữ liệu này tới OpenAI, có thể phát sinh phí API.',consentLabel);
  const send=node('button','Gửi preview đã duyệt để phân tích',previewArea);send.type='button';send.disabled=true;
  const sendReason=node('p',undefined,previewArea);sendReason.setAttribute('role','status');
  refreshSend=()=>{send.disabled=!consent.checked||!preview.configured||!keyReady||consent.disabled;sendReason.textContent=!preview.configured?'Chưa thể gửi: chưa cấu hình AI.':!keyReady?'Chưa thể gửi: '+status.textContent:!consent.checked?'Kiểm tra preview và tích đồng ý để bật nút gửi.':'';};consent.onchange=refreshSend;refreshSend();
  send.onclick=async()=>{if(active!==preview||!consent.checked)return;send.disabled=true;consent.disabled=true;prepare.disabled=true;for(const input of [selection,purpose,caseSelect,includeText])input.disabled=true;send.textContent=isCodex?'Đang chờ Codex…':'Đang chờ OpenAI…';resultArea.replaceChildren();const progress=node('p',isCodex?'Đang chờ Codex CLI, tối đa khoảng 180 giây. Không bấm gửi lại.':'Đang gửi và chờ phản hồi OpenAI. Không bấm gửi lại; kết nối có thể mất khoảng 45 giây hoặc lâu hơn.',resultArea);progress.setAttribute('role','status');try{
   const result=await api('/api/ai/run',{preview_id:preview.preview_id,request_sha256:preview.request_sha256,approved:true});
   if(renderVersion!==viewVersion||!panel.isConnected||active!==preview)return;
   progress.remove();send.textContent='Đã nhận kết quả';showAIResult(result,resultArea);
   notice('Đã nhận phân tích AI. Đây là nhận định model, chưa phải kết luận đã được xác minh.');
  }catch(e){if(panel.isConnected){const message=e.message+' Muốn gửi lại cần tạo và kiểm preview mới.';progress.textContent=message;progress.setAttribute('role','alert');send.textContent='Yêu cầu không có kết quả — xem lỗi bên dưới';notice(message);}}finally{prepare.disabled=false;for(const input of [selection,purpose,caseSelect,includeText])input.disabled=false;}};
  notice('Preview mới chỉ ở máy; kiểm nội dung trước khi đồng ý gửi.');
 }catch(e){if(panel.isConnected)notice(e.message);}finally{prepare.disabled=false;}};
 return {select(indexes){if(selection.disabled)return;selection.value=indexes.slice(0,20).join(',');invalidate();selection.scrollIntoView({block:'center',behavior:'smooth'});}};
}
async function reload(){state=await api('/api/state');render();}
function collectionPanel(result,records,viewVersion){
 records.replaceChildren();
 node('p',`Đã đọc ${result.returned}/${result.total_matching} event phù hợp${result.truncated?' — chỉ một phần theo giới hạn; có thể bỏ sót event khác':''}.`,records);
 node('p',`Cửa sổ: ${result.window.gte} → ${result.window.lt}`,records);
 if(!result.returned){node('p','Không có event phù hợp trong cửa sổ. Không đồng nghĩa không có tấn công hoặc không có log.',records);return;}
 const controls=node('section',undefined,records,'filters'),searchLabel=node('label','Tìm trong dữ liệu tại máy',controls),search=node('input',undefined,searchLabel),levelLabel=node('label','Mức Wazuh tối thiểu (chưa là kết luận AI)',controls),minimum=node('select',undefined,levelLabel);
 for(const [value,text] of [['0','Tất cả'],['3','Từ level 3'],['7','Từ level 7'],['10','Từ level 10'],['12','Từ level 12']])node('option',text,minimum).value=value;
 const ai=analysisPanel(result,records,viewVersion),summary=node('p',undefined,records),groupsArea=node('div',undefined,records);
 const paint=()=>{
  groupsArea.replaceChildren();const groups=new Map();let shown=0;
  result.documents.forEach((document,index)=>{const event=document.event,level=Number(event.rule?.level)||0;
   if(level<Number(minimum.value)||!JSON.stringify(event).toLowerCase().includes(search.value.toLowerCase()))return;shown++;
   const agent=String(event.agent?.id??'unknown'),rule=String(event.rule?.id??'none'),decoder=String(event.decoder?.name??'unknown'),key=JSON.stringify([agent,rule,decoder]);
   if(!groups.has(key))groups.set(key,{agent,rule,decoder,level,indexes:[],description:String(event.rule?.description??'')});
   const group=groups.get(key);group.level=Math.max(group.level,level);group.indexes.push(index+1);
  });
  summary.textContent=`Đang hiển thị ${shown}/${result.documents.length} event của snapshot · ${groups.size} nhóm. Sắp theo level Wazuh; gom nhóm không xóa log hoặc chứng minh giảm cảnh báo giả.`;
  for(const group of [...groups.values()].sort((a,b)=>b.level-a.level)){
   const article=node('article',undefined,groupsArea);node('h3',`Level ${group.level} · Agent ${group.agent} · Rule ${group.rule} · ${group.indexes.length} event`,article);
   if(group.description)node('p',group.description,article);node('p',`Decoder: ${group.decoder} · Vị trí snapshot: ${group.indexes.join(', ')}`,article);
   const select=node('button',`Chọn ${Math.min(group.indexes.length,20)} event nhóm này cho AI`,article);select.onclick=()=>ai.select(group.indexes);
  }
 };
 search.oninput=paint;minimum.onchange=paint;paint();
 const details=node('details',undefined,records);node('summary','Xem event gốc tại máy — không tự gửi AI',details);node('pre',JSON.stringify(result.documents,null,2),details);
}
function historyPanel(content,records,viewVersion){
 node('p','Lịch sử nội bộ tại máy, gồm kết quả và lỗi. Không tự gửi lại yêu cầu. Nội dung chưa được làm sạch để công khai.',content);
 const searchLabel=node('label','Tìm theo tóm tắt / model / trạng thái',content),search=node('input',undefined,searchLabel),refresh=node('button','Đọc lại lịch sử',content);
 const load=async()=>{refresh.disabled=true;try{const history=await api('/api/ai/history');if(renderVersion!==viewVersion)return;
  const paint=()=>{records.replaceChildren();node('p',`Hiển thị tối đa 100 hồ sơ gần nhất trong ${history.total} hồ sơ đọc được.${history.unreadable?` Có ${history.unreadable} hồ sơ lỗi/không đọc được; kiểm tra bản sao lưu.`:""}`,records);
   for(const item of history.items.filter(x=>JSON.stringify(x).toLowerCase().includes(search.value.toLowerCase()))){
    const article=node('article',undefined,records);node('h3',item.summary||item.error_code||item.status,article);node('p',`${item.created} · ${item.provider} · ${item.model} · ${item.purpose} · ${item.status}`,article);
    if(item.error_code)node('p',connectionErrors[item.error_code]||item.error_code,article);
    const open=node('button','Xem kết quả và bằng chứng đối chiếu',article),body=node('div',undefined,article);
    open.onclick=async()=>{open.disabled=true;try{const detail=await api('/api/ai/history/'+item.id);body.replaceChildren();if(detail.result)showAIResult(detail.result,body);else node('p',detail.status==='pending_or_interrupted'?'Yêu cầu chưa có kết quả hoặc app đã bị ngắt. Không tự thử lại.':connectionErrors[detail.error?.code]||detail.error?.code,body);const mapping=node('details',undefined,body);node('summary','Manifest và đối chiếu tại máy',mapping);node('pre',JSON.stringify(detail.manifest,null,2),mapping);}catch(e){node('p',e.message,body);}finally{open.disabled=false;}};
   }
  };search.oninput=paint;paint();
 }catch(e){notice(e.message);}finally{refresh.disabled=false;}};refresh.onclick=load;load();
}
function render(){
 if(monitorTimer){clearInterval(monitorTimer);monitorTimer=null;}
 const viewVersion=++renderVersion;
 $('#heading').textContent=titles[tab];document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
 const content=$('#content'),records=$('#records');content.replaceChildren();records.replaceChildren();$('#list-heading').textContent=tab==='overview'?'Số đếm theo run': 'Bản ghi đã lưu';
 if(tab==='history'){historyPanel(content,records,viewVersion);return;}
 if(tab==='overview'){
  const cards=node('div',undefined,content,'cards');for(const [value,label] of [[state.records.filter(r=>r.kind==='case').length,'Ca thử'],[state.report.active_runs,'Run còn hiệu lực (mọi nguồn)'],[state.records.filter(r=>r.kind==='candidate').length,'Phiên bản rule']]){const c=node('div',undefined,cards,'card');node('strong',String(value),c);node('span',label,c);}
  node('p','Protocol đo chưa chốt: ứng dụng chỉ đếm run theo nhãn, chưa tính độ phủ kỹ thuật hoặc tỉ lệ cảnh báo giả.',content);
  node('pre',JSON.stringify(state.report,null,2),records);return;
 }
 if(tab==='logs'){
  $('#list-heading').textContent='Các nhóm event';
  node('p','Mở log JSON/JSONL trên máy để gom theo agent, rule và decoder. Giữ nguyên mọi event; số nhóm ít hơn không có nghĩa cảnh báo giả đã giảm. Chưa có phân tích AI.',content);
  const form=node('form',undefined,content);
  const sourceLabel=node('label','Nguồn file',form),source=node('select',undefined,sourceLabel);
  for(const [value,title] of [['alerts','Alerts — cảnh báo'],['archives','Archives — event đã thu']]){const o=node('option',title,source);o.value=value;}
  const originLabel=node('label','Xuất xứ do bạn khai báo',form),origin=node('select',undefined,originLabel);
  for(const [value,title] of [['fixture','Fixture — dữ liệu giả lập'],['lab','Lab — dữ liệu phòng thử nghiệm']]){const o=node('option',title,origin);o.value=value;}
  const fileLabel=node('label','Chọn file UTF-8, tối đa 1 MB (hoặc dán bên dưới)',form,'wide'),file=node('input',undefined,fileLabel);file.type='file';file.accept='.json,.jsonl,.ndjson';
  const inputLabel=node('label','Nội dung log, tối đa 500 event',form,'wide'),input=node('textarea',undefined,inputLabel);input.required=true;
  const clear=()=>{records.replaceChildren();notice('Preview trước đã xóa; bấm Đọc và gom log để xem dữ liệu đang chọn.');};
  let fileReadVersion=0;
  file.onchange=async()=>{const version=++fileReadVersion;clear();input.value='';const selected=file.files[0];if(!selected)return;if(selected.size>1000000){notice('File vượt 1 MB.');return;}try{const value=new TextDecoder('utf-8',{fatal:true}).decode(await selected.arrayBuffer());if(version===fileReadVersion)input.value=value;}catch(e){if(version===fileReadVersion)notice('Không đọc được file UTF-8.');}};
  input.oninput=()=>{fileReadVersion++;clear();};source.onchange=clear;origin.onchange=clear;
  const submit=node('button','Đọc và gom log',form);submit.type='submit';
  form.onsubmit=async e=>{e.preventDefault();records.replaceChildren();submit.disabled=true;const snapshot=[input.value,source.value,origin.value];try{
   const preview=await api('/api/logs/preview',{text:snapshot[0],source:snapshot[1],origin:snapshot[2]});
   if(renderVersion!==viewVersion||snapshot.some((value,i)=>value!==[input.value,source.value,origin.value][i]))return;
   node('p',`${preview.total_events} event · ${preview.groups.length} nhóm · ${preview.repeated_content_count} bản có nội dung lặp. Chưa lưu và chưa gửi LLM.`,records);
   for(const message of preview.limitations)node('p',message,records,'empty');
   for(const group of preview.groups){const article=node('article',undefined,records);node('h3',`Agent ${group.agent_id} · Rule ${group.rule_id??'chưa có ID'} · ${group.count} event`,article);node('p',`Decoder: ${group.decoder??'chưa có'} · Vị trí event: ${group.event_indexes.join(', ')}`,article);}
   notice('Đã đọc cục bộ. Nguồn chưa được xác minh; chưa kết luận nguy hiểm hoặc cảnh báo giả.');
  }catch(e){notice(e.message);}finally{submit.disabled=false;}};return;
 }
 if(tab==='redact'){
  node('p','Chỉ nhận JSON. Policy theo trường: định danh dùng HMAC, secret bị loại, trường lạ và command line tự do bị chặn. Preview có thể thiếu đặc trưng; cần người kiểm. Không có thao tác gửi LLM.',content);
  const f=node('form',undefined,content),l=node('label','JSON cần xử lý',f,'wide'),input=node('textarea',undefined,l);const b=node('button','Tạo preview',f);b.type='submit';const output=node('pre','',content);
  f.onsubmit=async e=>{e.preventDefault();try{output.textContent=JSON.stringify(await api('/api/redact',{text:input.value}),null,2);notice('Preview chưa được gửi ra ngoài.');}catch(e){notice(e.message);}};return;
 }
 if(tab==='lab'){
  $('#list-heading').textContent='Dữ liệu đọc từ Wazuh';
  node('p','NEXUS chạy trên máy thật và đọc dữ liệu từ Wazuh trong Ubuntu VM. Lần đọc này không sửa rule, không gửi AI và chưa tạo kết quả nghiên cứu.',content);
  const status=node('p','Đang đọc cấu hình kết nối…',content);
  api('/api/indexer/status').then(config=>{if(renderVersion!==viewVersion)return;status.textContent=config.configured?`${config.url} · ${config.username} · CA: ${config.ca_available?'đã có':'chưa có'} · Mật khẩu phiên: ${config.credential_available?'đã nhập':'chưa nhập'}. Chưa xác nhận kết nối.`:'Chưa cấu hình. Trên máy thật, chạy python run_nexus.py --setup-indexer trong thư mục dự án để nhập cấu hình và mật khẩu cục bộ.';}).catch(e=>{if(renderVersion===viewVersion)status.textContent=e.message;});
  const form=node('form',undefined,content),sourceLabel=node('label','Nguồn cần đọc',form),source=node('select',undefined,sourceLabel);
  for(const [value,title] of [['alerts','Alerts — cảnh báo'],['archives','Archives — cần được bật và index']]){const option=node('option',title,source);option.value=value;}
  const timeLabel=node('label','Khoảng thời gian gần nhất',form),minutes=node('select',undefined,timeLabel);
  for(const [value,title] of [['15','15 phút'],['60','1 giờ'],['1440','24 giờ']]){const option=node('option',title,minutes);option.value=value;}minutes.value='60';
  const limitLabel=node('label','Số event tối đa (1–500)',form),limit=node('input',undefined,limitLabel);limit.type='number';limit.min='1';limit.max='500';limit.value='100';limit.required=true;
  const agentLabel=node('label','Agent ID (để trống để đọc tất cả)',form),agent=node('input',undefined,agentLabel);agent.maxLength=128;
  const button=node('button','Đọc dữ liệu từ Wazuh',form);button.type='submit';
  for(const field of [source,minutes,limit,agent])field.oninput=()=>records.replaceChildren();
  form.onsubmit=async e=>{e.preventDefault();records.replaceChildren();button.disabled=true;const query={source:source.value,minutes:Number(minutes.value),limit:Number(limit.value),agent_id:agent.value.trim()};const signature=JSON.stringify(query);try{
   const result=await api('/api/indexer/collect',query);
   if(renderVersion!==viewVersion||signature!==JSON.stringify({source:source.value,minutes:Number(minutes.value),limit:Number(limit.value),agent_id:agent.value.trim()}))return;
   collectionPanel(result,records,viewVersion);
   notice('Đã truy vấn indexer thành công. Chưa lưu, chưa kết luận nguy hiểm/nhiễu và chưa gửi AI.');
  }catch(e){if(renderVersion===viewVersion)notice(e.message);}finally{button.disabled=false;}};
  const polling=node('section',undefined,content,'ai-panel');node('h2','Theo dõi định kỳ — chỉ đọc, không tự gọi AI',polling);
  const intervalLabel=node('label','Chu kỳ đọc',polling),interval=node('select',undefined,intervalLabel);for(const [value,text] of [['30','30 giây'],['60','1 phút'],['300','5 phút']])node('option',text,interval).value=value;interval.value='60';
  const monitorStatus=node('p','Đang kiểm tra…',polling),start=node('button','Bắt đầu đọc định kỳ theo bộ lọc trên',polling),stop=node('button','Dừng đọc định kỳ',polling),latest=node('button','Xem lượt đọc định kỳ mới nhất',polling);
  const showStatus=async()=>{try{const value=await api('/api/monitor/status');if(renderVersion!==viewVersion)return;monitorStatus.textContent=`${value.running?'Đang chạy':'Đã dừng'} · ${value.cycles} lượt thành công · ${value.new_documents} ID mới thấy trong phiên (cache tối đa 5000)${value.truncated?' · Lượt gần nhất bị cắt theo giới hạn':''}${value.error_code?' · Lỗi: '+(connectionErrors[value.error_code]||value.error_code):''}. Không tự gọi AI; tự dừng sau tối đa 8 giờ. Lượt bị giới hạn không bảo đảm lấy hết log.`;start.disabled=value.running;stop.disabled=!value.running;}catch(e){if(renderVersion===viewVersion)monitorStatus.textContent=e.message;}};
  start.onclick=async()=>{try{await api('/api/monitor/start',{query:{source:source.value,minutes:Number(minutes.value),limit:Number(limit.value),agent_id:agent.value.trim()},interval:Number(interval.value)});await showStatus();}catch(e){monitorStatus.textContent=e.message;}};
  stop.onclick=async()=>{stop.disabled=true;try{await api('/api/monitor/stop',{});await showStatus();}catch(e){monitorStatus.textContent=e.message;}};
  latest.onclick=async()=>{try{const result=await api('/api/monitor/latest');if(renderVersion===viewVersion)collectionPanel(result,records,viewVersion);}catch(e){notice(e.message);}};
  showStatus();monitorTimer=setInterval(showStatus,5000);return;
 }
 if(tab==='candidate')node('p','Mỗi lần lưu tạo phiên bản có SHA-256. XML đúng cấu trúc chưa phải logtest-pass. Bundle có helper Ubuntu lab: stage, logtest, activate và rollback; chỉ chạy khi bạn chủ động thực hiện trên lab.',content);
 if(tab==='check')node('p','Đây là kết quả do người dùng ghi nhận kèm bằng chứng; app chưa tự chạy hay xác minh kết quả này.',content);
 const form=node('form',undefined,content);
 for(const [name,title,type] of schemas[tab]){
  const label=node('label',title,form,type==='text'?'wide':undefined);let input;
  if(type?.startsWith('@')||type?.startsWith('?')){
   input=node('select',undefined,label);const empty=node('option','— Chọn —',input);empty.value='';
   for(const r of state.records.filter(r=>r.kind===type.slice(1)&&!(tab==='candidate'&&name==='case_id'&&r.split!=='development'))){const o=node('option',(r.title||r.label||r.id)+' · '+r.id.slice(0,8),input);o.value=r.id;}
  }else if(type?.includes('|')){input=node('select',undefined,label);for(const value of type.split('|')){const o=node('option',value,input);o.value=value;}}
  else input=node(type==='text'?'textarea':'input',undefined,label);
  input.name=name;input.required=!type?.startsWith('?');
 }
 node('button','Lưu bản ghi mới',form).type='submit';
 if(tab==='candidate'){
  const validate=node('button','Kiểm cấu trúc XML trước khi lưu',form);validate.type='button';const output=node('pre',undefined,content);
  validate.onclick=async()=>{try{output.textContent=JSON.stringify(await api('/api/rules/validate',{xml:new FormData(form).get('xml')}),null,2);}catch(e){output.textContent=e.message;}};
 }
 form.onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(form));if(tab==='run')for(const k of ['log_present','alert_matches'])data[k]=data[k]==='unknown'?null:data[k]==='yes';try{await api('/api/records',{kind:tab,data});notice('Đã lưu cục bộ. Bản ghi mới không thay thế bằng chứng cũ.');await reload();}catch(e){notice(e.message);}};
 const items=state.records.filter(r=>r.kind===tab).reverse();if(!items.length)node('p','Chưa có bản ghi. Dữ liệu giả lập chỉ xuất hiện nếu bạn tự nhập và chọn fixture.',records,'empty');
 for(const item of items){const a=node('article',undefined,records);node('h3',item.title||item.label||item.outcome||item.step||item.id,a);node('pre',JSON.stringify(item,null,2),a);if(tab==='candidate'){const exportButton=node('button','Tải bundle rule cho Ubuntu lab',a);exportButton.onclick=()=>downloadBundle(item).catch(e=>notice(e.message));}}
}
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;render();});
$('#export').onclick=async()=>{try{const data=await api('/api/export');const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download='nexus-private-export.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);notice('Đã xuất dữ liệu nội bộ. Cần làm sạch trước khi chia sẻ.');}catch(e){notice(e.message);}};
(async()=>{try{token=(await(await fetch('/api/session')).json()).token;await reload();notice('Dữ liệu lưu trên máy chạy NEXUS. AI chỉ gửi sau khi bạn duyệt preview; chưa có runner triển khai rule.');}catch(e){notice('Không tải được ứng dụng: '+e.message);}})();
