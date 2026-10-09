import "./styles.css";
import { backendRequest, isTauri } from "./api.js";
import { invoke } from "@tauri-apps/api/core";
import { checkForUpdate, installUpdate } from "./updater.js";
const S={page:"processes",processes:[],rules:[],network:[],firewall:[],startup:[],settings:{},history:[],q:"",external:false,firewallNotice:"",signatureStatuses:new Map(),pendingSignatureChecks:new Map(),signatureObserver:null,signatureTimer:null,signatureRequestInFlight:false,processIcons:new Map(),attemptedProcessIcons:new Set(),pendingProcessIcons:new Map(),iconObserver:null,iconTimer:null,iconRequestInFlight:false,expandedProcessGroups:new Set(),assistantSettings:{},assistantModel:"",assistantBusy:false,assistantDraft:"",assistantError:"",settingsProviderDraft:"",settingsNotice:"",settingsNoticeError:false};
const P={processes:["Активные процессы","V.E.R.A. · EXECUTIVE PROTECTION"],network:["Network Radar","V.E.R.A. · NETWORK VISIBILITY"],firewall:["Firewall","V.E.R.A. · WINDOWS FIREWALL RULES"],startup:["Автозапуск","V.E.R.A. · STARTUP CONTROL"],blocked:["Блокировки","V.E.R.A. · RELIABILITY RULES"],assistant:["V.E.R.A. Assistant","VERIFIED EXECUTIVE & RELIABILITY ASSISTANT"],settings:["Настройки","V.E.R.A. · SYSTEM PREFERENCES"]};
const $=s=>document.querySelector(s),e=v=>String(v??"").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&gt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));
const errorText=err=>{if(err?.message)return err.message;if(typeof err==="string"&&err.trim())return err;try{let value=JSON.stringify(err);if(value&&value!=="{}")return value}catch{}return "Неизвестная ошибка IPC. Проверьте, что V.E.R.A. запущена из release-сборки."};
const signatureKey=process=>String(process.exe||"").trim().toLowerCase();
const FALLBACK_PROCESS_ICON=`data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="9" fill="#2d3558"/><path d="M9 10.5h14v11H9z" fill="#9ba9df"/><path d="M11 13h4v2h-4zm0 4h7v2h-7z" fill="#59678f"/><circle cx="20.5" cy="18" r="1.5" fill="#d7e1ff"/></svg>')}`;
const processIconKey=process=>String(process.exe||"").trim().toLowerCase();
function processIconSource(process){return S.processIcons.get(processIconKey(process))||FALLBACK_PROCESS_ICON}
function updateProcessIconElements(key,source){document.querySelectorAll("[data-process-icon]").forEach(image=>{if(image.dataset.processIcon===key)image.src=source})}
function queueProcessIconChecks(processes){for(let process of processes){let key=processIconKey(process);if(!key||S.attemptedProcessIcons.has(key)||S.pendingProcessIcons.has(key))continue;S.pendingProcessIcons.set(key,{pid:process.pid,exe:process.exe})}if(!S.pendingProcessIcons.size||S.iconRequestInFlight)return;clearTimeout(S.iconTimer);S.iconTimer=setTimeout(flushProcessIconChecks,25)}
async function flushProcessIconChecks(){if(S.iconRequestInFlight||!S.pendingProcessIcons.size)return;let batch=[...S.pendingProcessIcons.entries()].slice(0,32);batch.forEach(([key])=>S.pendingProcessIcons.delete(key));S.iconRequestInFlight=true;try{let response=await backendRequest("processes.icons",{processes:batch.map(([,process])=>process)}),received=new Map(response.data.map(process=>[processIconKey(process),process.icon||FALLBACK_PROCESS_ICON]));for(let [key] of batch){let source=received.get(key)||FALLBACK_PROCESS_ICON;S.processIcons.set(key,source);S.attemptedProcessIcons.add(key);updateProcessIconElements(key,source)}}catch{for(let [key] of batch){S.processIcons.set(key,FALLBACK_PROCESS_ICON);S.attemptedProcessIcons.add(key);updateProcessIconElements(key,FALLBACK_PROCESS_ICON)}}finally{S.iconRequestInFlight=false;if(S.pendingProcessIcons.size)queueProcessIconChecks([])}}
function observeVisibleProcessIcons(){S.iconObserver?.disconnect();if(S.page!=="processes")return;let rows=[...document.querySelectorAll("[data-process-row]")],byPid=new Map(S.processes.map(process=>[String(process.pid),process]));let queueRows=entries=>queueProcessIconChecks(entries.filter(entry=>entry.isIntersecting).map(entry=>byPid.get(entry.target.dataset.pid)).filter(Boolean));if(!rows.length)return;if(!("IntersectionObserver" in window)){queueProcessIconChecks(rows.slice(0,20).map(row=>byPid.get(row.dataset.pid)).filter(Boolean));return}S.iconObserver=new IntersectionObserver(queueRows,{root:document.querySelector(".process-feed-scroll")||document.querySelector(".table-wrap"),rootMargin:"120px 0px",threshold:.01});rows.forEach(row=>S.iconObserver.observe(row))}
function applySignatureStatuses(processes){return processes.map(process=>({...process,security_status:S.signatureStatuses.get(signatureKey(process))??process.security_status}))}
function queueSignatureChecks(processes){for(let process of processes){let key=signatureKey(process);if(process.security_status!=="unchecked"||!key||S.signatureStatuses.has(key)||S.pendingSignatureChecks.has(key))continue;S.pendingSignatureChecks.set(key,{pid:process.pid,exe:process.exe})}if(!S.pendingSignatureChecks.size||S.signatureRequestInFlight)return;clearTimeout(S.signatureTimer);S.signatureTimer=setTimeout(flushSignatureChecks,50)}
async function flushSignatureChecks(){if(S.signatureRequestInFlight||!S.pendingSignatureChecks.size)return;let processes=[...S.pendingSignatureChecks.values()];S.pendingSignatureChecks.clear();S.signatureRequestInFlight=true;try{let response=await backendRequest("processes.verify_signatures",{processes});for(let result of response.data)S.signatureStatuses.set(signatureKey(result),result.security_status);S.processes=applySignatureStatuses(S.processes);if(S.page==="processes")render()}catch{}finally{S.signatureRequestInFlight=false;if(S.pendingSignatureChecks.size)queueSignatureChecks([])}}
function observeVisibleProcesses(){S.signatureObserver?.disconnect();if(S.page!=="processes")return;let rows=[...document.querySelectorAll("[data-process-row]")],byPid=new Map(S.processes.map(process=>[String(process.pid),process]));let queueRows=entries=>queueSignatureChecks(entries.filter(entry=>entry.isIntersecting).map(entry=>byPid.get(entry.target.dataset.pid)).filter(Boolean));if(!rows.length)return;if(!("IntersectionObserver" in window)){queueSignatureChecks(rows.slice(0,20).map(row=>byPid.get(row.dataset.pid)).filter(Boolean));return}S.signatureObserver=new IntersectionObserver(queueRows,{root:document.querySelector(".process-feed-scroll")||document.querySelector(".table-wrap"),threshold:0.01});rows.forEach(row=>S.signatureObserver.observe(row))}
$("#app").innerHTML=`<main class="shell"><aside class="sidebar glass"><div class="brand"><span class="brand-mark"><span></span></span><span>V.E.R.A.</span></div><p class="brand-caption">Verified Executive &amp; Reliability Assistant</p><nav><button class="assistant-card" data-page="assistant"><span class="vera-orb"><span class="orb-ring"></span><span class="orb-core"></span></span><span><b>Спросить V.E.R.A.</b><small>Надёжный AI-помощник</small></span></button>${[["processes","▦","Процессы"],["network","◉","Network Radar"],["firewall","⛨","Firewall"],["startup","◇","Автозапуск"],["blocked","⊘","Блокировки"]].map(x=>`<button class="nav" data-page="${x[0]}"><span>${x[1]}</span> ${x[2]}</button>`).join("")}</nav><div class="sidebar-footer"><span class="pulse"></span><span id="backend">Подключение…</span></div></aside><section class="content"><header class="topbar glass"><div><p id="eye" class="eyebrow"></p><h1 id="title"></h1></div><div class="topbar-actions"><button id="go-settings" class="icon-button">⚙</button><button id="refresh" class="primary">↻ Обновить</button></div></header><div id="view" class="workspace"></div><footer>V.E.R.A. · Verified Executive &amp; Reliability Assistant</footer></section></main>`;
const empty=(t,d)=>`<div class="empty-state"><span>◌</span><h2>${e(t)}</h2><p>${e(d)}</p></div>`, table=(head,rows,cols)=>`<section class="process-card glass"><div class="table-wrap"><table><thead>${head}</thead><tbody>${rows||`<tr><td colspan="${cols}" class="empty">Нет данных</td></tr>`}</tbody></table></div></section>`;
function countryFlag(ip){
  let code=String(ip?.country_code||"").trim().toLowerCase();
  if(!/^[a-z]{2}$/.test(code))return "";
  let country=ip.country_name||ip.country_code;
  return `<span class="ip-flag-glass" title="${e(country)}"><img src="https://flagcdn.com/${code}.svg" width="40" height="28" alt="Флаг: ${e(country)}" onerror="this.closest('.ip-flag-glass')?.remove()"></span>`;
}
function process(){let a=S.processes.filter(x=>!S.q||`${x.name} ${x.exe} ${x.pid}`.toLowerCase().includes(S.q.toLowerCase())),m=S.stats||{};return `<section class="metrics"><article class="metric glass"><div><small>ВСЕГО ПРОЦЕССОВ</small><strong>${m.total_processes??a.length}</strong></div></article><article class="metric glass"><div><small>АКТИВНЫЕ ПРАВИЛА</small><strong>${m.active_rules??0}</strong></div></article><article class="metric glass"><div><small>ЗА СЕССИЮ</small><strong>${m.session_terminated??0}</strong></div></article></section><section class="process-card glass"><div class="table-toolbar"><label class="search">⌕ <input id="search" value="${e(S.q)}" placeholder="Поиск по имени, PID или пути"></label></div>${table(`<tr><th>ПРОЦЕСС</th><th>PID</th><th>CPU</th><th>ПАМЯТЬ</th><th>СТАТУС</th><th></th></tr>`,a.map(x=>`<tr data-process-row data-pid="${x.pid}"><td><b>${e(x.name)}</b><small>${e(x.exe||"Путь недоступен")}</small></td><td>${x.pid}</td><td>${Number(x.cpu_percent).toFixed(1)}%</td><td>${Number(x.memory_mb).toFixed(0)} MB</td><td><span class="badge ${x.is_blocked?"blocked":x.security_status==="verified"?"verified":"neutral"}">${x.is_blocked?"Блокируется":x.security_status==="verified"?"Проверен":x.exe?"Проверка…":"Недоступно"}</span></td><td><button class="row-action" data-rule="${e(x.name)}" data-exe="${e(x.exe)}" data-blocked="${x.is_blocked}">${x.is_blocked?"Снять":"Блокировать"}</button><button class="row-action" data-kill="${x.pid}" data-name="${e(x.name)}" data-exe="${e(x.exe)}">Завершить</button><button class="row-action" data-ai="${e(x.name)}" data-exe="${e(x.exe)}" data-security="${x.security_status}">AI</button></td></tr>`).join(""),6)}</section>`}
function network(){let a=S.network.filter(x=>(!S.external||x.address_type==="public")&&(!S.q||`${x.process_name} ${x.pid} ${x.remote_address}`.toLowerCase().includes(S.q.toLowerCase()))),ip=S.ip||{};return `<section class="process-card glass"><div class="secondary-head network-summary"><div class="external-ip">${countryFlag(ip)}<div><small>ВНЕШНИЙ IP</small><h2>${e(ip.ip||"Недоступен")}</h2><p>${e(ip.error||[ip.city,ip.country_name,ip.provider,ip.asn].filter(Boolean).join(" · "))}</p></div></div><button id="ip" class="row-action">Обновить IP</button></div><div class="table-toolbar"><label class="search">⌕ <input id="search" value="${e(S.q)}" placeholder="Процесс, PID или адрес"></label><label><input id="external" type="checkbox" ${S.external?"checked":""}> Только внешние</label></div>${table(`<tr><th>ПРОЦЕСС</th><th>PID</th><th>LOCAL</th><th>REMOTE</th><th>СТАТУС</th><th>РИСК</th><th></th></tr>`,a.map(x=>`<tr><td><b>${e(x.process_name)}</b><small>${e(x.process_path)}</small></td><td>${x.pid}</td><td>${e(x.local_address)}:${x.local_port??""}</td><td>${e(x.remote_address||"—")}:${x.remote_port??""}</td><td>${e(x.status)}</td><td>${e(x.risk)}</td><td>${x.process_path?`<button class="row-action" data-open="${e(x.process_path)}">Открыть</button>`:""}</td></tr>`).join(""),7)}</section>`}
function firewall(){return `<section class="process-card glass firewall-layout"><div class="secondary-head"><div><small>WINDOWS FIREWALL</small><h2>Правила V.E.R.A.</h2><p>Изменения требуют запуска от имени администратора. Управляются только правила V.E.R.A.</p></div></div>${S.firewallNotice?`<p class="firewall-notice">${e(S.firewallNotice)}</p>`:""}<form id="firewall-form" class="firewall-form"><label>Название<input name="label" maxlength="80" required placeholder="Блокировать браузер"></label><label>Путь к .exe<input name="program" required placeholder="C:\\Program Files\\App\\app.exe"></label><label>Действие<select name="action"><option value="block">Блокировать</option><option value="allow">Разрешить</option></select></label><label>Направление<select name="direction"><option value="outbound">Исходящее</option><option value="inbound">Входящее</option></select></label><label>Протокол<select name="protocol"><option value="any">Любой</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>Порты<input name="local_port" placeholder="any или 443, 80-90"></label><label>Удалённые IP<input name="remote_ip" placeholder="any или 8.8.8.8"></label><label>Профиль<select name="profile"><option value="any">Все</option><option value="private">Частная сеть</option><option value="public">Общедоступная сеть</option><option value="domain">Домен</option></select></label><button class="primary">Создать правило</button></form>${table(`<tr><th>ПРАВИЛО</th><th>ПРОГРАММА</th><th>НАПРАВЛЕНИЕ</th><th>ДЕЙСТВИЕ</th><th>СЕТЬ</th><th>СТАТУС</th><th></th></tr>`,S.firewall.map(r=>`<tr><td><b>${e(r.label)}</b><small>${e(r.protocol.toUpperCase())} · порт: ${e(r.local_port)} · IP: ${e(r.remote_ip)}</small></td><td><small>${e(r.program)}</small></td><td>${r.direction==="outbound"?"Исходящее":"Входящее"}</td><td><span class="badge ${r.action==="block"?"blocked":"verified"}">${r.action==="block"?"Блок":"Разрешить"}</span></td><td>${e(r.profile)}</td><td><span class="badge ${r.enabled?"verified":"neutral"}">${r.enabled?"Активно":"Выключено"}</span></td><td><button class="row-action" data-firewall-toggle="${e(r.id)}">${r.enabled?"Выключить":"Включить"}</button><button class="row-action" data-firewall-delete="${e(r.id)}">Удалить</button></td></tr>`).join(""),7)}</section>`}
function blocked(){return `<section class="process-card glass"><div class="secondary-head"><div><small>ПРАВИЛА</small><h2>Блокировки процессов</h2></div></div><div class="rule-list">${S.rules.map(r=>`<article class="rule-row"><div><b>${e(r.name)}</b><small>${e(r.exe_path||"Для любого пути")} · ${e(r.mode)} · завершено: ${r.kill_count}</small></div><span class="badge ${r.enabled?"verified":"neutral"}">${r.enabled?"Активно":"Отключено"}</span><button class="row-action" data-toggle="${e(r.name)}" data-exe="${e(r.exe_path)}">${r.enabled?"Выключить":"Включить"}</button><button class="row-action" data-delete="${e(r.name)}" data-exe="${e(r.exe_path)}">Удалить</button></article>`).join("")||empty("Правил пока нет","Добавьте правило на экране процессов.")}</div></section>`}
function startup(){return table(`<tr><th>НАЗВАНИЕ</th><th>ИСТОЧНИК</th><th>ПУТЬ</th><th>СТАТУС</th><th></th></tr>`,S.startup.map(x=>`<tr><td><b>${e(x.name)}</b></td><td>${e(x.source)}${x.needs_admin?" · admin":""}</td><td><small title="${e(x.target_path)}">${e(x.target_path)}</small></td><td><span class="badge ${x.status==="active"?"verified":"neutral"}">${x.status==="active"?"Активно":"Приостановлено"}</span></td><td><button class="row-action" title="${x.needs_admin?"Требуются права администратора":""}" data-startup="${encodeURIComponent(JSON.stringify(x))}" ${x.needs_admin?"disabled":""}>${x.status==="active"?"Приостановить":"Включить"}</button></td></tr>`).join(""),5)}
function assistantModelLabel(){let config=S.assistantSettings||{};return S.assistantModel||(config.provider==="groq"?"llama-3.3-70b-versatile":config.gemini_model||"Gemini")}
function assistantMessage(message){let isUser=message.role==="user",label=isUser?"Вы":"V.E.R.A.",copy=encodeURIComponent(message.text);return `<article class="chat-message ${isUser?"user":"assistant"}"><div class="chat-message-meta"><b>${label}</b><button type="button" class="chat-copy" data-copy="${copy}" title="Копировать сообщение">Копировать</button></div><p>${e(message.text)}</p></article>`}
function assistant(){let hasMessages=S.history.length>0;return `<section class="assistant-chat glass"><header class="assistant-chat-header"><div><small>AI ASSISTANT · ${e(assistantModelLabel())}</small><h2>Диалог с V.E.R.A.</h2><p>Помощник объясняет процессы и предлагает безопасные следующие шаги.</p></div><div class="assistant-chat-status ${S.assistantBusy?"thinking":""}"><span></span>${S.assistantBusy?"V.E.R.A. думает…":"Готова к вопросу"}</div><button id="new-chat" type="button" class="row-action" ${S.assistantBusy?"disabled":""}>Новый чат</button></header><div class="chat" id="chat-log" aria-live="polite">${hasMessages?S.history.map(assistantMessage).join(""):`<section class="chat-welcome"><div class="chat-welcome-mark" aria-hidden="true">✦</div><h3>Привет! Я V.E.R.A.</h3><p>Помогу понять, что делает процесс, оценить риск и выбрать безопасное действие.</p><div class="chat-suggestions"><button type="button" data-chat-prompt="Как проверить, безопасен ли процесс в Windows?">Как проверить процесс?</button><button type="button" data-chat-prompt="Какие признаки у подозрительного процесса?">Признаки угрозы</button><button type="button" data-chat-prompt="Как безопасно отключить программу из автозапуска?">Управление автозапуском</button></div></section>`}${S.assistantBusy?`<article class="chat-message assistant chat-loading"><div class="chat-message-meta"><b>V.E.R.A.</b></div><p><span></span><span></span><span></span> Анализирую вопрос…</p></article>`:""}</div>${S.assistantError?`<p class="chat-error" role="alert">${e(S.assistantError)}</p>`:""}<form id="assistant-chat-form" class="chat-composer"><textarea id="chat-input" rows="1" maxlength="6000" placeholder="Спросите V.E.R.A. о процессе или безопасности…" ${S.assistantBusy?"disabled":""}>${e(S.assistantDraft)}</textarea><button type="submit" class="primary" ${S.assistantBusy?"disabled":""}>${S.assistantBusy?"Думаю…":"Отправить"}</button><small>Enter — отправить · Shift + Enter — новая строка</small></form></section>`}
function settings(){let x=S.settings,provider=S.settingsProviderDraft||x.provider||"gemini",isGroq=provider==="groq",keyField=(name,label,help)=>`<div class="setting-control secret-control"><input id="${name}" name="${name}" type="password" autocomplete="off" placeholder="Сохранённый ключ не отображается"><button type="button" class="icon-button key-visibility" data-key-toggle="${name}" aria-label="Показать или скрыть ключ">◉</button><small>${help}</small></div>`,toggle=(name,checked)=>`<label class="switch"><input name="${name}" type="checkbox" ${checked?"checked":""}><span aria-hidden="true"></span></label>`,row=(title,description,control)=>`<div class="setting-row"><div><h3>${title}</h3><p>${description}</p></div>${control}</div>`;return `<section class="settings-page"><form id="settings-form"><header class="settings-intro glass"><div><p class="eyebrow">V.E.R.A. · SYSTEM PREFERENCES</p><h2>Настройки</h2><p>Управляйте запуском, защитой и AI-помощником в одном месте.</p></div><button class="primary" type="submit">Сохранить изменения</button></header>${S.settingsNotice?`<p class="settings-notice ${S.settingsNoticeError?"error":""}" role="status">${e(S.settingsNotice)}</p>`:""}<div class="settings-grid"><section class="settings-section glass"><header><span>01</span><div><h2>Запуск и работа в фоне</h2><p>Как V.E.R.A. ведёт себя после входа в Windows и закрытия окна.</p></div></header>${row("Автозапуск с Windows","Запускает V.E.R.A. при входе в систему.",toggle("autostart",x.autostart))}${row("Сворачивать в трей","При закрытии окна приложение останется в системном трее.",toggle("minimize_to_tray",x.minimize_to_tray))}</section><section class="settings-section glass"><header><span>02</span><div><h2>Мониторинг процессов</h2><p>Настройте постоянную проверку и сообщения о важных действиях.</p></div></header>${row("Мониторинг и защита","Регулярно проверять процессы и применять созданные правила.",toggle("monitoring_enabled",x.monitoring_enabled))}${row("Интервал проверки","Как часто сканировать запущенные процессы.",`<label class="interval-control"><input name="scan_interval_sec" type="number" min="1" max="60" value="${x.scan_interval_sec||5}"><span>сек</span></label>`)}${row("Уведомления","Показывать системное уведомление при завершении процесса.",toggle("show_notifications",x.show_notifications))}</section><section class="settings-section settings-ai glass"><header><span>03</span><div><h2>AI-помощник</h2><p>Ключи защищаются Windows DPAPI и не отображаются после сохранения.</p></div></header>${row("AI-провайдер","Выберите модель для диалогов и описаний процессов.",`<label class="setting-control"><select id="settings-provider" name="provider"><option value="gemini" ${!isGroq?"selected":""}>Google Gemini</option><option value="groq" ${isGroq?"selected":""}>Groq · Llama 3.3 70B</option></select><small>${isGroq?"Быстрая модель Llama через Groq.":"Gemini Flash — рекомендуемый вариант."}</small></label>`)}${isGroq?row("Groq API-ключ","Нужен для обращений к Llama через Groq.",keyField("groq_api_key","Groq API-ключ","Создайте ключ в console.groq.com.")):`${row("Модель Gemini","Можно указать доступную Gemini-модель.",`<label class="setting-control"><input name="gemini_model" value="${e(x.gemini_model||"gemini-3.1-flash-preview")}" placeholder="gemini-3.1-flash-preview"><small>Используется для чата и описаний процессов.</small></label>`)}${row("Gemini API-ключ","Нужен для работы чата через Google AI Studio.",keyField("gemini_api_key","Gemini API-ключ","Получите ключ на aistudio.google.com/apikey."))}`}</section><section class="settings-section settings-about glass"><header><span>04</span><div><h2>О приложении</h2><p>Локальный помощник для контроля процессов Windows.</p></div></header><div class="about-details"><strong>V.E.R.A.</strong><span>Версия 0.4.1</span><p>Мониторинг, правила блокировки, сетевой обзор и AI-чат.</p></div></section></div><footer class="settings-footer"><button class="primary" type="submit">Сохранить изменения</button><span>Изменения применяются сразу после сохранения.</span></footer></form></section>`}
function render(){S.signatureObserver?.disconnect();let [t,x]=P[S.page];$("#title").textContent=t;$("#eye").textContent=x;$("#view").innerHTML=({processes:process,network,firewall,blocked,startup,assistant,settings})[S.page]();document.querySelectorAll("[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===S.page));observeVisibleProcesses()}
async function load(){try{if(S.page==="processes"){let snapshot=(await backendRequest("processes.snapshot")).data;S.processes=applySignatureStatuses(snapshot.processes);S.stats=snapshot.statistics}if(S.page==="network"){let ipRequest=backendRequest("network.public_ip").catch(err=>({data:{error:errorText(err)}}));S.network=(await backendRequest("network.list")).data;render();S.ip=(await ipRequest).data}if(S.page==="firewall")S.firewall=(await backendRequest("firewall.list")).data;if(S.page==="blocked")S.rules=(await backendRequest("rules.list")).data;if(S.page==="startup")S.startup=(await backendRequest("startup.list")).data;if(S.page==="settings")S.settings=(await backendRequest("settings.get")).data;$("#backend").textContent=isTauri()?"Backend подключён":"Browser preview"}catch(err){$("#backend").textContent="Backend недоступен";$("#view").innerHTML=empty(S.page==="network"?"Ошибка Network Radar":"Ошибка",errorText(err));return}render();if(S.page==="network"){clearInterval(S.networkTimer);S.networkTimer=setInterval(()=>load(),5000)}};async function go(page){clearInterval(S.networkTimer);S.page=page;S.q="";S.firewallNotice="";render();await load()}
document.addEventListener("click",async ev=>{let page=ev.target.closest("[data-page]")?.dataset.page;if(page)return go(page);if(ev.target.id==="go-settings")return go("settings");if(ev.target.id==="refresh"||ev.target.id==="ip")return load();let b=ev.target.closest("[data-rule]");if(b){await backendRequest(b.dataset.blocked==="true"?"rules.delete":"rules.upsert",{name:b.dataset.rule,exe_path:b.dataset.exe});return load()}b=ev.target.closest("[data-kill]");if(b){await backendRequest("process.terminate",{pid:Number(b.dataset.kill),name:b.dataset.name,exe_path:b.dataset.exe});return load()}b=ev.target.closest("[data-toggle]");if(b){await backendRequest("rules.toggle",{name:b.dataset.toggle,exe_path:b.dataset.exe});return load()}b=ev.target.closest("[data-delete]");if(b){await backendRequest("rules.delete",{name:b.dataset.delete,exe_path:b.dataset.exe});return load()}b=ev.target.closest("[data-firewall-toggle]");if(b){if(!window.confirm("Изменить состояние правила Windows Firewall?"))return;await backendRequest("firewall.toggle",{id:b.dataset.firewallToggle});return load()}b=ev.target.closest("[data-firewall-delete]");if(b){if(!window.confirm("Удалить это правило V.E.R.A. из Windows Firewall?"))return;await backendRequest("firewall.delete",{id:b.dataset.firewallDelete});return load()}b=ev.target.closest("[data-startup]");if(b){await backendRequest("startup.toggle",{item:JSON.parse(decodeURIComponent(b.dataset.startup))});return load()}b=ev.target.closest("[data-open]");if(b&&isTauri())return invoke("open_process_location",{path:b.dataset.open});b=ev.target.closest("[data-ai]");if(b){let oldText=b.textContent;b.disabled=true;b.textContent="Запрашиваю…";try{let r=await backendRequest("process.describe",{name:b.dataset.ai,exe_path:b.dataset.exe,security_status:b.dataset.security,force:b.dataset.aiForce==="true"});S.processes=S.processes.map(p=>p.name===b.dataset.ai&&p.exe===b.dataset.exe?{...p,description:r.data.description,description_status:r.data.status}:p);render()}catch(err){b.disabled=false;b.textContent=oldText;window.alert(`Не удалось получить описание: ${errorText(err)}`)}return}if(ev.target.id==="new"){S.history=[];return render()}b=ev.target.closest("[data-copy]");if(b)return navigator.clipboard.writeText(decodeURIComponent(b.dataset.copy));if(ev.target.id==="send"){let input=$("#chat-input"),message=input.value.trim();if(!message)return;S.history.push({role:"user",text:message});render();try{let r=await backendRequest("assistant.chat",{history:S.history.slice(0,-1),message});S.history.push({role:"model",text:r.data.text})}catch(err){S.history.push({role:"model",text:`Ошибка: ${err.message}`})}render()}});
document.addEventListener("input",ev=>{if(ev.target.id==="search"){S.q=ev.target.value;S.processVisibleCount=24;render();document.querySelector(".process-feed-scroll")?.scrollTo(0,0)}if(ev.target.id==="external"){S.external=ev.target.checked;render()}});document.addEventListener("submit",async ev=>{if(ev.target.id==="firewall-form"){ev.preventDefault();if(!window.confirm("Создать правило Windows Firewall с указанными ограничениями?"))return;try{let values=Object.fromEntries(new FormData(ev.target));await backendRequest("firewall.create",{values});S.firewallNotice="Правило создано.";await load()}catch(err){S.firewallNotice=`Ошибка: ${err.message}`;render()}return}if(ev.target.id!=="form")return;ev.preventDefault();let f=new FormData(ev.target),v=Object.fromEntries(f);["monitoring_enabled","autostart","minimize_to_tray","show_notifications"].forEach(k=>v[k]=f.has(k));v.scan_interval_sec=Number(v.scan_interval_sec);let saved=(await backendRequest("settings.set",{values:v})).data;if(isTauri())await invoke("monitor_configure",{enabled:saved.monitoring_enabled,intervalSeconds:saved.scan_interval_sec});await backendRequest("app_autostart.set",{enabled:saved.autostart});S.settings=saved;render()});

// Two policies existed in the legacy client.  Keep their controls and lists
// separate so a startup-only rule is never silently converted to a permanent one.
P.kill_on_launch=["Kill-on-Launch","V.E.R.A. · STARTUP-ONLY PROCESS BLOCKS"];
document.querySelector("nav").insertAdjacentHTML("beforeend",'<button class="nav" data-page="kill_on_launch"><span>◎</span> Kill-on-Launch</button>');
P.heart=["Сердце","V.E.R.A. · AUTONOMOUS REASONING CORE"];
document.querySelector(".assistant-card").insertAdjacentHTML("afterend",'<button class="nav heart-nav" data-page="heart"><span class="heart-nav-icon" aria-hidden="true"><i></i></span><span class="heart-nav-label">Сердце<small>CONCEPT</small></span></button>');
Object.assign(S,{processSort:"name",processSortDirection:"asc",processVisibleCount:24,processLoadObserver:null,heartPreview:false});

const PROCESS_PAGE_SIZE=24;
const processSortLabels={name:"По имени",cpu_percent:"По нагрузке CPU",memory_mb:"По памяти",pid:"По PID",attention:"По уровню внимания"};

function processAttention(process){
  if(process.is_blocked||process.description_status==="dangerous")return 3;
  if(!process.exe||process.security_status==="unknown")return 2;
  if(process.security_status==="verified")return 0;
  return 1;
}

function processGroupKey(process){return `${String(process.name||"").toLowerCase()}\u0000${String(process.exe||"").toLowerCase()}`}
function groupedProcesses(){
  let groups=new Map();
  for(let process of S.processes){let key=processGroupKey(process);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(process)}
  return [...groups.entries()].map(([key,processes])=>{
    let representative=[...processes].sort((a,b)=>Number(b.memory_mb||0)-Number(a.memory_mb||0))[0];
    let allVerified=processes.every(process=>process.security_status==="verified");
    let securityStatus=allVerified?"verified":processes.some(process=>process.security_status==="unknown")?"unknown":"unchecked";
    return {...representative,key,processes,count:processes.length,cpu_percent:processes.reduce((total,process)=>total+Number(process.cpu_percent||0),0),memory_mb:processes.reduce((total,process)=>total+Number(process.memory_mb||0),0),is_blocked:processes.some(process=>process.is_blocked),security_status:securityStatus,description_status:processes.some(process=>process.description_status==="dangerous")?"dangerous":representative.description_status};
  });
}
function sortedProcesses(){
  let query=S.q.trim().toLowerCase(),direction=S.processSortDirection==="desc"?-1:1;
  let rows=groupedProcesses().filter(group=>!query||group.processes.some(process=>`${process.name} ${process.exe} ${process.pid} ${process.description||""}`.toLowerCase().includes(query)));
  return rows.map((process,index)=>({process,index})).sort((left,right)=>{
    let a=left.process,b=right.process,result=0;
    if(S.processSort==="name")result=a.name.localeCompare(b.name,"ru",{sensitivity:"base"});
    else if(S.processSort==="attention")result=processAttention(a)-processAttention(b);
    else result=Number(a[S.processSort]||0)-Number(b[S.processSort]||0);
    return result===0?left.index-right.index:result*direction;
  }).map(entry=>entry.process);
}

function processCard(x){
  let permanent=x.block_mode==="permanent",launch=x.block_mode==="kill_on_launch",rulePath=x.block_rule_exe_path||x.exe,isGroup=x.count>1,expanded=S.expandedProcessGroups.has(x.key);
  let verified=x.security_status==="verified",attention=processAttention(x);
  let stateLabel=permanent?"Блокируется":launch?"При запуске":verified?"Подпись проверена":x.exe?"Требует внимания":"Путь недоступен";
  let stateClass=permanent?"blocked":verified?"verified":attention>1?"attention":"neutral";
  let description=x.description?`<p>${e(x.description)}</p><button class="process-text-action" data-ai="${e(x.name)}" data-exe="${e(x.exe)}" data-security="${x.security_status}" data-ai-force="true">Обновить описание</button>`:`<p class="description-placeholder">Локального описания пока нет.</p><button class="process-text-action" data-ai="${e(x.name)}" data-exe="${e(x.exe)}" data-security="${x.security_status}">Узнать через AI</button>`;
  let instances=isGroup?`<button type="button" class="process-instance-toggle" data-process-group-toggle="${encodeURIComponent(x.key)}" aria-expanded="${expanded}"><span>${x.count} ${x.count===2||x.count===3||x.count===4?"экземпляра":"экземпляров"}</span><b>${expanded?"Скрыть список ↑":"Показать PID ↓"}</b></button>${expanded?`<div class="process-instances">${[...x.processes].sort((a,b)=>Number(b.memory_mb||0)-Number(a.memory_mb||0)).map(process=>`<div class="process-instance"><div class="process-instance-identity"><span aria-hidden="true">↳</span><div><b>PID ${process.pid}</b><small>${e(process.status||"—")}</small></div></div><div class="process-instance-stat"><small>CPU</small><b>${Number(process.cpu_percent).toFixed(1)}%</b></div><div class="process-instance-stat"><small>ПАМ</small><b>${Number(process.memory_mb).toFixed(0)} МБ</b></div><button type="button" class="process-instance-kill" data-kill="${process.pid}" data-name="${e(process.name)}" data-exe="${e(process.exe)}">Завершить</button></div>`).join("")}</div>`:""}`:"";
  let terminate=isGroup?"":`<button class="tile-action danger-text" data-kill="${x.pid}" data-name="${e(x.name)}" data-exe="${e(x.exe)}">Завершить</button>`;
  return `<article class="process-tile ${stateClass} ${isGroup?"process-stack":""}" data-process-row data-pid="${x.pid}"><header class="process-tile-head"><span class="process-app-icon"><img data-process-icon="${e(processIconKey(x))}" src="${processIconSource(x)}" alt="" aria-hidden="true"></span><span class="process-state-dot" aria-hidden="true"></span><div class="process-identity"><h3>${e(x.name||"System process")}</h3><p title="${e(x.exe||"Путь недоступен")}">${e(x.exe||"Путь недоступен")}</p></div><span class="badge ${stateClass}">${stateLabel}</span></header><div class="process-facts"><div><span>${isGroup?"Экземпляры":"PID"}</span><strong>${isGroup?x.count:x.pid}</strong></div><div><span>CPU</span><strong>${Number(x.cpu_percent).toFixed(1)}%</strong></div><div><span>Память</span><strong>${Number(x.memory_mb).toFixed(0)} МБ</strong></div><div><span>Состояние</span><strong>${isGroup?"Запущены":e(x.status||"—")}</strong></div></div>${instances}<div class="process-tile-description">${description}</div><div class="process-tile-actions"><button class="tile-action ${permanent?"active danger":""}" data-block-mode="permanent" data-rule-name="${e(x.name)}" data-exe="${e(rulePath)}" data-rule-active="${permanent}">${permanent?"Снять блок":"Блокировать"}</button><button class="tile-action ${launch?"active warm":""}" data-block-mode="kill_on_launch" data-rule-name="${e(x.name)}" data-exe="${e(rulePath)}" data-rule-active="${launch}">${launch?"Убрать при запуске":"Kill-on-Launch"}</button>${terminate}<button class="tile-action assistant-action" data-assistant-context="${e(x.name)}">Спросить V.E.R.A.</button></div></article>`;
}

function migratedProcess(){
  let all=sortedProcesses(),visible=all.slice(0,S.processVisibleCount),m=S.stats||{},hasMore=visible.length<all.length,totalInstances=all.reduce((total,group)=>total+group.count,0);
  let options=Object.entries(processSortLabels).map(([value,label])=>`<option value="${value}" ${S.processSort===value?"selected":""}>${label}</option>`).join("");
  return `<section class="metrics"><article class="metric glass"><div><small>ВСЕГО ПРОЦЕССОВ</small><strong>${m.total_processes??totalInstances}</strong><em>${all.length} приложений в списке</em></div></article><article class="metric glass"><div><small>АКТИВНЫЕ ПРАВИЛА</small><strong>${m.active_rules??0}</strong><em>Защита в реальном времени</em></div></article><article class="metric glass"><div><small>ЗА СЕССИЮ</small><strong>${m.session_terminated??0}</strong><em>Завершено автоматически</em></div></article></section><section class="process-board glass"><div class="process-controls"><label class="process-search"><span>Поиск</span><input id="search" value="${e(S.q)}" placeholder="Имя, PID, путь или описание"></label><label class="process-sort"><span>Сортировка</span><select id="process-sort">${options}</select></label><button id="process-sort-direction" class="sort-direction" title="Изменить направление сортировки">${S.processSortDirection==="asc"?"По возрастанию":"По убыванию"}</button><span class="process-count">Показано ${visible.length} из ${all.length} приложений</span></div><div class="process-feed-scroll"><div class="process-grid">${visible.map(processCard).join("")||empty("Процессы не найдены","Попробуйте изменить строку поиска.")}</div>${hasMore?`<div class="process-load-sentinel"><span></span>Загружаю следующую группу…</div>`:""}</div></section>`;
}

function observeProcessFeed(){
  S.processLoadObserver?.disconnect();
  if(S.page!=="processes")return;
  let sentinel=document.querySelector(".process-load-sentinel"),root=document.querySelector(".process-feed-scroll");
  if(!sentinel||!root)return;
  S.processLoadObserver=new IntersectionObserver(entries=>{if(!entries.some(entry=>entry.isIntersecting))return;S.processVisibleCount+=PROCESS_PAGE_SIZE;render()},{root,rootMargin:"240px 0px",threshold:.01});
  S.processLoadObserver.observe(sentinel);
}

function migratedBlocked(){
  let launch=S.page==="kill_on_launch",mode=launch?"kill_on_launch":"permanent",rules=S.rules.filter(rule=>(rule.mode||"permanent")===mode);
  let title=launch?"Kill-on-Launch":"Заблокированные процессы",description=launch?"Приложения из списка завершаются только при запуске V.E.R.A. После этого их можно открыть повторно — мониторинг их не трогает.":"Процессы из этого списка автоматически завершаются при обнаружении.";
  let enabled=rules.filter(rule=>rule.enabled).length;
  return `<section class="rule-workspace glass"><header class="rule-workspace-head"><div><small>ПРАВИЛА · ${launch?"СТАРТ ПРИЛОЖЕНИЯ":"ПОСТОЯННЫЙ КОНТРОЛЬ"}</small><h2>${title}</h2><p>${description}</p></div><div class="rule-summary"><strong>${rules.length}</strong><span>правил</span><em>${enabled} активно</em></div></header><div class="rule-card-list">${rules.map(r=>{let status=r.enabled?"Активно":"Отключено",desc=r.description||"Описание процесса ещё не добавлено.",killCount=Number(r.kill_count||0);return `<article class="rule-card ${r.enabled?"is-enabled":""} ${launch?"is-launch":""}"><header><span class="rule-card-mark" aria-hidden="true">${launch?"↗":"⊘"}</span><div><h3>${e(r.name)}</h3><p title="${e(r.exe_path||"Для любого пути")}">${e(r.exe_path||"Для любого пути")}</p></div><span class="rule-status ${r.enabled?"enabled":"paused"}">${status}</span></header><div class="rule-card-details"><span><b>Завершено</b>${killCount} раз</span><span><b>Область</b>${r.exe_path?"Точный путь":"Любой путь"}</span></div><p class="rule-card-description">${e(desc)}</p><footer><button class="row-action" data-toggle="${e(r.name)}" data-exe="${e(r.exe_path)}">${r.enabled?"Приостановить":"Включить"}</button><button class="row-action danger-text" data-delete="${e(r.name)}" data-exe="${e(r.exe_path)}">Удалить</button></footer></article>`}).join("")||empty("Правил пока нет",launch?"Добавьте Kill-on-Launch на экране процессов.":"Добавьте блокировку на экране процессов.")}</div></section>`
}

function heart(){
  let active=S.heartPreview;
  return `<section class="heart-screen ${active?"is-thinking":""}">
    <div class="heart-aurora" aria-hidden="true"></div>
    <div class="heart-grid" aria-hidden="true"></div>
    <div class="heart-copy">
      <div class="heart-kicker"><span></span> КЛЮЧЕВАЯ ФУНКЦИЯ · КОНЦЕПТ</div>
      <h2>Разум, который<br><em>остаётся рядом.</em></h2>
      <p>«Сердце» подключает выбранную LLM и запускает безопасный фоновый цикл reasoning: V.E.R.A. периодически осмысливает состояние системы, замечает важное и готовит рекомендации.</p>
      <div class="heart-actions">
        <button class="heart-demo" data-heart-demo>${active?"Остановить демонстрацию":"Показать, как это работает"}</button>
        <button class="heart-connect" disabled>Подключить LLM <span>СКОРО</span></button>
      </div>
      <div class="heart-promise"><span></span><p><b>Контроль остаётся у вас.</b> Реальные действия потребуют явного разрешения; фоновая модель только анализирует и предлагает.</p></div>
    </div>
    <div class="heart-reactor" aria-label="Визуализация reasoning-цикла">
      <div class="reactor-orbit orbit-one"><i></i><i></i><i></i></div>
      <div class="reactor-orbit orbit-two"><i></i><i></i></div>
      <div class="reactor-halo"></div>
      <div class="reactor-core"><div class="core-glyph"><span></span></div><small>${active?"THINKING":"DORMANT"}</small></div>
      <div class="reactor-scan"></div>
      <div class="heart-wave"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
      <div class="reactor-caption"><span></span>${active?"Симуляция reasoning-цикла":"Ядро ожидает подключения модели"}</div>
    </div>
    <div class="heart-flow">
      <article class="${active?"active":""}"><span>01</span><div><b>Наблюдает</b><small>Сигналы системы и выбранный контекст</small></div><i></i></article>
      <article class="${active?"active delay-one":""}"><span>02</span><div><b>Осмысливает</b><small>Периодический reasoning без лишнего шума</small></div><i></i></article>
      <article class="${active?"active delay-two":""}"><span>03</span><div><b>Предлагает</b><small>Выводы и действия только под вашим контролем</small></div></article>
    </div>
    <div class="heart-specs glass">
      <div><span>MODEL LINK</span><strong>Не подключена</strong></div>
      <div><span>THOUGHT CYCLE</span><strong>Настраиваемый</strong></div>
      <div><span>LOCAL MEMORY</span><strong>Защищённая</strong></div>
      <div><span>GUARDRAILS</span><strong>Разрешения пользователя</strong></div>
    </div>
  </section>`;
}

function migratedRender(){S.signatureObserver?.disconnect();S.iconObserver?.disconnect();S.processLoadObserver?.disconnect();let oldScroll=S.page==="processes"?(document.querySelector(".process-feed-scroll")?.scrollTop||0):0,[t,x]=P[S.page];$("#title").textContent=t;$("#eye").textContent=x;$("#view").innerHTML=({processes:migratedProcess,network,firewall,blocked:migratedBlocked,kill_on_launch:migratedBlocked,heart,startup,assistant,settings})[S.page]();document.querySelectorAll("[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===S.page));let feed=document.querySelector(".process-feed-scroll");if(feed)feed.scrollTop=oldScroll;let chatLog=$("#chat-log");if(chatLog)requestAnimationFrame(()=>chatLog.scrollTop=chatLog.scrollHeight);observeVisibleProcesses();observeVisibleProcessIcons();observeProcessFeed()}
async function migratedLoad(){try{if(S.page==="processes"){let snapshot=(await backendRequest("processes.snapshot")).data;S.processes=applySignatureStatuses(snapshot.processes);S.stats=snapshot.statistics;S.processVisibleCount=PROCESS_PAGE_SIZE}if(S.page==="network"){let ipRequest=backendRequest("network.public_ip").catch(err=>({data:{error:errorText(err)}}));S.network=(await backendRequest("network.list")).data;migratedRender();S.ip=(await ipRequest).data}if(S.page==="firewall")S.firewall=(await backendRequest("firewall.list")).data;if(S.page==="blocked"||S.page==="kill_on_launch")S.rules=(await backendRequest("rules.list")).data;if(S.page==="startup")S.startup=(await backendRequest("startup.list")).data;if(S.page==="settings")S.settings=(await backendRequest("settings.get")).data;if(S.page==="assistant")S.assistantSettings=(await backendRequest("settings.get")).data;$("#backend").textContent=isTauri()?"Backend подключён":"Browser preview"}catch(err){$("#backend").textContent="Backend недоступен";$("#view").innerHTML=empty(S.page==="network"?"Ошибка Network Radar":"Ошибка",errorText(err));return}migratedRender();if(S.page==="network"){clearInterval(S.networkTimer);S.networkTimer=setInterval(()=>migratedLoad(),5000)}}
async function migratedGo(page){clearInterval(S.networkTimer);S.page=page;S.q="";S.firewallNotice="";S.processVisibleCount=PROCESS_PAGE_SIZE;migratedRender();await migratedLoad()}
document.addEventListener("click",async ev=>{if(ev.target.id==="process-sort-direction"){S.processSortDirection=S.processSortDirection==="asc"?"desc":"asc";S.processVisibleCount=PROCESS_PAGE_SIZE;render();document.querySelector(".process-feed-scroll")?.scrollTo(0,0);return}let button=ev.target.closest("[data-block-mode]");if(!button)return;let action=button.dataset.ruleActive==="true"?"rules.delete":"rules.upsert";await backendRequest(action,{name:button.dataset.ruleName,mode:button.dataset.blockMode,exe_path:button.dataset.exe});await load()});
document.addEventListener("change",ev=>{if(ev.target.id!=="process-sort")return;S.processSort=ev.target.value;S.processVisibleCount=PROCESS_PAGE_SIZE;render();document.querySelector(".process-feed-scroll")?.scrollTo(0,0)});
document.addEventListener("click",ev=>{let toggle=ev.target.closest("[data-process-group-toggle]");if(!toggle)return;let key=decodeURIComponent(toggle.dataset.processGroupToggle);if(S.expandedProcessGroups.has(key))S.expandedProcessGroups.delete(key);else S.expandedProcessGroups.add(key);render()});
document.addEventListener("click",ev=>{let demo=ev.target.closest("[data-heart-demo]");if(!demo)return;S.heartPreview=!S.heartPreview;render()});
document.addEventListener("click",async ev=>{
  let newChat=ev.target.closest("#new-chat");
  if(newChat){S.history=[];S.assistantDraft="";S.assistantError="";S.assistantModel="";return render()}
  let suggestion=ev.target.closest("[data-chat-prompt]");
  if(suggestion){S.assistantDraft=suggestion.dataset.chatPrompt||"";render();$("#chat-input")?.focus();return}
  let context=ev.target.closest("[data-assistant-context]");
  if(!context)return;
  S.assistantDraft=`Что делает процесс ${context.dataset.assistantContext}? Стоит ли его блокировать?`;
  await go("assistant");
  $("#chat-input")?.focus();
});
document.addEventListener("keydown",ev=>{
  if(ev.target.id!=="chat-input"||ev.key!=="Enter"||ev.shiftKey||ev.isComposing)return;
  ev.preventDefault();
  ev.target.form?.requestSubmit();
});
document.addEventListener("submit",async ev=>{
  if(ev.target.id!=="assistant-chat-form")return;
  ev.preventDefault();
  if(S.assistantBusy)return;
  let message=$("#chat-input")?.value.trim()||"";
  if(!message)return;
  let history=S.history.slice();
  S.history.push({role:"user",text:message});
  S.assistantDraft="";
  S.assistantError="";
  S.assistantBusy=true;
  render();
  try{
    let response=await backendRequest("assistant.chat",{history,message});
    S.history.push({role:"model",text:response.data.text});
    S.assistantModel=response.data.model||S.assistantModel;
  }catch(err){
    S.assistantError=errorText(err);
  }finally{
    S.assistantBusy=false;
    render();
  }
});
document.addEventListener("change",ev=>{
  if(ev.target.id!=="settings-provider")return;
  S.settingsProviderDraft=ev.target.value;
  S.settingsNotice="";
  render();
});
document.addEventListener("click",ev=>{
  let toggle=ev.target.closest("[data-key-toggle]");
  if(!toggle)return;
  let input=document.getElementById(toggle.dataset.keyToggle);
  if(!input)return;
  let visible=input.type==="text";
  input.type=visible?"password":"text";
  toggle.textContent=visible?"◉":"◌";
  toggle.setAttribute("aria-label",visible?"Показать ключ":"Скрыть ключ");
});
document.addEventListener("submit",async ev=>{
  if(ev.target.id!=="settings-form")return;
  ev.preventDefault();
  let form=new FormData(ev.target),values=Object.fromEntries(form);
  ["monitoring_enabled","autostart","minimize_to_tray","show_notifications"].forEach(key=>values[key]=form.has(key));
  values.scan_interval_sec=Number(values.scan_interval_sec);
  try{
    let saved=(await backendRequest("settings.set",{values})).data;
    if(isTauri())await invoke("monitor_configure",{enabled:saved.monitoring_enabled,intervalSeconds:saved.scan_interval_sec});
    await backendRequest("app_autostart.set",{enabled:saved.autostart});
    S.settings=saved;
    S.settingsProviderDraft="";
    S.settingsNotice="Настройки сохранены и применены.";
    S.settingsNoticeError=false;
  }catch(err){
    S.settingsNotice=errorText(err);
    S.settingsNoticeError=true;
  }
  render();
});

process=migratedProcess;blocked=migratedBlocked;render=migratedRender;load=migratedLoad;go=migratedGo;
go("processes").then(async()=>{if(!isTauri())return;try{let x=(await backendRequest("settings.get")).data;await invoke("monitor_configure",{enabled:x.monitoring_enabled,intervalSeconds:x.scan_interval_sec})}catch{}});

function addUpdateControl(){
  if(S.page!=="settings"||document.querySelector("#check-updates"))return;
  let details=document.querySelector(".settings-about .about-details");
  if(details){let version=details.querySelector("span");if(version)version.textContent="Версия 0.4.1";details.insertAdjacentHTML("beforeend",'<button id="check-updates" type="button" class="row-action">Проверить обновления</button>')}
}
const renderBeforeUpdateControl=migratedRender;
migratedRender=function(){renderBeforeUpdateControl();addUpdateControl()};
render=migratedRender;
document.addEventListener("click",async event=>{
  if(event.target.id!=="check-updates")return;
  let button=event.target;
  if(!isTauri()){S.settingsNotice="Проверка обновлений доступна только в установленном приложении.";S.settingsNoticeError=false;render();return}
  button.disabled=true;
  button.textContent="Проверяю…";
  try{
    let result=await checkForUpdate();
    if(!result.available){S.settingsNotice="Установлена актуальная версия V.E.R.A.";S.settingsNoticeError=false;render();return}
    let update=result.update;
    let confirmed=window.confirm(`Доступна версия ${update.version}. Скачать и установить её после закрытия V.E.R.A.?`);
    if(!confirmed){await update.close();S.settingsNotice="Обновление не установлено.";S.settingsNoticeError=false;render();return}
    S.settingsNotice=`Скачиваю обновление ${update.version}…`;
    S.settingsNoticeError=false;
    render();
    await installUpdate(update);
  }catch(error){S.settingsNotice=`Не удалось обновить приложение: ${errorText(error)}`;S.settingsNoticeError=true;render()}
});
