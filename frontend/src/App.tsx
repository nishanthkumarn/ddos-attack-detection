import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, BrainCircuit, CircleDot,
  Clock3, Database, Download, FileText, Gauge, LayoutDashboard, LockKeyhole,
  Menu, Pause, Play, Printer, Radio, RefreshCw, Search, Server, Settings2,
  Shield, ShieldAlert, ShieldCheck, Siren, SlidersHorizontal, Sparkles,
  TerminalSquare, Wifi, X, Zap
} from 'lucide-react';
import {
  Area, AreaChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts';

type Event = { event_id:string; timestamp:string; src_ip:string; dst_ip:string; src_port:number; dst_port:number; protocol:string; label:'BENIGN'|'DDoS'; probability:number; confidence:number; severity:string; bytes_per_second:number; packets_per_second:number; flow_duration_ms:number; mode:string; model_version:string };
type Stats = { total:number; attacks:number; benign:number; attack_rate:number; pps:number; bps:number; model_loaded:boolean; model_version:string; mode:string; database?:string; drift?:{samples:number;anomalous_samples:number;anomaly_rate:number}; stream:{running:boolean; interval_ms:number; events:number; attack_burst:boolean; source?:string} };
type Alert = { alert_id:string; first_seen:string; last_seen:string; src_ip:string; dst_ip:string; protocol:string; severity:string; probability:number; occurrences:number; status:string; reason:string };
type ScanForm = { src_ip:string; dst_ip:string; src_port:number; dst_port:number; protocol:string; packets_per_second:number; bytes_per_second:number; flow_duration_ms:number; total_fwd_packets:number; total_bwd_packets:number; packet_length_mean:number; syn_flag_count:number; ack_flag_count:number; rst_flag_count:number; psh_flag_count:number; fin_flag_count:number };
type ScanReport = { scan_id:string; timestamp:string; target:{src_ip:string;dst_ip:string;src_port:number;dst_port:number;protocol:string}; verdict:string; probability:number; confidence:number; threat_level:string; risk_score:number; attack_type:string; attack_description:string; summary:string; telemetry:Record<string,number>; signals:Array<{feature:string;importance:number;value:number}>; drift_analysis:Array<{feature:string;value:number;baseline_mean:number;z_score:number;anomaly:boolean}>; recommendations:string[]; firewall_rules:Record<string,string>; model_info:{version:string;threshold:number;mode:string;roc_auc?:number;f1_score?:number} };
type BatchFlow = { row:number; src_ip:string; dst_ip:string; protocol:string; actual_label:string; actual_class:'BENIGN'|'DDoS'; predicted_label:string; probability:number; confidence:number; severity:string; mode:string; correct:boolean };
type BatchResult = { filename:string; rows:number; model_version:string; threshold:number; metrics:{accuracy:number;precision:number;recall:number;f1:number;specificity:number;false_positive_rate:number;false_negative_rate:number;roc_auc:number|null;average_precision:number|null;confusion_matrix:{tn:number;fp:number;fn:number;tp:number}}; attack_families:Array<{label:string;rows:number;recall:number}>; results:BatchFlow[] };

const API = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/,'');
const empty:Stats = { total:0, attacks:0, benign:0, attack_rate:0, pps:0, bps:0, model_loaded:false, model_version:'untrained', mode:'demo', stream:{running:false,interval_ms:350,events:0,attack_burst:false,source:'synthetic'} };
const nav = [
  {id:'overview',label:'Command Center',icon:LayoutDashboard},
  {id:'alerts',label:'Incident Queue',icon:Siren},
  {id:'scan',label:'Flow Scanner',icon:Search},
  {id:'model',label:'Detection Engine',icon:BrainCircuit},
  {id:'ops',label:'Operations',icon:Settings2},
] as const;
type Tab = typeof nav[number]['id'];

function pct(n:number){return `${(n*100).toFixed(1)}%`}
function fmt(n:number){return Intl.NumberFormat('en-US',{notation:n>999999?'compact':'standard',maximumFractionDigits:1}).format(n)}
function ago(ts:string){const s=Math.max(0,Math.round((Date.now()-new Date(ts).getTime())/1000)); return s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`}
function severityClass(s:string){const x=s.toUpperCase();return x==='CRITICAL'?'critical':x==='HIGH'?'high':x==='MEDIUM'?'medium':'low'}

export default function App(){
  const [events,setEvents]=useState<Event[]>([]); const [alerts,setAlerts]=useState<Alert[]>([]); const [stats,setStats]=useState<Stats>(empty);
  const [connected,setConnected]=useState(false); const [tab,setTab]=useState<Tab>('overview'); const [menu,setMenu]=useState(false); const [search,setSearch]=useState(''); const [clock,setClock]=useState(new Date());
  const ws=useRef<WebSocket|null>(null);
  const refresh=()=>Promise.all([fetch(`${API}/api/stats`).then(r=>r.json()),fetch(`${API}/api/alerts`).then(r=>r.json())]).then(([s,a])=>{setStats(s);setAlerts(a)}).catch(()=>{});
  useEffect(()=>{refresh();const t=setInterval(refresh,2500);const c=setInterval(()=>setClock(new Date()),1000);return()=>{clearInterval(t);clearInterval(c);ws.current?.close()}},[]);
  const connect=()=>{if(ws.current?.readyState===WebSocket.OPEN)return;const s=new WebSocket(API.replace(/^http/,'ws')+'/ws/stream');ws.current=s;s.onopen=()=>setConnected(true);s.onclose=()=>setConnected(false);s.onerror=()=>setConnected(false);s.onmessage=e=>{try{const ev=JSON.parse(e.data) as Event;setEvents(x=>[...x,ev].slice(-160));setStats(x=>({...x,total:x.total+1,attacks:x.attacks+(ev.label==='DDoS'?1:0),benign:x.benign+(ev.label==='BENIGN'?1:0)}))}catch{}}};
  const control=(action:string)=>fetch(`${API}/api/stream/control`,{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':import.meta.env.VITE_OPERATOR_API_KEY||''},body:JSON.stringify({action})}).then(refresh).catch(()=>{});
  const chart=useMemo(()=>events.slice(-60).map((e,i)=>({i,pps:Math.round(e.packets_per_second),risk:Math.round(e.probability*100)})),[events]);
  const recent=useMemo(()=>events.slice().reverse().filter(e=>!search || `${e.src_ip} ${e.dst_ip} ${e.label} ${e.protocol}`.toLowerCase().includes(search.toLowerCase())).slice(0,9),[events,search]);
  const threat = Math.min(100,Math.round((stats.attack_rate*0.55)+(alerts.length?Math.min(alerts.length,10)*3:0)+(stats.stream.attack_burst?30:0)));
  const health = stats.model_loaded ? 96 : 61;
  return <div className="app-shell">
    <aside className={`sidebar ${menu?'open':''}`}>
      <div className="brand"><div className="brand-mark"><Shield size={22}/></div><div><b>NEXUS</b><span>CYBER DEFENSE</span></div><button className="close-mobile" onClick={()=>setMenu(false)}><X size={18}/></button></div>
      <div className="environment"><span className="live-dot"/> LOCAL SOC <span>LAB</span></div>
      <div className="side-label">OPERATIONS</div>
      <nav>{nav.map(n=>{const I=n.icon;return <button key={n.id} className={tab===n.id?'active':''} onClick={()=>{setTab(n.id);setMenu(false)}}><I size={17}/><span>{n.label}</span>{n.id==='alerts'&&alerts.length>0?<em>{alerts.length}</em>:null}</button>})}</nav>
      <div className="side-label">SYSTEM</div>
      <div className="side-status"><div><span>API</span><b className="ok">ONLINE</b></div><div><span>STREAM</span><b className={connected?'ok':'warn'}>{connected?'CONNECTED':'WAITING'}</b></div><div><span>MODEL</span><b className={stats.model_loaded?'ok':'warn'}>{stats.model_loaded?'READY':'UNTRAINED'}</b></div></div>
      <div className="side-bottom"><div className="mini-terminal"><TerminalSquare size={15}/><span>DEFENSIVE LAB</span><span className="blink">_</span></div><small>v4.0 • CICDDoS2019</small></div>
    </aside>
    {menu&&<div className="backdrop" onClick={()=>setMenu(false)}/>}
    <main className="main">
      <header className="topbar"><div className="top-left"><button className="mobile-menu" onClick={()=>setMenu(true)}><Menu size={20}/></button><div><div className="eyebrow">SECURITY OPERATIONS CENTER / FLOW INTELLIGENCE</div><h1>{nav.find(n=>n.id===tab)?.label.toUpperCase()}</h1></div></div><div className="top-actions"><div className="clock">{clock.toLocaleTimeString([], {hour12:false})}<small> LOCAL</small></div><button className="icon-btn"><LockKeyhole size={17}/></button><div className="operator"><div className="avatar">N</div><div><b>OPERATOR</b><span>LOCAL ADMIN</span></div></div></div></header>
      <div className="content">
        {tab==='overview'&&<>
          <section className="hero-row"><div><div className="eyebrow green">REAL-TIME NETWORK DEFENSE</div><h2>Traffic under continuous <span>machine analysis.</span></h2><p>Flow telemetry, calibrated risk scoring and correlated incidents in one defensive workspace.</p></div><div className="hero-controls"><button className="btn ghost" onClick={connect}><Radio size={15}/>{connected?'STREAM CONNECTED':'CONNECT STREAM'}</button><button className="btn cyan" onClick={()=>control('start')}><Play size={15}/>START</button><button className="btn dark" onClick={()=>control('stop')}><Pause size={15}/>PAUSE</button><button className="btn danger" onClick={()=>control('burst')}><Siren size={15}/>SIMULATE ATTACK</button></div></section>
          <div className="notice"><Sparkles size={15}/><span><b>Lab mode:</b> synthetic traffic is active for safe local validation. Live deployment should ingest CICFlowMeter-compatible features.</span><span className="notice-right">{stats.mode.toUpperCase()}</span></div>
          <section className="kpi-grid">
            <Kpi icon={Activity} label="FLOW EVENTS" value={fmt(stats.total)} trend="LIVE" positive/>
            <Kpi icon={ShieldAlert} label="DDoS DETECTIONS" value={fmt(stats.attacks)} trend={stats.attack_rate.toFixed(1)+'% rate'} alert/>
            <Kpi icon={Gauge} label="PACKETS / SEC" value={fmt(stats.pps)} trend="THROUGHPUT" />
            <Kpi icon={BrainCircuit} label="MODEL HEALTH" value={stats.model_loaded?'READY':'DEMO'} trend={stats.model_version} positive={stats.model_loaded}/>
            <Kpi icon={Wifi} label="STREAM STATE" value={connected?'ONLINE':'IDLE'} trend={stats.stream.attack_burst?'BURST':'NORMAL'} positive={connected} alert={stats.stream.attack_burst}/>
          </section>
          <section className="dashboard-grid">
            <div className="panel traffic-panel"><PanelHead title="LIVE THREAT TELEMETRY" sub="PACKET RATE VS MODEL RISK" icon={Activity}/><div className="chart-legend"><span><i className="dot green-dot"/> PACKETS / SEC</span><span><i className="dot red-dot"/> RISK SCORE</span></div><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chart}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ff4d5e" stopOpacity=".22"/><stop offset="1" stopColor="#ff4d5e" stopOpacity="0"/></linearGradient><linearGradient id="ppsFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#4de2a8" stopOpacity=".16"/><stop offset="1" stopColor="#4de2a8" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="#1b2930" vertical={false}/><XAxis dataKey="i" hide/><YAxis yAxisId="left" stroke="#52636b" fontSize={10} tickLine={false}/><YAxis yAxisId="right" orientation="right" domain={[0,100]} stroke="#52636b" fontSize={10} tickLine={false}/><Tooltip contentStyle={{background:'#0a1116',border:'1px solid #24343d',borderRadius:8,fontSize:11}}/><Area yAxisId="left" type="monotone" dataKey="pps" stroke="#4de2a8" fill="url(#ppsFill)" strokeWidth={2} dot={false}/><Area yAxisId="right" type="monotone" dataKey="risk" stroke="#ff6472" fill="url(#riskFill)" strokeWidth={2} dot={false}/></AreaChart></ResponsiveContainer></div></div>
            <div className="panel threat-panel"><PanelHead title="THREAT POSTURE" sub="CURRENT ENVIRONMENT RISK" icon={ShieldAlert}/><div className="score-wrap"><div className="score-ring" style={{'--score':`${threat*3.6}deg`} as CSSProperties}><div><strong>{threat}</strong><span>/ 100</span></div></div><div className="score-label"><b>{threat>70?'ELEVATED':threat>35?'GUARDED':'STABLE'}</b><span>composite risk</span></div></div><div className="meter"><div style={{width:`${threat}%`}}/></div><div className="threat-facts"><Fact label="ATTACK RATE" value={`${stats.attack_rate.toFixed(1)}%`}/><Fact label="CORRELATED ALERTS" value={String(alerts.length)}/><Fact label="ENGINE HEALTH" value={`${health}%`}/></div></div>
          </section>
          <section className="lower-grid"><div className="panel incidents"><PanelHead title="PRIORITY INCIDENTS" sub="CORRELATED FLOW ACTIVITY" icon={Siren}/><div className="incident-list">{alerts.slice(0,5).map(a=><Incident key={a.alert_id} a={a}/>)}{!alerts.length&&<Empty icon={ShieldCheck} text="No correlated incidents. Environment is quiet."/>}</div></div><div className="panel distribution"><PanelHead title="TRAFFIC CLASSIFICATION" sub="CURRENT EVENT DISTRIBUTION" icon={Gauge}/><div className="donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={[{name:'DDoS',value:stats.attacks},{name:'BENIGN',value:stats.benign}]} innerRadius={55} outerRadius={78} paddingAngle={3} dataKey="value"><Cell fill="#ff4d5e"/><Cell fill="#4de2a8"/></Pie><Tooltip contentStyle={{background:'#0a1116',border:'1px solid #24343d',borderRadius:8,fontSize:11}}/></PieChart></ResponsiveContainer><div className="donut-center"><b>{stats.total?Math.round((stats.attacks/stats.total)*100):0}%</b><span>ATTACK</span></div></div><div className="class-legend"><div><i className="red-box"/><span>DDoS</span><b>{fmt(stats.attacks)}</b></div><div><i className="green-box"/><span>Benign</span><b>{fmt(stats.benign)}</b></div></div></div></section>
          <section className="panel feed-panel"><div className="feed-head"><PanelHead title="LIVE DETECTION FEED" sub="MOST RECENT CLASSIFICATIONS" icon={Database}/><div className="search"><Search size={14}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search IP, protocol, class..."/></div></div><Feed events={recent}/></section>
        </>}
        {tab==='alerts'&&<AlertsPage alerts={alerts}/>} {tab==='scan'&&<ScannerPage api={API}/>} {tab==='model'&&<ModelPanel api={API}/>} {tab==='ops'&&<OpsPanel api={API}/>}
      </div>
      <footer><span>◆ NEXUS CYBER DEFENSE</span><span>DEFENSIVE RESEARCH / LOCAL LAB</span><span>CICDDoS2019 FEATURE CONTRACT</span><span>API {API.replace(/^https?:\/\//,'')}</span></footer>
    </main>
  </div>
}

  function Kpi({icon:Icon,label,value,trend,positive,alert}:{icon:any;label:string;value:string;trend:string;positive?:boolean;alert?:boolean}){return <div className={`kpi panel ${alert?'kpi-alert':''}`}><div className="kpi-top"><span>{label}</span><Icon size={17}/></div><div className="kpi-value">{value}</div><div className={`kpi-trend ${positive?'up':''} ${alert?'red':''}`}>{positive?<ArrowUpRight size={12}/>:<ArrowDownRight size={12}/>} {trend}</div></div>}
function PanelHead({title,sub,icon:Icon}:{title:string;sub:string;icon:any}){return <div className="panel-head"><div className="panel-icon"><Icon size={15}/></div><div><h3>{title}</h3><span>{sub}</span></div></div>}
function Fact({label,value}:{label:string;value:string}){return <div><span>{label}</span><b>{value}</b></div>}
function Incident({a}:{a:Alert}){return <div className="incident"><div className={`sev ${severityClass(a.severity)}`}><span/></div><div className="incident-main"><div><b>{a.src_ip}</b><span>→</span><b>{a.dst_ip}</b><em>{a.protocol}</em></div><small>{a.reason || 'Repeated high-risk flow classification'} • {ago(a.last_seen)}</small></div><div className="incident-score"><b>{pct(a.probability)}</b><span>{a.occurrences} hits</span></div></div>}
function Empty({icon:Icon,text}:{icon:any;text:string}){return <div className="empty"><Icon size={22}/><span>{text}</span></div>}
function Feed({events}:{events:Event[]}){return <div className="feed"><div className="feed-row feed-title"><span>TIME</span><span>SOURCE → DESTINATION</span><span>PROTO</span><span>RATE</span><span>RISK</span><span>CLASS</span></div>{events.map(e=><div className="feed-row" key={e.event_id}><span className="muted">{new Date(e.timestamp).toLocaleTimeString([], {hour12:false})}</span><span className="mono">{e.src_ip} <i>→</i> {e.dst_ip}:{e.dst_port}</span><span className="muted">{e.protocol}</span><span>{fmt(e.packets_per_second)} p/s</span><span className={e.probability>=.78?'risk-high':'risk-low'}>{pct(e.probability)}</span><span><b className={`class-pill ${e.label==='DDoS'?'ddos':'benign'}`}>{e.label}</b></span></div>)}{!events.length&&<Empty icon={Radio} text="Connect to the WebSocket stream to receive detections."/>}</div>}

function AlertsPage({alerts}:{alerts:Alert[]}){return <div className="page"><div className="page-intro"><div><div className="eyebrow red">INCIDENT RESPONSE</div><h2>Correlated alert queue.</h2><p>Repeated detections are grouped by flow tuple to reduce noise and expose persistent sources.</p></div><div className="page-stat"><b>{alerts.length}</b><span>OPEN INCIDENTS</span></div></div><div className="panel big-panel"><div className="table-head"><span>SEVERITY</span><span>FLOW</span><span>PROBABILITY</span><span>OCCURRENCES</span><span>LAST SEEN</span><span>STATUS</span></div>{alerts.map(a=><div className="alert-row" key={a.alert_id}><span><b className={`severity-chip ${severityClass(a.severity)}`}>{a.severity}</b></span><span className="mono">{a.src_ip} → {a.dst_ip} <small>{a.protocol}</small></span><strong>{pct(a.probability)}</strong><span>{a.occurrences}</span><span className="muted">{ago(a.last_seen)}</span><span className="status-chip">{a.status}</span></div>)}{!alerts.length&&<Empty icon={ShieldCheck} text="No alerts are currently active."/>}</div></div>}
function ModelPanel({api}:{api:string}){const [m,setM]=useState<any>(null);useEffect(()=>{fetch(`${api}/api/model`).then(r=>r.json()).then(setM).catch(()=>{})},[api]);return <div className="page"><div className="page-intro"><div><div className="eyebrow">MODEL INTELLIGENCE</div><h2>Detection engine.</h2><p>Calibration, validation metrics and feature signals used by the real-time classifier.</p></div><div className={`engine-badge ${m?.loaded?'ready':'demo'}`}><CircleDot size={12}/>{m?.loaded?'MODEL READY':'DEMO / UNTRAINED'}</div></div><div className="model-grid"><div className="panel big-panel"><PanelHead title="MODEL CARD" sub="RUNTIME CONFIGURATION" icon={BrainCircuit}/><div className="metric-grid">{[['VERSION',m?.version||'untrained'],['THRESHOLD',m?.threshold?.toFixed?.(4)||'—'],['ROC AUC',m?.metrics?.roc_auc?.toFixed?.(4)||'—'],['AVG PRECISION',m?.metrics?.average_precision?.toFixed?.(4)||'—'],['RECALL',m?.metrics?.recall_at_threshold?.toFixed?.(4)||'—'],['F1 SCORE',m?.metrics?.f1_at_threshold?.toFixed?.(4)||'—']].map(([a,b])=><div className="metric" key={a}><span>{a}</span><b>{b}</b></div>)}</div></div><div className="panel big-panel"><PanelHead title="TOP FEATURE SIGNALS" sub="PERMUTATION IMPORTANCE" icon={SlidersHorizontal}/><div className="importance">{(m?.importance||[]).slice(0,12).map((x:any,i:number)=><div className="imp" key={x[0]}><span>{String(i+1).padStart(2,'0')}</span><b title={x[0]}>{x[0]}</b><div><i style={{width:`${Math.min(100,Math.max(5,Number(x[1])*700))}%`}}/></div><em>{Number(x[1]).toFixed(4)}</em></div>)}</div></div></div></div>}
function ScannerPage({api}:{api:string}){
  const [mode,setMode]=useState<'single'|'batch'>('single');
  const [form,setForm]=useState<ScanForm>({src_ip:'185.220.101.5',dst_ip:'10.0.0.10',src_port:44921,dst_port:80,protocol:'TCP',packets_per_second:75000,bytes_per_second:40000000,flow_duration_ms:500,total_fwd_packets:37500,total_bwd_packets:0,packet_length_mean:533,syn_flag_count:100,ack_flag_count:0,rst_flag_count:0,psh_flag_count:0,fin_flag_count:0});
  const [report,setReport]=useState<ScanReport|null>(null);
  const [history,setHistory]=useState<ScanReport[]>([]);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');

  useEffect(()=>{
    let active=true;
    fetch(`${api}/api/scans?limit=20`).then(r=>{if(!r.ok)throw new Error('Could not load saved scans');return r.json()}).then((items:ScanReport[])=>{
      if(active){setHistory(items);setReport(items[0]??null)}
    }).catch(()=>{if(active)setError('Saved scans could not be loaded from the API.')});
    return()=>{active=false};
  },[api]);

  const updateField=(key:keyof ScanForm,value:string)=>{
    const textFields:(keyof ScanForm)[]=['src_ip','dst_ip','protocol'];
    setForm(current=>({...current,[key]:textFields.includes(key)?value:Number(value)} as ScanForm));
  };
  const runScan=async(event:React.FormEvent<HTMLFormElement>)=>{
    event.preventDefault();setBusy(true);setError('');
    try{
      const response=await fetch(`${api}/api/scan`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(form)});
      const result=await response.json();
      if(!response.ok)throw new Error(result.detail||`Scan failed (${response.status})`);
      const next=result as ScanReport;
      setReport(next);setHistory(current=>[next,...current.filter(item=>item.scan_id!==next.scan_id)].slice(0,20));
    }catch(reason){setError(reason instanceof Error?reason.message:'Scan request failed. Check the API connection and try again.')}
    finally{setBusy(false)}
  };
  const downloadReport=()=>{
    if(!report)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
    const link=document.createElement('a');link.href=url;link.download=`${report.scan_id.toLowerCase()}-report.json`;link.click();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  };

  return <div className="page scan-page">
    <div className="page-intro"><div><div className="eyebrow">FLOW ANALYSIS</div><h2>Scan report.</h2><p>Record a flow assessment with its evidence, model context, and response guidance.</p></div><div className="page-stat"><b>{history.length}</b><span>SAVED SCANS</span></div></div>
    <div className="scan-mode-switch" role="group" aria-label="Evaluation mode"><button type="button" aria-pressed={mode==='single'} className={mode==='single'?'active':''} onClick={()=>setMode('single')}>Single flow</button><button type="button" aria-pressed={mode==='batch'} className={mode==='batch'?'active':''} onClick={()=>setMode('batch')}>Labeled CSV test</button></div>
    {mode==='single'&&<>
    <form className="panel big-panel scanner-controls" onSubmit={runScan}>
      <PanelHead title="FLOW INPUT" sub="SCAN PARAMETERS" icon={Search}/>
      <div className="form-grid">
        <label className="form-field">SOURCE IP<input required value={form.src_ip} onChange={e=>updateField('src_ip',e.target.value)}/></label>
        <label className="form-field">DESTINATION IP<input required value={form.dst_ip} onChange={e=>updateField('dst_ip',e.target.value)}/></label>
        <label className="form-field">SOURCE PORT<input type="number" min="0" max="65535" value={form.src_port} onChange={e=>updateField('src_port',e.target.value)}/></label>
        <label className="form-field">DESTINATION PORT<input type="number" min="0" max="65535" value={form.dst_port} onChange={e=>updateField('dst_port',e.target.value)}/></label>
        <label className="form-field">PROTOCOL<select value={form.protocol} onChange={e=>updateField('protocol',e.target.value)}><option>TCP</option><option>UDP</option><option>ICMP</option></select></label>
        <label className="form-field">PACKETS / SECOND<input type="number" min="0" step="any" value={form.packets_per_second} onChange={e=>updateField('packets_per_second',e.target.value)}/></label>
        <label className="form-field">BYTES / SECOND<input type="number" min="0" step="any" value={form.bytes_per_second} onChange={e=>updateField('bytes_per_second',e.target.value)}/></label>
        <label className="form-field">FLOW DURATION (MS)<input type="number" min="0" step="any" value={form.flow_duration_ms} onChange={e=>updateField('flow_duration_ms',e.target.value)}/></label>
        <label className="form-field">FORWARD PACKETS<input type="number" min="0" step="any" value={form.total_fwd_packets} onChange={e=>updateField('total_fwd_packets',e.target.value)}/></label>
        <label className="form-field">BACKWARD PACKETS<input type="number" min="0" step="any" value={form.total_bwd_packets} onChange={e=>updateField('total_bwd_packets',e.target.value)}/></label>
        <label className="form-field">MEAN PACKET LENGTH<input type="number" min="0" step="any" value={form.packet_length_mean} onChange={e=>updateField('packet_length_mean',e.target.value)}/></label>
        <label className="form-field">SYN FLAG COUNT<input type="number" min="0" step="any" value={form.syn_flag_count} onChange={e=>updateField('syn_flag_count',e.target.value)}/></label>
        <label className="form-field">ACK FLAG COUNT<input type="number" min="0" step="any" value={form.ack_flag_count} onChange={e=>updateField('ack_flag_count',e.target.value)}/></label>
        <label className="form-field">RST FLAG COUNT<input type="number" min="0" step="any" value={form.rst_flag_count} onChange={e=>updateField('rst_flag_count',e.target.value)}/></label>
        <label className="form-field">PSH FLAG COUNT<input type="number" min="0" step="any" value={form.psh_flag_count} onChange={e=>updateField('psh_flag_count',e.target.value)}/></label>
        <label className="form-field">FIN FLAG COUNT<input type="number" min="0" step="any" value={form.fin_flag_count} onChange={e=>updateField('fin_flag_count',e.target.value)}/></label>
      </div>
      {error&&<div className="scan-error" role="alert">{error}</div>}
      <div className="scan-actions">
        {history.length>0&&<label className="scan-history"><Clock3 size={14}/><select aria-label="Saved scan reports" value={report?.scan_id||''} onChange={e=>setReport(history.find(item=>item.scan_id===e.target.value)||null)}><option value="">Saved reports</option>{history.map(item=><option key={item.scan_id} value={item.scan_id}>{item.scan_id} · {item.verdict} · {new Date(item.timestamp).toLocaleString()}</option>)}</select></label>}
        <button className="btn glow-cyan" type="submit" disabled={busy}>{busy?<RefreshCw size={15} className="spin"/>:<Search size={15}/>} {busy?'SCANNING':'RUN SCAN'}</button>
      </div>
    </form>
    {report?<ScanReportView report={report} onPrint={()=>window.print()} onDownload={downloadReport}/>:<div className="panel scan-empty"><FileText size={22}/><span>Run a scan to create the first report.</span></div>}
    </>}
    {mode==='batch'&&<BatchEvaluation api={api}/>}
  </div>;
}

function BatchEvaluation({api}:{api:string}){
  const [file,setFile]=useState<File|null>(null);
  const [result,setResult]=useState<BatchResult|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const [filter,setFilter]=useState<'all'|'false-positive'|'false-negative'>('all');

  const runEvaluation=async(event:React.FormEvent<HTMLFormElement>)=>{
    event.preventDefault();if(!file)return;
    setBusy(true);setError('');setResult(null);
    try{
      const body=new FormData();body.append('file',file);
      const response=await fetch(`${api}/api/evaluate/csv`,{method:'POST',body});
      const payload=await response.json();
      if(!response.ok)throw new Error(payload.detail||`Evaluation failed (${response.status})`);
      setResult(payload as BatchResult);setFilter('all');
    }catch(reason){setError(reason instanceof Error?reason.message:'CSV evaluation failed. Check the API connection and try again.')}
    finally{setBusy(false)}
  };
  const download=(kind:'json'|'csv')=>{
    if(!result)return;
    let content:string;let mime:string;let suffix:string;
    if(kind==='json'){
      content=JSON.stringify(result,null,2);mime='application/json';suffix='json';
    }else{
      const columns=['row','src_ip','dst_ip','protocol','actual_label','predicted_label','probability','confidence','severity','mode','correct'];
      const quote=(value:unknown)=>{
        const text=String(value??'');
        const safe=/^[=+@\-\t\r]/.test(text)?`'${text}`:text;
        return `"${safe.replaceAll('"','""')}"`;
      };
      content=[columns.join(','),...result.results.map(row=>columns.map(column=>quote(row[column as keyof BatchFlow])).join(','))].join('\r\n');
      mime='text/csv;charset=utf-8';suffix='csv';
    }
    const url=URL.createObjectURL(new Blob([content],{type:mime}));
    const link=document.createElement('a');link.href=url;link.download=`${result.filename.replace(/\.csv$/i,'')}-evaluation.${suffix}`;link.click();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  const matrix=result?.metrics.confusion_matrix;
  const filtered=result?.results.filter(row=>filter==='all'||(filter==='false-positive'&&row.actual_class==='BENIGN'&&row.predicted_label==='DDoS')||(filter==='false-negative'&&row.actual_class==='DDoS'&&row.predicted_label==='BENIGN'))||[];

  return <div className="batch-evaluation">
    <form className="panel big-panel scanner-controls" onSubmit={runEvaluation}>
      <PanelHead title="LABELED FLOW DATASET" sub="OFFLINE MODEL EVALUATION" icon={FileText}/>
      <div className="batch-upload"><label className="form-field">CICFlowMeter CSV<input type="file" accept=".csv,text/csv" required onChange={event=>{setFile(event.target.files?.[0]||null);setResult(null);setError('')}}/></label><span>Requires a Label/Class/Target column. Processed in memory; limit 25 MB and 20,000 rows.</span></div>
      {error&&<div className="scan-error" role="alert">{error}</div>}
      <div className="scan-actions"><span className="batch-file-name">{file?.name||'No CSV selected'}</span><button className="btn glow-cyan" type="submit" disabled={busy||!file}>{busy?<RefreshCw size={15} className="spin"/>:<Search size={15}/>} {busy?'EVALUATING':'EVALUATE DATASET'}</button></div>
    </form>
    {result&&<section className="panel big-panel batch-report">
      <header className="batch-report-head"><div><div className="eyebrow">LABELED DATASET RESULT</div><h3>{result.filename}</h3><span>{fmt(result.rows)} flows · {result.model_version} · threshold {pct(result.threshold)}</span></div><div className="batch-export"><button className="btn" type="button" onClick={()=>download('csv')}><Download size={14}/> CSV</button><button className="btn" type="button" onClick={()=>download('json')}><Download size={14}/> JSON</button></div></header>
      <div className="batch-metrics">{[['ACCURACY',pct(result.metrics.accuracy)],['PRECISION',pct(result.metrics.precision)],['RECALL',pct(result.metrics.recall)],['F1 SCORE',pct(result.metrics.f1)],['ROC AUC',result.metrics.roc_auc===null?'N/A':result.metrics.roc_auc.toFixed(4)],['PR AUC',result.metrics.average_precision===null?'N/A':result.metrics.average_precision.toFixed(4)]].map(([label,value])=><div key={label}><span>{label}</span><b>{value}</b></div>)}</div>
      <div className="batch-detail-grid"><section className="batch-detail"><h4>CONFUSION MATRIX</h4><div className="confusion-grid"><span>TRUE NEGATIVE</span><b>{matrix?.tn}</b><span>FALSE POSITIVE</span><b>{matrix?.fp}</b><span>FALSE NEGATIVE</span><b>{matrix?.fn}</b><span>TRUE POSITIVE</span><b>{matrix?.tp}</b></div><p>False-positive rate {pct(result.metrics.false_positive_rate)} · false-negative rate {pct(result.metrics.false_negative_rate)} · specificity {pct(result.metrics.specificity)}</p></section>
        <section className="batch-detail"><h4>ATTACK FAMILY RECALL</h4>{result.attack_families.length?<div className="family-list">{result.attack_families.map(family=><div key={family.label}><span>{family.label}</span><b>{pct(family.recall)}</b><small>{fmt(family.rows)} flows</small></div>)}</div>:<p>No attack-family rows found in this dataset.</p>}</section></div>
      <div className="batch-findings-head"><h4>PER-FLOW FINDINGS</h4><div className="batch-filter" role="group" aria-label="Filter findings">{([['all',`ALL ${result.rows}`],['false-positive',`FALSE POSITIVES ${matrix?.fp??0}`],['false-negative',`FALSE NEGATIVES ${matrix?.fn??0}`]] as const).map(([value,label])=><button type="button" key={value} aria-pressed={filter===value} className={filter===value?'active':''} onClick={()=>setFilter(value)}>{label}</button>)}</div></div>
      <div className="batch-table-wrap"><table className="batch-table"><thead><tr><th>ROW</th><th>SOURCE → DESTINATION</th><th>PROTO</th><th>ACTUAL</th><th>PREDICTED</th><th>PROBABILITY</th><th>RESULT</th></tr></thead><tbody>{filtered.slice(0,200).map(row=><tr key={row.row}><td>{row.row}</td><td className="mono">{row.src_ip||'—'} → {row.dst_ip||'—'}</td><td>{row.protocol||'—'}</td><td>{row.actual_label}</td><td>{row.predicted_label}</td><td>{pct(row.probability)}</td><td className={row.correct?'batch-correct':'batch-incorrect'}>{row.correct?'CORRECT':'ERROR'}</td></tr>)}</tbody></table>{filtered.length===0&&<div className="batch-no-results">No findings match this filter.</div>}</div>
      {filtered.length>200&&<p className="batch-truncation">Showing first 200 of {fmt(filtered.length)} matching rows. Exports include every evaluated flow.</p>}
    </section>}
  </div>;
}

function ScanReportView({report,onPrint,onDownload}:{report:ScanReport;onPrint:()=>void;onDownload:()=>void}){
  const threatClass=report.verdict==='DDoS'?'ddos':'benign';
  return <article className="report-panel" id="scan-report">
    <header className="report-top"><div><div className="eyebrow">DEFENSIVE FLOW ASSESSMENT</div><h2>Scan report</h2><span className="report-id-badge">{report.scan_id}</span><p className="report-timestamp">{new Date(report.timestamp).toLocaleString()}</p></div><div className="scan-actions report-actions"><button className="btn btn-print" type="button" onClick={onPrint}><Printer size={15}/> PRINT / SAVE PDF</button><button className="btn" type="button" onClick={onDownload}><Download size={15}/> JSON</button></div></header>
    <section className={`verdict-banner ${threatClass}`}><div className="verdict-left"><div className="verdict-icon">{report.verdict==='DDoS'?<ShieldAlert size={23}/>:<ShieldCheck size={23}/>}</div><div><h2>{report.verdict} · {report.threat_level}</h2><p>{report.attack_type}</p></div></div><div className="verdict-right"><strong>{report.risk_score}</strong><span>RISK SCORE / 100</span></div></section>
    <div className="report-metrics"><div><span>PROBABILITY</span><b>{pct(report.probability)}</b></div><div><span>CONFIDENCE</span><b>{pct(report.confidence)}</b></div><div><span>MODEL</span><b>{report.model_info.mode.toUpperCase()}</b></div><div><span>THRESHOLD</span><b>{pct(report.model_info.threshold)}</b></div></div>
    <section className="report-section"><h3>Assessment summary</h3><p className="summary-box">{report.summary}</p><p className="report-description">{report.attack_description}</p></section>
    <div className="report-subgrid">
      <section className="report-section"><h3>Observed flow</h3><dl className="report-details"><dt>Source</dt><dd>{report.target.src_ip}:{report.target.src_port}</dd><dt>Destination</dt><dd>{report.target.dst_ip}:{report.target.dst_port}</dd><dt>Protocol</dt><dd>{report.target.protocol}</dd><dt>Packets / second</dt><dd>{fmt(report.telemetry.packets_per_second)}</dd><dt>Bytes / second</dt><dd>{fmt(report.telemetry.bytes_per_second)}</dd><dt>Duration</dt><dd>{fmt(report.telemetry.flow_duration_ms)} ms</dd><dt>Forward / backward packets</dt><dd>{fmt(report.telemetry.total_fwd_packets)} / {fmt(report.telemetry.total_bwd_packets)}</dd><dt>Mean packet length</dt><dd>{fmt(report.telemetry.packet_length_mean)} bytes</dd></dl></section>
      <section className="report-section"><h3>Model provenance</h3><dl className="report-details"><dt>Version</dt><dd>{report.model_info.version}</dd><dt>Inference mode</dt><dd>{report.model_info.mode}</dd><dt>Decision threshold</dt><dd>{pct(report.model_info.threshold)}</dd><dt>Test ROC AUC</dt><dd>{report.model_info.roc_auc?.toFixed(4)??'Not available'}</dd><dt>Test F1 score</dt><dd>{report.model_info.f1_score?.toFixed(4)??'Not available'}</dd></dl></section>
    </div>
    <section className="report-section"><h3>Feature signals</h3>{report.signals.length?<table className="signal-table"><thead><tr><th>FEATURE</th><th>OBSERVED VALUE</th><th>IMPORTANCE</th></tr></thead><tbody>{report.signals.map(signal=><tr key={signal.feature}><td>{signal.feature}</td><td>{fmt(signal.value)}</td><td>{signal.importance.toFixed(5)}</td></tr>)}</tbody></table>:<p className="report-description">No feature-importance signals were returned for this scan.</p>}</section>
    {report.drift_analysis.length>0&&<section className="report-section"><h3>Baseline deviation</h3><table className="signal-table"><thead><tr><th>FEATURE</th><th>VALUE</th><th>BASELINE MEAN</th><th>Z-SCORE</th><th>STATUS</th></tr></thead><tbody>{report.drift_analysis.map(item=><tr key={item.feature}><td>{item.feature}</td><td>{fmt(item.value)}</td><td>{fmt(item.baseline_mean)}</td><td>{item.z_score.toFixed(2)}</td><td>{item.anomaly?'ANOMALOUS':'WITHIN RANGE'}</td></tr>)}</tbody></table></section>}
    <section className="report-section"><h3>Recommended response</h3><ol className="playbook-list">{report.recommendations.map((item,index)=><li className="playbook-item" key={`${index}-${item}`}><span>{String(index+1).padStart(2,'0')}</span>{item}</li>)}</ol></section>
    {report.verdict==='DDoS'&&<section className="report-section"><h3>Suggested firewall rules</h3><p className="report-description">Review and adapt these examples for your environment before applying them.</p><div className="firewall-grid">{Object.entries(report.firewall_rules).map(([platform,rule])=><div className="firewall-rule" key={platform}><h4>{platform}</h4><pre className="code-box"><code>{rule}</code></pre></div>)}</div></section>}
  </article>;
}
function OpsPanel({api}:{api:string}){const [s,setS]=useState<any>(null);const [sec,setSec]=useState<any>(null);useEffect(()=>{Promise.all([fetch(`${api}/api/stats`).then(r=>r.json()),fetch(`${api}/api/security`).then(r=>r.json())]).then(([a,b])=>{setS(a);setSec(b)}).catch(()=>{})},[api]);return <div className="page"><div className="page-intro"><div><div className="eyebrow">PLATFORM OPERATIONS</div><h2>System observability.</h2><p>Runtime health, stream state, drift and operator controls.</p></div></div><div className="ops-grid"><div className="panel big-panel"><PanelHead title="STREAM TELEMETRY" sub="REAL-TIME INGESTION" icon={Radio}/><div className="metric-grid">{[['RUNNING',String(s?.stream?.running??'—')],['SOURCE',s?.stream?.source||'synthetic'],['EVENTS',String(s?.stream?.events||0)],['DRIFT SAMPLES',String(s?.drift?.samples||0)],['ANOMALOUS',String(s?.drift?.anomalous_samples||0)],['ANOMALY RATE',s?.drift?.anomaly_rate?`${(s.drift.anomaly_rate*100).toFixed(2)}%`:'0.00%']].map(([a,b])=><div className="metric" key={a}><span>{a}</span><b>{b}</b></div>)}</div></div><div className="panel big-panel"><PanelHead title="SECURITY CONTROLS" sub="OPERATOR + OBSERVABILITY" icon={LockKeyhole}/><div className="metric-grid">{[['AUTHENTICATION',sec?.authentication||'loading'],['RATE LIMIT','ENABLED'],['PROMETHEUS','/metrics'],['DATABASE',s?.database||'configured'],['ALERT CORRELATION','TUPLE + OCCURRENCE'],['WEBSOCKET',connectedLabel(s)]].map(([a,b])=><div className="metric" key={a}><span>{a}</span><b>{b}</b></div>)}</div></div></div></div>}
function connectedLabel(s:any){return s?.stream?.running?'ACTIVE':'STANDBY'}
