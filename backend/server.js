require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { z } = require('zod');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { query, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());
if(process.env.SERVE_FRONTEND==='true')app.use(express.static(path.join(__dirname,'../frontend/dist')));

/* Goal 7 + Goal 8: Authentication, RBAC and persistent PostgreSQL storage. */
const sessions=new Map();
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  return salt+':'+crypto.scryptSync(password,salt,64).toString('hex');
}
function verifyPassword(password,stored){
  const [salt,key]=String(stored).split(':'); if(!salt||!key)return false;
  const actual=crypto.scryptSync(password,salt,64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(key,'hex'));
}
function tokenFor(user){
  const payload=Buffer.from(JSON.stringify({sub:user.id,username:user.username,role:user.role,exp:Date.now()+8*60*60*1000})).toString('base64url');
  const secret=process.env.AUTH_SECRET||'routeiq-local-development-secret-change-me';
  const sig=crypto.createHmac('sha256',secret).update(payload).digest('base64url');
  const token=payload+'.'+sig; sessions.set(token,{...user,token}); return token;
}
function currentUser(req){
  const raw=req.headers.authorization||''; const token=raw.startsWith('Bearer ')?raw.slice(7):'';
  if(!token)return null;
  const [payload,sig]=token.split('.'); if(!payload||!sig)return null;
  const secret=process.env.AUTH_SECRET||'routeiq-local-development-secret-change-me';
  const expected=crypto.createHmac('sha256',secret).update(payload).digest('base64url');
  if(sig!==expected)return null;
  try{const data=JSON.parse(Buffer.from(payload,'base64url').toString());if(data.exp<Date.now())return null;return sessions.get(token)||data;}catch{return null;}
}
function requireRole(...roles){return (req,res,next)=>{if(!req.user)return res.status(401).json({error:'Authentication required'});if(roles.length&&!roles.includes(req.user.role))return res.status(403).json({error:'Insufficient permissions'});next();};}
async function recordDbAudit(action,actor,target,details={}){
  await query('INSERT INTO audit_events (id,action,actor,target,details,created_at) VALUES ($1,$2,$3,$4,$5,NOW())',[id('DBA'),action,actor,target||null,details]);
}
const seedUsers=[
  ['USR-ADMIN','admin','Abhishek','admin','Admin@123'],
  ['USR-OP','operator','Ravi Kumar','operator','Operator@123'],
  ['USR-VIEW','viewer','Sneha Rao','viewer','Viewer@123']
];
const operationsTeam=[
  ['TEAM-MORNING','Abhi','Morning Shift','Abhi128s'],
  ['TEAM-AFTERNOON','Harsha','Afternoon Shift','harsha128s'],
  ['TEAM-EVENING','Prasad','Evening Shift','prasad128s'],
  ['TEAM-NIGHT','Channu','Night Shift','channu128s']
];

app.use('/api',(req,res,next)=>{
  req.user=currentUser(req);
  if(req.method==='GET'||req.path==='/auth/login'||req.path==='/team/login')return next();
  if(!req.user)return res.status(401).json({error:'Authentication required'}); next();
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const username=String(req.body?.username||'').trim().toLowerCase(); const password=String(req.body?.password||'');
    const {rows}=await query('SELECT id,username,name,role,password_hash FROM users WHERE username=$1',[username]);
    const user=rows[0];
    if(!user||!verifyPassword(password,user.password_hash))return res.status(401).json({error:'Invalid username or password'});
    const safe={id:user.id,username:user.username,name:user.name,role:user.role}; const token=tokenFor(safe);
    await recordDbAudit('auth.login',safe.username,safe.id,{role:safe.role});
    res.json({data:{token,user:safe},message:'Login successful'});
  }catch(err){res.status(500).json({error:'Database error',detail:err.message});}
});
app.post('/api/auth/logout',async(req,res)=>{const token=(req.headers.authorization||'').replace(/^Bearer\s+/,'');const user=currentUser(req);if(token)sessions.delete(token);if(user)await recordDbAudit('auth.logout',user.username,user.id,{});res.json({message:'Logged out'});});
app.get('/api/auth/me',(req,res)=>{const user=currentUser(req);if(!user)return res.status(401).json({error:'Authentication required'});res.json({data:user});});
app.get('/api/team/members',async(_req,res)=>{const {rows}=await query('SELECT id,name,shift,active FROM operations_team ORDER BY CASE shift WHEN $1 THEN 1 WHEN $2 THEN 2 WHEN $3 THEN 3 WHEN $4 THEN 4 ELSE 5 END',["Morning Shift","Afternoon Shift","Evening Shift","Night Shift"]);res.json({data:rows});});
app.post('/api/team/login',async(req,res)=>{try{const memberId=String(req.body?.memberId||'').trim();const password=String(req.body?.password||'');const {rows}=await query('SELECT id,name,shift,active,password_hash FROM operations_team WHERE id=$1',[memberId]);const member=rows[0];if(!member||!member.active||!verifyPassword(password,member.password_hash))return res.status(401).json({error:'Invalid team member or password'});const safe={id:member.id,name:member.name,shift:member.shift,role:'operations-team'};const token=tokenFor({id:member.id,username:member.name.toLowerCase(),role:'operations-team'});await recordDbAudit('team.login',member.name,member.id,{shift:member.shift});res.json({data:{token,member:safe},message:'Operations Team login successful'});}catch(err){res.status(500).json({error:'Database error',detail:err.message});}});
app.get('/api/users',requireRole('admin'),async(_req,res)=>{const {rows}=await query('SELECT id,username,name,role,created_at as "createdAt" FROM users ORDER BY created_at');res.json({data:rows});});
app.post('/api/users',requireRole('admin'),async(req,res)=>{const username=String(req.body?.username||'').trim().toLowerCase();const name=String(req.body?.name||'').trim();const role=String(req.body?.role||'viewer');const password=String(req.body?.password||'');if(!username||!name||!password||!['admin','operator','viewer'].includes(role))return res.status(400).json({error:'username, name, password and valid role are required'});const existing=await query('SELECT id FROM users WHERE username=$1',[username]);if(existing.rows[0])return res.status(409).json({error:'Username already exists'});const uid=id('USR');await query('INSERT INTO users (id,username,name,role,password_hash,created_at) VALUES ($1,$2,$3,$4,$5,NOW())',[uid,username,name,role,hashPassword(password)]);await recordDbAudit('user.create',req.user.username,uid,{username,role});res.status(201).json({data:{id:uid,username,name,role},message:'User created'});});

const cities = ['Hyderabad','Bengaluru','Chennai','Mumbai','Pune','Delhi','Jaipur','Ahmedabad','Kolkata','Vijayawada','Nagpur','Kurnool'];
const carriers = ['SwiftRoute Logistics','Bharat Express','MetroFreight','SouthLine Logistics','BlueRoute Cargo'];
const statuses = ['Delivered','In Transit','Delayed','At Risk'];
const reasons = {
  Delayed:'Hub processing delay',
  'At Risk':'ETA trending beyond SLA',
  'In Transit':'Moving on planned route',
  Delivered:'Successfully delivered'
};

function now(){ return new Date().toISOString(); }
function id(prefix){ return prefix + '-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,7).toUpperCase(); }

function buildShipments(count=72){
  return Array.from({length:count},(_,i)=>{
    const origin=cities[i%cities.length];
    const destination=cities[(i*3+2)%cities.length];
    const status=statuses[i%4];
    const shipmentId=`SHP-IND-${String(10401+i).padStart(5,'0')}`;
    return {
      id:shipmentId, trackingId:shipmentId, origin, destination,
      currentLocation:status==='Delivered'?destination:cities[(i+4)%cities.length],
      carrier:carriers[i%carriers.length], status,
      eta:new Date(Date.now()+((i%12)+2)*3600000).toISOString(),
      sla:status==='Delayed'?'Breached':status==='At Risk'?'At Risk':'On Track',
      reason:reasons[status], priority:status==='Delayed'?'High':status==='At Risk'?'Medium':'Normal',
      updatedAt:new Date(Date.now()-(i%9)*3600000).toISOString(),
      timeline:[
        {label:'Order created',time:'08:10 AM',done:true},
        {label:'Picked up',time:'09:35 AM',done:true},
        {label:'Hub processing',time:'01:20 PM',done:true},
        {label:'Out for delivery',time:'04:40 PM',done:status==='Delivered'},
        {label:'Delivered',time:'06:15 PM',done:status==='Delivered'}
      ]
    };
  });
}

let shipments=[];
let exceptions=[];

async function persistShipment(s){
  await query(`INSERT INTO shipments
    (id,tracking_id,origin,destination,current_location,carrier,status,eta,sla,reason,priority,updated_at,timeline)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT (id) DO UPDATE SET
      tracking_id=EXCLUDED.tracking_id, origin=EXCLUDED.origin, destination=EXCLUDED.destination,
      current_location=EXCLUDED.current_location, carrier=EXCLUDED.carrier, status=EXCLUDED.status,
      eta=EXCLUDED.eta, sla=EXCLUDED.sla, reason=EXCLUDED.reason, priority=EXCLUDED.priority,
      updated_at=EXCLUDED.updated_at, timeline=EXCLUDED.timeline`,
    [s.id,s.trackingId,s.origin,s.destination,s.currentLocation,s.carrier,s.status,s.eta,s.sla,s.reason,s.priority,s.updatedAt,JSON.stringify(s.timeline)]);
}
async function loadShipments(){
  const {rows}=await query(`SELECT id,tracking_id AS "trackingId",origin,destination,current_location AS "currentLocation",
    carrier,status,eta,sla,reason,priority,updated_at AS "updatedAt",timeline FROM shipments ORDER BY id`);
  if(rows.length){shipments=rows.map(s=>({...s,eta:new Date(s.eta).toISOString(),updatedAt:new Date(s.updatedAt).toISOString()}));return;}
  shipments=buildShipments();
  for(const s of shipments)await persistShipment(s);
}
let operators=[
  {id:'OP-01',name:'Ravi Kumar',team:'Hyderabad Hub',active:true},
  {id:'OP-02',name:'Priya Sharma',team:'South Operations',active:true},
  {id:'OP-03',name:'Arjun Reddy',team:'Exception Desk',active:true},
  {id:'OP-04',name:'Sneha Rao',team:'Customer Operations',active:true}
];

let aiInsights=[];
let auditLog=[];
let activityLog=[];

function logActivity(type,message,meta={}){
  activityLog.unshift({id:id('ACT'),type,message,meta,timestamp:now()});
  activityLog=activityLog.slice(0,100);
}
function audit(action,actor,target,before,after,meta={}){
  auditLog.unshift({id:id('AUD'),action,actor,target,before,after,meta,timestamp:now()});
  auditLog=auditLog.slice(0,200);
}
function recommendationFor(s){
  if(s.status==='Delayed') return {
    action:'Reassign to an available route',
    detail:`Check ${s.carrier} capacity and move ${s.id} to the next available ${s.origin} → ${s.destination} service.`
  };
  if(s.status==='At Risk') return {
    action:'Investigate ETA risk',
    detail:'Review current hub processing and carrier capacity before the SLA threshold is crossed.'
  };
  return {action:'Continue monitoring',detail:'No immediate operator action is required.'};
}
function syncExceptions(){
  for(const s of shipments){
    if((s.status==='Delayed'||s.status==='At Risk')&&!exceptions.some(e=>e.shipmentId===s.id&&e.status!=='Resolved')){
      const rec=recommendationFor(s);
      const e={
        id:`EXC-${s.id.slice(-5)}`,shipmentId:s.id,type:s.status==='Delayed'?'Delay':'SLA Risk',
        priority:s.priority,reason:s.reason,impact:s.status==='Delayed'?'SLA breach likely':'Delivery may miss SLA',
        recommendedAction:rec.action,recommendationDetail:rec.detail,status:'Open',assignee:null,
        createdAt:now(),updatedAt:now()
      };
      exceptions.push(e);
      logActivity('exception.created',`New ${e.type} detected for ${s.id}`,{shipmentId:s.id,exceptionId:e.id});
    }
  }
}

function activeExceptions(){ syncExceptions(); return exceptions.filter(e=>e.status!=='Resolved'); }

function makeInsight(type,severity,title,explanation,recommendation,target,confidence=0.9,requiresApproval=true){
  const existing=aiInsights.find(x=>x.status==='Pending'&&x.type===type&&x.target?.key===target.key);
  if(existing) return existing;
  const insight={
    id:id('AI'),type,severity,title,explanation,recommendation,confidence,requiresApproval,
    status:'Pending',target,createdAt:now(),updatedAt:now()
  };
  aiInsights.unshift(insight);
  return insight;
}

function runAIAnalysis(){
  const active=activeExceptions();
  const generated=[];
  const delayed=shipments.filter(s=>s.status==='Delayed');
  const atRisk=shipments.filter(s=>s.status==='At Risk');

  if(delayed.length){
    generated.push(makeInsight(
      'sla_breach_cluster',delayed.length>=3?'High':'Medium',
      `${delayed.length} shipments are currently delayed`,
      'The monitoring engine found active shipment delays that can directly affect SLA performance.',
      'Prioritize the delayed shipments, review route capacity, and reassign critical loads where capacity is available.',
      {key:'delayed-shipments',kind:'shipment-cluster',count:delayed.length},
      Math.min(.98,.82+delayed.length*.01)
    ));
  }

  if(atRisk.length){
    generated.push(makeInsight(
      'sla_risk',atRisk.length>=10?'High':'Medium',
      `${atRisk.length} shipments are trending toward SLA risk`,
      'ETA signals indicate a group of shipments may miss their promised delivery window if current conditions continue.',
      'Investigate the highest-priority ETA risks before they become SLA breaches.',
      {key:'at-risk-shipments',kind:'shipment-cluster',count:atRisk.length},
      .91
    ));
  }

  const routeGroups=new Map();
  for(const s of shipments.filter(s=>s.status==='Delayed'||s.status==='At Risk')){
    const key=`${s.origin} → ${s.destination}`;
    const g=routeGroups.get(key)||{route:key,delayed:0,atRisk:0,shipments:[]};
    if(s.status==='Delayed')g.delayed++; else g.atRisk++;
    g.shipments.push(s.id); routeGroups.set(key,g);
  }
  for(const g of routeGroups.values()){
    if(g.delayed>=2){
      generated.push(makeInsight(
        'route_pattern',g.delayed>=3?'High':'Medium',
        `Repeated disruption on ${g.route}`,
        `${g.delayed} delayed shipments were detected on the same route, indicating a recurring operational bottleneck rather than a single shipment event.`,
        'Review hub handling and available carrier capacity for this route; consider rerouting the affected shipments.',
        {key:g.route,kind:'route',route:g.route,shipmentIds:g.shipments},
        .88
      ));
    }
  }

  const carrierGroups=new Map();
  for(const s of shipments.filter(s=>s.status==='Delayed')){
    const g=carrierGroups.get(s.carrier)||{carrier:s.carrier,count:0,shipments:[]};
    g.count++; g.shipments.push(s.id); carrierGroups.set(s.carrier,g);
  }
  for(const g of carrierGroups.values()){
    if(g.count>=3){
      generated.push(makeInsight(
        'carrier_pattern','High',
        `${g.carrier} has ${g.count} delayed shipments`,
        'Multiple active delays are associated with the same carrier in the current operating dataset.',
        'Review carrier capacity and departure performance before assigning additional urgent loads.',
        {key:g.carrier,kind:'carrier',carrier:g.carrier,shipmentIds:g.shipments},
        .86
      ));
    }
  }

  if(active.length>=5){
    generated.push(makeInsight(
      'exception_backlog',active.length>=20?'High':'Medium',
      `${active.length} active exceptions need operator attention`,
      'The exception queue has accumulated multiple unresolved operational issues.',
      'Assign open exceptions to available operators and resolve the highest-impact items first.',
      {key:'exception-backlog',kind:'exception-queue',count:active.length},
      .95
    ));
  }

  const pending=aiInsights.filter(x=>x.status==='Pending').length;
  logActivity('ai.analysis',`AI monitoring completed: ${pending} pending recommendations`,{generated:generated.length});
  return {insights:aiInsights.filter(x=>x.status==='Pending'),generatedCount:generated.length,analyzedAt:now()};
}

function findInsight(req,res){
  const insight=aiInsights.find(x=>x.id===req.params.id);
  if(!insight)return res.status(404).json({error:'AI insight not found'});
  return insight;
}

const querySchema=z.object({q:z.string().trim().optional(),status:z.string().optional()});

app.get('/',(_req,res)=>{if(process.env.SERVE_FRONTEND==='true'&&fs.existsSync(path.join(__dirname,'../frontend/dist/index.html'))){return res.sendFile(path.join(__dirname,'../frontend/dist/index.html'));}res.json({ok:true,service:'logistics-api',message:'RouteIQ Logistics API is running'});});
app.get('/api/health',(_req,res)=>res.json({ok:true,service:'logistics-api',timestamp:now()}));

app.get('/api/shipments',(req,res)=>{
  const p=querySchema.safeParse(req.query);
  if(!p.success)return res.status(400).json({error:'Invalid query'});
  let result=shipments,q=p.data.q?.toLowerCase();
  if(q)result=result.filter(s=>[s.id,s.origin,s.destination,s.currentLocation,s.carrier].some(v=>v.toLowerCase().includes(q)));
  if(p.data.status&&p.data.status!=='All')result=result.filter(s=>s.status===p.data.status);
  res.json({data:result,total:result.length});
});
app.get('/api/shipments/:id',(req,res)=>{
  const s=shipments.find(x=>x.id.toLowerCase()===req.params.id.toLowerCase());
  if(!s)return res.status(404).json({error:'Shipment not found'});
  res.json({data:s});
});
app.get('/api/dashboard',(_req,res)=>{
  const total=shipments.length,delivered=shipments.filter(s=>s.status==='Delivered').length,
    delayed=shipments.filter(s=>s.status==='Delayed').length,atRisk=shipments.filter(s=>s.status==='At Risk').length,
    inTransit=shipments.filter(s=>s.status==='In Transit').length;
  res.json({data:{total,delivered,delayed,atRisk,inTransit,sla:Math.round(((total-delayed)/total)*1000)/10}});
});
app.get('/api/exceptions',(req,res)=>{
  let data=activeExceptions();
  if(req.query.status&&req.query.status!=='All')data=data.filter(e=>e.status===req.query.status);
  res.json({data,total:data.length});
});
app.get('/api/operators',(_req,res)=>res.json({data:operators}));

app.post('/api/exceptions/:id/assign',requireRole('admin','operator'),(req,res)=>{
  const e=exceptions.find(x=>x.id===req.params.id);
  if(!e)return res.status(404).json({error:'Exception not found'});
  if(e.status==='Resolved')return res.status(409).json({error:'Exception is already resolved'});
  const op=operators.find(x=>x.id===req.body?.operatorId);
  if(!op)return res.status(400).json({error:'Operator not found'});
  const before={status:e.status,assignee:e.assignee};
  e.assignee=op;e.status='Investigating';e.updatedAt=now();
  audit('exception.assign',op.name,e.id,before,{status:e.status,assignee:e.assignee},{shipmentId:e.shipmentId});
  logActivity('exception.assigned',`${e.id} assigned to ${op.name}`,{exceptionId:e.id,operatorId:op.id});
  res.json({data:e,message:`Assigned to ${op.name}`});
});
app.post('/api/exceptions/:id/investigate',requireRole('admin','operator'),(req,res)=>{
  const e=exceptions.find(x=>x.id===req.params.id);
  if(!e)return res.status(404).json({error:'Exception not found'});
  if(e.status==='Resolved')return res.status(409).json({error:'Exception is already resolved'});
  const before={status:e.status};
  e.status='Investigating';e.updatedAt=now();
  audit('exception.investigate','operator',e.id,before,{status:e.status},{shipmentId:e.shipmentId});
  logActivity('exception.investigating',`Investigation started for ${e.id}`,{exceptionId:e.id});
  res.json({data:e,message:'Investigation started'});
});
app.post('/api/exceptions/:id/resolve',requireRole('admin','operator'),async(req,res)=>{
  const e=exceptions.find(x=>x.id===req.params.id);
  if(!e)return res.status(404).json({error:'Exception not found'});
  if(e.status==='Resolved')return res.status(409).json({error:'Exception is already resolved'});
  const s=shipments.find(x=>x.id===e.shipmentId);
  const before={exceptionStatus:e.status,shipmentStatus:s?.status,shipmentSla:s?.sla};
  if(s){s.status='In Transit';s.sla='On Track';s.priority='Normal';s.reason='Exception resolved by operations';s.updatedAt=now();await persistShipment(s);}
  e.status='Resolved';e.updatedAt=now();
  audit('exception.resolve','operator',e.id,before,{exceptionStatus:e.status,shipmentStatus:s?.status,shipmentSla:s?.sla},{shipmentId:e.shipmentId});
  logActivity('exception.resolved',`Exception ${e.id} resolved`,{exceptionId:e.id,shipmentId:e.shipmentId});
  res.json({data:e,message:'Exception resolved successfully',shipment:s});
});

app.post('/api/simulation/delay',requireRole('admin','operator'),async(req,res)=>{
  const s=shipments.find(x=>x.id===req.body?.shipmentId)||shipments.find(x=>x.status==='In Transit');
  if(!s)return res.status(404).json({error:'No shipment available'});
  const before={status:s.status,sla:s.sla,priority:s.priority};
  s.status='Delayed';s.sla='Breached';s.priority='High';s.reason='Simulated vehicle departure delay';s.updatedAt=now();
  await persistShipment(s);
  syncExceptions();
  audit('simulation.delay','demo',s.id,before,{status:s.status,sla:s.sla,priority:s.priority},{shipmentId:s.id});
  logActivity('shipment.delayed',`Demo delay simulated for ${s.id}`,{shipmentId:s.id});
  res.json({data:s,message:'Shipment delay simulated successfully'});
});
app.post('/api/simulation/deliver',requireRole('admin','operator'),async(req,res)=>{
  const s=shipments.find(x=>x.id===req.body?.shipmentId)||shipments.find(x=>x.status!=='Delivered');
  if(!s)return res.status(404).json({error:'No shipment available'});
  const before={status:s.status,sla:s.sla};
  s.status='Delivered';s.sla='On Track';s.priority='Normal';s.currentLocation=s.destination;s.reason='Successfully delivered';s.updatedAt=now();
  await persistShipment(s);
  audit('simulation.deliver','demo',s.id,before,{status:s.status,sla:s.sla},{shipmentId:s.id});
  logActivity('shipment.delivered',`Demo delivery completed for ${s.id}`,{shipmentId:s.id});
  res.json({data:s,message:'Shipment delivered successfully'});
});

/* Goal 3: AI Operations Agent */
app.get('/api/ai/status',(_req,res)=>{
  const active=activeExceptions();
  res.json({
    data:{
      agent:'RouteIQ Operations Agent',
      status:'Monitoring',
      mode:'deterministic-analysis',
      monitoredShipments:shipments.length,
      activeExceptions:active.length,
      pendingInsights:aiInsights.filter(x=>x.status==='Pending').length,
      lastAnalysis:aiInsights[0]?.updatedAt||null
    }
  });
});
app.get('/api/ai/insights',(req,res)=>{
  const run=req.query.refresh==='true'?runAIAnalysis():{insights:aiInsights.filter(x=>x.status==='Pending'),generatedCount:0,analyzedAt:null};
  const data=aiInsights.filter(x=>!req.query.status||x.status===req.query.status);
  res.json({data,total:data.length,analysis:run});
});
app.post('/api/ai/analyze',requireRole('admin','operator'),(_req,res)=>{
  const result=runAIAnalysis();
  res.json({data:result,message:`AI analysis completed with ${result.insights.length} pending insights`});
});
app.get('/api/ai/insights/:id',(req,res)=>{
  const insight=findInsight(req,res); if(!insight)return;
  res.json({data:insight});
});
app.post('/api/ai/insights/:id/approve',requireRole('admin','operator'),(req,res)=>{
  const insight=findInsight(req,res); if(!insight)return;
  if(insight.status!=='Pending')return res.status(409).json({error:`Insight is already ${insight.status}`});
  insight.status='Approved';insight.approvedBy=req.body?.approvedBy||'operator';insight.updatedAt=now();
  audit('ai.approve',insight.approvedBy,insight.id,{status:'Pending'},{status:'Approved'},{type:insight.type,target:insight.target});
  logActivity('ai.approved',`AI recommendation approved: ${insight.title}`,{insightId:insight.id});
  res.json({data:insight,message:'AI recommendation approved'});
});
app.post('/api/ai/insights/:id/reject',requireRole('admin','operator'),(req,res)=>{
  const insight=findInsight(req,res); if(!insight)return;
  if(insight.status!=='Pending')return res.status(409).json({error:`Insight is already ${insight.status}`});
  insight.status='Rejected';insight.rejectedBy=req.body?.rejectedBy||'operator';insight.updatedAt=now();
  audit('ai.reject',insight.rejectedBy,insight.id,{status:'Pending'},{status:'Rejected'},{type:insight.type,target:insight.target});
  logActivity('ai.rejected',`AI recommendation rejected: ${insight.title}`,{insightId:insight.id});
  res.json({data:insight,message:'AI recommendation rejected'});
});
app.post('/api/ai/insights/:id/execute',requireRole('admin','operator'),(req,res)=>{
  const insight=findInsight(req,res); if(!insight)return;
  if(insight.status!=='Approved')return res.status(409).json({error:'Insight must be approved before execution'});
  const target=insight.target||{};
  const before={};
  let action='monitor';

  if(insight.type==='sla_breach_cluster'||insight.type==='sla_risk'){
    action='prioritize_exception_queue';
    const active=activeExceptions();
    const candidates=active.filter(e=>target.kind==='shipment-cluster'?target.count>=0:true).slice(0,5);
    candidates.forEach(e=>{if(e.status==='Open')e.status='Investigating';e.updatedAt=now();});
  } else if(insight.type==='route_pattern'){
    action='flag_route_for_review';
  } else if(insight.type==='carrier_pattern'){
    action='flag_carrier_for_review';
  } else if(insight.type==='exception_backlog'){
    action='prioritize_exception_queue';
  }

  insight.status='Executed';insight.executedBy=req.body?.executedBy||'operator';insight.updatedAt=now();
  audit('ai.execute',insight.executedBy,insight.id,before,{status:'Executed',action},{type:insight.type,target});
  logActivity('ai.executed',`AI action executed: ${insight.title}`,{insightId:insight.id,action});
  res.json({data:insight,action,message:'AI action executed successfully'});
});

app.get('/api/operations/activity',(req,res)=>{
  const limit=Math.min(Math.max(Number(req.query.limit)||20,1),100);
  res.json({data:activityLog.slice(0,limit),total:activityLog.length});
});
app.get('/api/audit',(req,res)=>{
  const limit=Math.min(Math.max(Number(req.query.limit)||50,1),200);
  res.json({data:auditLog.slice(0,limit),total:auditLog.length});
});

/* Goal 5: Customer Tracking + Analytics */
app.get('/api/tracking/:trackingId',(req,res)=>{
  const trackingId=String(req.params.trackingId||'').trim().toLowerCase();
  const s=shipments.find(x=>x.trackingId.toLowerCase()===trackingId||x.id.toLowerCase()===trackingId);
  if(!s)return res.status(404).json({error:'Tracking ID not found'});
  const statusCopy={
    Delivered:'Shipment delivered successfully',
    Delayed:'Shipment is delayed and our operations team is investigating',
    'At Risk':'Shipment is moving but may miss the promised SLA',
    'In Transit':'Shipment is moving on the planned route'
  };
  res.json({data:{trackingId:s.trackingId,shipmentId:s.id,origin:s.origin,destination:s.destination,currentLocation:s.currentLocation,carrier:s.carrier,status:s.status,statusMessage:statusCopy[s.status],eta:s.eta,sla:s.sla,reason:s.reason,updatedAt:s.updatedAt,timeline:s.timeline}});
});

app.get('/api/analytics',(req,res)=>{
  const total=shipments.length;
  const statusCounts=Object.fromEntries(statuses.map(status=>[status,shipments.filter(s=>s.status===status).length]));
  const carrierMap=new Map(), routeMap=new Map(), reasonMap=new Map();
  for(const s of shipments){
    const c=carrierMap.get(s.carrier)||{carrier:s.carrier,total:0,delivered:0,delayed:0,atRisk:0};
    c.total++; if(s.status==='Delivered')c.delivered++; if(s.status==='Delayed')c.delayed++; if(s.status==='At Risk')c.atRisk++; carrierMap.set(s.carrier,c);
    const routeKey=s.origin+' → '+s.destination; const r=routeMap.get(routeKey)||{route:routeKey,total:0,delayed:0,atRisk:0};
    r.total++; if(s.status==='Delayed')r.delayed++; if(s.status==='At Risk')r.atRisk++; routeMap.set(routeKey,r);
    if(s.status==='Delayed'||s.status==='At Risk')reasonMap.set(s.reason,(reasonMap.get(s.reason)||0)+1);
  }
  const carrierPerformance=[...carrierMap.values()].map(c=>({...c,deliveryRate:c.total?Math.round(c.delivered/c.total*100):0,issueRate:c.total?Math.round((c.delayed+c.atRisk)/c.total*100):0})).sort((a,b)=>b.deliveryRate-a.deliveryRate);
  const routePerformance=[...routeMap.values()].sort((a,b)=>(b.delayed+b.atRisk)-(a.delayed+a.atRisk)).slice(0,10);
  const delayReasons=[...reasonMap.entries()].map(([reason,count])=>({reason,count})).sort((a,b)=>b.count-a.count);
  const sla=total?Math.round((total-statusCounts.Delayed)/total*1000)/10:0;
  res.json({data:{total,sla,statuses:statusCounts,carrierPerformance,routePerformance,delayReasons,generatedAt:now()}});
});


/* Goal 6: AI-assisted customer communication with human approval. */
function customerProfile(shipment){
  const names=['Ananya','Rahul','Meera','Karthik','Priyanka','Vikram','Nisha','Arjun'];
  const idx=Math.abs(Number(String(shipment.id).slice(-2)))%names.length;
  return {name:names[idx]+' Customer',contact:'customer+'+shipment.id.toLowerCase()+'@demo.routeiq.local'};
}
function generateCustomerMessage(s){
  const p=customerProfile(s);
  if(s.status==='Delayed')return {subject:'Update on your shipment '+s.id,message:'Hello '+p.name+', your shipment '+s.id+' from '+s.origin+' to '+s.destination+' is delayed due to '+s.reason.toLowerCase()+'. Our operations team is investigating the issue. The latest ETA is '+new Date(s.eta).toLocaleString()+'. We will keep you updated.'};
  if(s.status==='At Risk')return {subject:'Your shipment may arrive later than planned',message:'Hello '+p.name+', your shipment '+s.id+' is currently moving from '+s.origin+' to '+s.destination+', but it may miss the promised SLA. Our operations team is monitoring the route and will provide an updated ETA if needed.'};
  return {subject:'Shipment update for '+s.id,message:'Hello '+p.name+', your shipment '+s.id+' is currently '+s.status.toLowerCase()+'. Current location: '+s.currentLocation+'. Thank you for choosing RouteIQ.'};
}
app.get('/api/notifications',async(req,res)=>{
  const {rows}=await query('SELECT id,shipment_id AS "shipmentId",channel,customer_name AS "customerName",customer_contact AS "customerContact",subject,message,status,created_by AS "createdBy",approved_by AS "approvedBy",sent_by AS "sentBy",created_at AS "createdAt",updated_at AS "updatedAt",sent_at AS "sentAt" FROM notifications ORDER BY created_at DESC LIMIT 100');
  res.json({data:rows,total:rows.length});
});
app.post('/api/notifications/generate',requireRole('admin','operator'),async(req,res)=>{
  const s=shipments.find(x=>x.id===String(req.body?.shipmentId||'')); if(!s)return res.status(404).json({error:'Shipment not found'});
  if(s.status!=='Delayed'&&s.status!=='At Risk')return res.status(400).json({error:'Customer notification is only generated for delayed or at-risk shipments'});
  const p=customerProfile(s), copy=generateCustomerMessage(s), nid=id('NTF');
  await query('INSERT INTO notifications (id,shipment_id,channel,customer_name,customer_contact,subject,message,status,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())',[nid,s.id,'Demo Message',p.name,p.contact,copy.subject,copy.message,'Pending Approval',req.user.username]);
  await recordDbAudit('notification.generate',req.user.username,nid,{shipmentId:s.id});
  logActivity('notification.drafted','AI customer message drafted for '+s.id,{notificationId:nid,shipmentId:s.id});
  res.status(201).json({data:{id:nid,shipmentId:s.id,status:'Pending Approval',subject:copy.subject,message:copy.message},message:'AI customer message generated and queued for human approval'});
});
app.post('/api/notifications/:id/approve',requireRole('admin','operator'),async(req,res)=>{
  const {rows}=await query('SELECT * FROM notifications WHERE id=$1',[req.params.id]); const n=rows[0]; if(!n)return res.status(404).json({error:'Notification not found'});
  if(n.status!=='Pending Approval')return res.status(409).json({error:'Notification is already '+n.status});
  await query('UPDATE notifications SET status=$1,approved_by=$2,updated_at=NOW() WHERE id=$3',['Approved',req.user.username,n.id]);
  await recordDbAudit('notification.approve',req.user.username,n.id,{shipmentId:n.shipment_id});
  logActivity('notification.approved','Customer message approved for '+n.shipment_id,{notificationId:n.id});
  res.json({message:'Customer message approved',data:{...n,status:'Approved',approved_by:req.user.username}});
});
app.post('/api/notifications/:id/reject',requireRole('admin','operator'),async(req,res)=>{
  const {rows}=await query('SELECT * FROM notifications WHERE id=$1',[req.params.id]); const n=rows[0]; if(!n)return res.status(404).json({error:'Notification not found'});
  if(n.status!=='Pending Approval')return res.status(409).json({error:'Notification is already '+n.status});
  await query('UPDATE notifications SET status=$1,updated_at=NOW() WHERE id=$2',['Rejected',n.id]);
  await recordDbAudit('notification.reject',req.user.username,n.id,{shipmentId:n.shipment_id});
  logActivity('notification.rejected','Customer message rejected for '+n.shipment_id,{notificationId:n.id});
  res.json({message:'Customer message rejected'});
});
app.post('/api/notifications/:id/send',requireRole('admin','operator'),async(req,res)=>{
  const {rows}=await query('SELECT * FROM notifications WHERE id=$1',[req.params.id]); const n=rows[0]; if(!n)return res.status(404).json({error:'Notification not found'});
  if(n.status!=='Approved')return res.status(409).json({error:'Notification must be approved before sending'});
  const sent=now(); await query('UPDATE notifications SET status=$1,sent_by=$2,sent_at=$3,updated_at=$3 WHERE id=$4',['Sent',req.user.username,sent,n.id]);
  await recordDbAudit('notification.send',req.user.username,n.id,{shipmentId:n.shipment_id,channel:n.channel});
  logActivity('notification.sent','Customer notification sent for '+n.shipment_id,{notificationId:n.id,channel:n.channel});
  res.json({message:'Notification sent (demo)',data:{id:n.id,status:'Sent',sentAt:sent}});
});
app.get('/api/permissions',(req,res)=>{const permissions={admin:['view','operate','approve_ai','send_notifications','manage_users','view_audit'],operator:['view','operate','approve_ai','send_notifications','view_audit'],viewer:['view']};res.json({data:{role:req.user?.role||'public',permissions:permissions[req.user?.role]||[]}});});

async function bootstrap(){
  await initDb();
  for(const [uid,username,name,role,password] of seedUsers){
    const existing=await query('SELECT id FROM users WHERE username=$1',[username]);
    if(!existing.rows[0]){
      await query('INSERT INTO users (id,username,name,role,password_hash,created_at) VALUES ($1,$2,$3,$4,$5,NOW())',[uid,username,name,role,hashPassword(password)]);
    }
  }
  for(const [tid,name,shift,password] of operationsTeam){
    const existing=await query('SELECT id FROM operations_team WHERE id=$1',[tid]);
    if(!existing.rows[0])await query('INSERT INTO operations_team (id,name,shift,password_hash,active,created_at) VALUES ($1,$2,$3,$4,TRUE,NOW())',[tid,name,shift,hashPassword(password)]);
  }
  await loadShipments();
  syncExceptions();
  runAIAnalysis();
  app.listen(PORT,()=>console.log(`Logistics API running on http://localhost:${PORT} (PostgreSQL)`));
}
bootstrap().catch(err=>{console.error('Failed to start RouteIQ:',err);process.exit(1);});
