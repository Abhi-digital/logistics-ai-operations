const base='http://localhost:4000/api';
const assert=(c,m)=>{if(!c)throw new Error(m)};
async function req(path,opts={}){const r=await fetch(base+path,opts);let body={};try{body=await r.json()}catch{}return {status:r.status,body};}
async function login(username,password){const r=await req('/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})});assert(r.status===200,'login failed for '+username);return r.body.data;}
(async()=>{
 const bad=await req('/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:'wrong'})});assert(bad.status===401,'invalid login was not rejected');
 const admin=await login('admin','Admin@123'); const operator=await login('operator','Operator@123'); const viewer=await login('viewer','Viewer@123');
 const me=await req('/auth/me',{headers:{authorization:'Bearer '+admin.token}});assert(me.status===200&&me.body.data.role==='admin','admin me failed');
 const users=await req('/users',{headers:{authorization:'Bearer '+admin.token}});assert(users.status===200&&users.body.data.length>=3,'admin user list failed');
 const forbidden=await req('/simulation/delay',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+viewer.token},body:JSON.stringify({shipmentId:'SHP-IND-10403'})});assert(forbidden.status===403,'viewer operation was not blocked');
 const delay=await req('/simulation/delay',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+operator.token},body:JSON.stringify({shipmentId:'SHP-IND-10403'})});assert(delay.status===200&&delay.body.data.status==='Delayed','operator delay failed');
 const gen=await req('/notifications/generate',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+operator.token},body:JSON.stringify({shipmentId:'SHP-IND-10403'})});assert(gen.status===201&&gen.body.data.status==='Pending Approval','notification generation failed');
 const nid=gen.body.data.id;
 const sendEarly=await req('/notifications/'+nid+'/send',{method:'POST',headers:{authorization:'Bearer '+operator.token}});assert(sendEarly.status===409,'send-before-approval was not blocked');
 const approve=await req('/notifications/'+nid+'/approve',{method:'POST',headers:{authorization:'Bearer '+admin.token}});assert(approve.status===200&&approve.body.data.status==='Approved','approval failed');
 const send=await req('/notifications/'+nid+'/send',{method:'POST',headers:{authorization:'Bearer '+admin.token}});assert(send.status===200&&send.body.data.status==='Sent','send failed');
 const list=await req('/notifications');assert(list.status===200&&list.body.data.some(x=>x.id===nid&&x.status==='Sent'),'notification persistence failed');
 console.log(JSON.stringify({ok:true,invalidLogin:bad.status,roles:{admin:admin.user.role,operator:operator.user.role,viewer:viewer.user.role},viewerSimulation:forbidden.status,delay:delay.status,notificationId:nid,generate:gen.status,sendBeforeApproval:sendEarly.status,approve:approve.status,send:send.status,persisted:true,userCount:users.body.data.length},null,2));
})().catch(e=>{console.error(e.stack||e);process.exit(1)});