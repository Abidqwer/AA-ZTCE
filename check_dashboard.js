// Dependency-free DOM-stub unit checks. These are not rendered-browser acceptance tests.
const fs=require('fs'),vm=require('vm'),path=require('path');
const root=__dirname;
const html=fs.readFileSync(path.join(root,'docs/soc/SOC_Correlation_Dashboard.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const rows=[...html.matchAll(/<tr>([\s\S]*?)<\/tr>/g)].slice(1).map(m=>({textContent:m[1].replace(/<[^>]+>/g,' '),hidden:false}));
const input={value:'',addEventListener(name,fn){this.listener=fn;}},count={},download={};let blob,clicked=false;
const sandbox={Blob,setTimeout(){},URL:{createObjectURL(value){blob=value;return 'blob:unit-check';},revokeObjectURL(){}},
 document:{querySelectorAll(){return rows;},querySelector(s){return s==='#q'?input:s==='#count'?count:download;},
 createElement(){return {click(){clicked=true;}};}}};
vm.createContext(sandbox);vm.runInContext(script,sandbox);
const all=rows.filter(r=>!r.hidden).length;
input.value='not-a-real-event';input.listener();const zero=rows.filter(r=>!r.hidden).length;
input.value='identity.risk-change';input.listener();const matches=rows.filter(r=>!r.hidden).length;
download.onclick();
(async()=>{const text=await blob.text();const exported=text.trim().split('\n').map(JSON.parse);
 const result={test_type:'DOM-stub unit checks; no browser rendering',all_rows:all,zero_filter:zero,
 correlated_rows:matches,download_clicked:clicked,exported_records:exported.length,
 browser_rendering:'NOT_RUN: browser binary unavailable; download blocked/truncated by environment'};
 fs.writeFileSync(path.join(root,'results/soc/dashboard_checks.json'),JSON.stringify(result,null,2));
 console.log(JSON.stringify(result));if(!all||zero!==0||matches===0||!clicked||exported.length!==all)process.exitCode=1;
})().catch(e=>{console.error(String(e));process.exitCode=1;});
