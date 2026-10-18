// DOM-stub functionality checks; no rendered-browser acceptance is claimed.
const fs=require('fs'),vm=require('vm'),path=require('path');
const root=__dirname,html=fs.readFileSync(path.join(root,'results/virtual_range/AA_ZTCE_Live_AI_Report.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes={};let blob,clicked=false;
function node(){return {value:'',children:[],innerHTML:'',textContent:'',appendChild(n){this.children.push(n)},addEventListener(type,fn){this[type]=fn},click(){clicked=true}}}
for(const id of ['cards','search','condition','cases','count','method','limits','footer','download'])nodes[id]=node();
const context={Blob,setTimeout(){},URL:{createObjectURL(b){blob=b;return 'blob:check'},revokeObjectURL(){}},document:{getElementById(id){return nodes[id]},createElement(){return node()}}};
vm.createContext(context);vm.runInContext(script,context);
const all=nodes.count.textContent;nodes.condition.value='assurance';nodes.condition.change();const selected=nodes.count.textContent;
nodes.search.value='not-a-real-case';nodes.search.input();const zero=nodes.count.textContent;
nodes.search.value='business';nodes.search.input();const filtered=nodes.count.textContent;
nodes.download.onclick();
(async()=>{const report=JSON.parse(await blob.text());const result={test_type:'DOM-stub functionality; browser rendering not performed',cards:nodes.cards.children.length,all_rows:all,assurance_rows:selected,empty_search:zero,business_search:filtered,download_clicked:clicked,downloaded_cases:report.cases.length};
if(result.cards!==3||all!==report.cases.length+' rows'||selected!==report.cases.filter(r=>r.condition==='assurance').length+' rows'||zero!=='0 rows'||filtered==='0 rows'||!clicked)throw Error('report interaction failure');
fs.writeFileSync(path.join(root,'results/virtual_range/report_checks.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));})().catch(e=>{console.error(e.message);process.exitCode=1});
