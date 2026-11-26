// Regression: render the actual shared UI functions with a minimal DOM.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const source=fs.readFileSync(path.join(__dirname,"../runner/appsecctl/webui/assets/app.js"),"utf8");
class Element {
  constructor(tag, css, value) {
    this.tag=tag; this.className=css||""; this.value=value==null?"—":String(value);
    this.children=[]; this.style={};
    this.classList={add:(c)=>{this.className+=" "+c;}};
  }
  appendChild(child){this.children.push(child);return child;}
}
const node=(tag,css,value)=>new Element(tag,css,value===undefined?"":value);
const text=v=>v==null||v===""?"—":String(v);
const context={node,text,date:text,prefix:""};
const helpers=source.slice(source.indexOf("  function section("),source.indexOf("  function detailsTable("));
const renderers=source.slice(source.indexOf("  function renderOptimizedSummary("),source.indexOf("  async function openPipeline("));
vm.createContext(context);
vm.runInContext(helpers+renderers,context);
function render(data){const root=node("div");context.renderUnifiedSummary(root,data);return root;}
function all(root,match){return [...(match(root)?[root]:[]),...root.children.flatMap(x=>all(x,match))];}
function values(root,css){return all(root,x=>x.className.split(" ").includes(css)).map(x=>x.value);}
const original={phase:"original",status:"success",id:"original",image_ref:"nginx:latest",critical_count:1,high_count:71,medium_count:127,low_count:180,unknown_count:73,evidence:{verified:true,image_id:"before",scope:"os,library"}};
const optimized={state:"completed",stage:"original",result:{comparison:"frozen_db",original_findings:452,overall_findings:352,overall_introduced:0,base_severity:{CRITICAL:1,HIGH:71,MEDIUM:127,LOW:180,UNKNOWN:73},candidate_severity:{CRITICAL:1,HIGH:63,MEDIUM:110,LOW:161,UNKNOWN:17},candidate:"local:optimized",candidate_image_id:"after",image_ids:["before","after"]}};
const root=render({scans:[original],patches:[],optimization:optimized});
assert.deepEqual(values(root,"phase-count"),["452","352"]);
assert.deepEqual(values(root,"phase-label"),["01 · INITIAL SCAN","02 · FINAL OPTIMIZED SCAN"]);
assert.equal(all(root,x=>x.value==="Not scanned yet · no result available").length,0);
assert.equal(all(root,x=>x.value.includes("No separate Copa patch or rescan was recorded")).length,1);
const zero=render({scans:[original],optimization:{...optimized,result:{...optimized.result,overall_findings:0}}});
assert.deepEqual(values(zero,"phase-count"),["452","0"]);
const unknown=render({scans:[original],optimization:{...optimized,result:{...optimized.result,overall_findings:null}}});
assert.deepEqual(values(unknown,"phase-count"),["452","—"]);
const patch={phase:"patched",status:"success",id:"patched",image_ref:"local:patch",critical_count:1,high_count:65,medium_count:120,low_count:170,unknown_count:40,evidence:{verified:true,image_id:"intermediate",scope:"os,library"}};
const combined=render({scans:[original,patch],patches:[{status:"success"}],optimization:optimized});
assert.deepEqual(values(combined,"phase-count"),["452","352","272","226"]);
assert.equal(all(combined,x=>x.tag==="details"&&x.children[0]?.value==="Intermediate Copa evidence (optional)").length,1);
const plain=render({scans:[original,patch],patches:[{status:"success"}]});
assert.deepEqual(values(plain,"phase-count"),["272","226"]);
const pending=render({scans:[original],optimization:{state:"building"}});
assert.deepEqual(values(pending,"phase-count"),["272","—"]);
console.log("Optimized final scan cards, zero/unknown counts and separate Copa evidence verified.");
