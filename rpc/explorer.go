package rpc

import (
	"fmt"
	"net/http"
)

// ExplorerHandler serves the built-in block explorer web UI.
func ExplorerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, explorerHTML)
	}
}

var explorerHTML = explorerCSS + explorerBody + explorerJS + `</body></html>`

var explorerCSS = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Boson Infinity Explorer</title><style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#030712;color:#e5e7eb}
a{color:#38bdf8;text-decoration:none}a:hover{text-decoration:underline}
.top{background:linear-gradient(135deg,#0c4a6e,#020617);padding:16px 24px;border-bottom:1px solid #1e3a5f;display:flex;align-items:center;gap:16px}
.top h1{font-size:18px;color:#38bdf8;letter-spacing:.15em;text-transform:uppercase}
.nav{display:flex;gap:8px;margin-left:auto}.nav button{background:none;border:1px solid #1e3a5f;color:#94a3b8;padding:6px 14px;border-radius:8px;cursor:pointer;font-size:12px}
.nav button.act,.nav button:hover{border-color:#38bdf8;color:#e0f2fe}
.w{max-width:1100px;margin:0 auto;padding:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:20px}
.st{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:12px}.st .l{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em}.st .v{font-size:18px;font-weight:600;color:#f9fafb;margin-top:2px}.st .v.b{color:#38bdf8}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;padding:7px 8px;color:#6b7280;border-bottom:1px solid #1f2937;font-size:10px;text-transform:uppercase}
td{padding:7px 8px;border-bottom:1px solid #111827}tr:hover td{background:#0f172a}
.m{font-family:ui-monospace,monospace;font-size:11px}.hh{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block}
.bg{display:inline-block;padding:2px 7px;border-radius:99px;font-size:10px;font-weight:600}.bg.ok{background:#064e3b;color:#6ee7b7;border:1px solid #065f46}.bg.pd{background:#78350f;color:#fbbf24}
.sr{display:flex;gap:8px;margin-bottom:14px}.sr input{flex:1;padding:8px 12px;border-radius:10px;border:1px solid #1f2937;background:#0f172a;color:#e5e7eb;font-size:13px}.sr input:focus{outline:none;border-color:#38bdf8}
.sr button{padding:8px 18px;border-radius:10px;border:1px solid #38bdf8;background:#0c4a6e;color:#e0f2fe;cursor:pointer}
.dt{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:14px;margin-bottom:14px}.dt h3{font-size:13px;color:#38bdf8;margin-bottom:8px}
.dt .r{display:flex;gap:8px;padding:3px 0;font-size:12px}.dt .r .k{color:#6b7280;min-width:130px}
.pg{display:flex;gap:8px;justify-content:center;margin-top:14px}.pg button{padding:5px 12px;border-radius:8px;border:1px solid #1f2937;background:#111827;color:#94a3b8;cursor:pointer;font-size:12px}
.pg button:hover{border-color:#38bdf8;color:#e0f2fe}.pg button:disabled{opacity:.3}
#c{min-height:300px}.ld{text-align:center;padding:40px;color:#6b7280}
</style></head><body>`

var explorerBody = `
<div class="top"><h1>Boson Explorer</h1><div class="nav">
<button onclick="P('d')" id="nd" class="act">Dashboard</button>
<button onclick="P('b')" id="nb">Blocks</button>
<button onclick="P('s')" id="ns">Search</button>
</div></div><div class="w"><div id="c"><div class="ld">Loading...</div></div></div>`

var explorerJS = `<script>
const A=window.location.origin;let cp='d',bo=0;
async function F(p){return(await fetch(A+p)).json()}
function $(i){return document.getElementById(i)}
function H(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function S(s,n){return s&&s.length>n?s.slice(0,n)+'...':s}
function T(t){return new Date(t).toLocaleString()}
function C(a){return(a/1e8).toFixed(8).replace(/\.?0+$/,'')}
function P(p){cp=p;document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('act'));$('n'+p).classList.add('act');
if(p==='d')D();else if(p==='b'){bo=0;B()}else SR()}

async function D(){$('c').innerHTML='<div class="ld">Loading...</div>';
var s=await F('/stats'),h=await F('/health');
$('c').innerHTML='<div class="stats">'
+'<div class="st"><div class="l">Height</div><div class="v b">'+s.height+'</div></div>'
+'<div class="st"><div class="l">Difficulty</div><div class="v">'+s.difficulty_bits+' bits</div></div>'
+'<div class="st"><div class="l">Block Time</div><div class="v">'+(s.avg_block_seconds?.toFixed(1)||'-')+'s</div></div>'
+'<div class="st"><div class="l">Hashrate</div><div class="v b">'+(s.est_network_pretty||'-')+'</div></div>'
+'<div class="st"><div class="l">Minted</div><div class="v">'+(s.total_minted?.toFixed(2)||0)+' BOS</div></div>'
+'<div class="st"><div class="l">Supply</div><div class="v">'+(s.max_supply?.toFixed(0)||0)+' BOS</div></div>'
+'<div class="st"><div class="l">Mempool</div><div class="v">'+(h.mempool||0)+'</div></div>'
+'<div class="st"><div class="l">Accounts</div><div class="v">'+(h.accounts||0)+'</div></div>'
+(s.cost_per_coin>0?'<div class="st"><div class="l">Cost/Coin</div><div class="v b">'+s.cost_per_coin?.toFixed(4)+' '+s.fiat_currency+'</div></div>':'')
+'</div><h3 style="margin:14px 0 8px;color:#94a3b8;font-size:12px">Latest Blocks</h3><div id="lb"><div class="ld">...</div></div>';
var c=await F('/chain?from='+Math.max(0,s.height-9)+'&limit=10');BT((c.blocks||[]).reverse(),'lb')}

function BT(bl,id){if(!bl.length){$(id).innerHTML='<p style="color:#6b7280">No blocks</p>';return}
$(id).innerHTML='<table><tr><th>Height</th><th>Hash</th><th>Miner</th><th>TXs</th><th>Diff</th><th>Time</th></tr>'
+bl.map(b=>'<tr><td><a href="#" onclick="VB('+b.header.height+');return false">'+b.header.height+'</a></td>'
+'<td class="m"><span class="hh">'+H(b.hash)+'</span></td>'
+'<td class="m"><a href="#" onclick="VA(\''+b.header.miner+'\');return false">'+S(b.header.miner,10)+'</a></td>'
+'<td>'+(b.txs?.length||0)+'</td><td>'+b.header.difficulty+'</td><td>'+T(b.header.timestamp)+'</td></tr>').join('')+'</table>'}

async function B(){$('c').innerHTML='<div class="ld">Loading...</div>';var s=await F('/stats');
var fr=Math.max(0,s.height-bo-19),c=await F('/chain?from='+fr+'&limit=20');
var bl=(c.blocks||[]).reverse();$('c').innerHTML='<h3 style="margin-bottom:10px;color:#94a3b8;font-size:12px">All Blocks</h3><div id="bt"></div>'
+'<div class="pg"><button onclick="bo+=20;B()" '+(fr<=0?'disabled':'')+'>Older</button>'
+'<button onclick="bo=Math.max(0,bo-20);B()" '+(bo<=0?'disabled':'')+'>Newer</button></div>';BT(bl,'bt')}

function SR(){$('c').innerHTML='<div class="sr"><input id="q" placeholder="Block height, TX hash, or address (40 hex)" onkeydown="if(event.key===\'Enter\')DS()"><button onclick="DS()">Search</button></div><div id="res"></div>'}
function DS(){var q=$('q').value.trim();if(!q)return;if(/^\d+$/.test(q))VB(+q);else if(/^[0-9a-fA-F]{40}$/.test(q))VA(q);else VT(q)}

async function VB(h){$('c').innerHTML='<div class="ld">Loading block...</div>';
try{var b=await F('/block?height='+h);if(b.error){$('c').innerHTML='<p style="color:#f87171">Not found</p>';return}
var tx='';if(b.txs?.length){tx='<h3 style="margin:10px 0 6px;color:#94a3b8;font-size:12px">Transactions</h3><table><tr><th>Hash</th><th>From</th><th>To</th><th>Amount</th><th>Fee</th></tr>'
+b.txs.map(t=>'<tr><td class="m"><a href="#" onclick="VT(\''+t.hash+'\');return false">'+S(t.hash,16)+'</a></td>'
+'<td class="m"><a href="#" onclick="VA(\''+t.from+'\');return false">'+S(t.from,10)+'</a></td>'
+'<td class="m"><a href="#" onclick="VA(\''+t.to+'\');return false">'+S(t.to,10)+'</a></td>'
+'<td>'+C(t.amount)+'</td><td>'+C(t.fee)+'</td></tr>').join('')+'</table>'}
$('c').innerHTML='<div class="dt"><h3>Block #'+b.header.height+'</h3>'
+'<div class="r"><span class="k">Hash</span><span class="m">'+H(b.hash)+'</span></div>'
+'<div class="r"><span class="k">Prev Hash</span><span class="m">'+S(H(b.header.prev_hash),40)+'</span></div>'
+'<div class="r"><span class="k">Miner</span><span class="m"><a href="#" onclick="VA(\''+b.header.miner+'\');return false">'+b.header.miner+'</a></span></div>'
+'<div class="r"><span class="k">Time</span><span>'+T(b.header.timestamp)+'</span></div>'
+'<div class="r"><span class="k">Difficulty</span><span>'+b.header.difficulty+' bits</span></div>'
+'<div class="r"><span class="k">Nonce</span><span class="m">'+b.header.nonce+'</span></div>'
+'<div class="r"><span class="k">TXs</span><span>'+(b.txs?.length||0)+'</span></div></div>'
+tx+'<div class="pg"><button onclick="VB('+(b.header.height-1)+')" '+(b.header.height<=0?'disabled':'')+'>Prev</button><button onclick="VB('+(b.header.height+1)+')">Next</button></div>'
}catch(e){$('c').innerHTML='<p style="color:#f87171">Error</p>'}}

async function VA(a){$('c').innerHTML='<div class="ld">Loading...</div>';
try{var[ac,tx]=await Promise.all([F('/account?addr='+a),F('/address/txs?addr='+a+'&limit=50')]);
var tbl='';if(tx.txs?.length){tbl='<h3 style="margin:10px 0 6px;color:#94a3b8;font-size:12px">Transactions ('+tx.count+')</h3><table><tr><th>Hash</th><th>From</th><th>To</th><th>Amount</th><th>Block</th></tr>'
+tx.txs.map(t=>'<tr><td class="m"><a href="#" onclick="VT(\''+t.tx.hash+'\');return false">'+S(t.tx.hash,16)+'</a></td>'
+'<td class="m">'+S(t.tx.from,10)+'</td><td class="m">'+S(t.tx.to,10)+'</td>'
+'<td>'+C(t.tx.amount)+'</td><td><a href="#" onclick="VB('+t.block_height+');return false">#'+t.block_height+'</a></td></tr>').join('')+'</table>'}
$('c').innerHTML='<div class="dt"><h3>Address</h3><div class="r"><span class="k">Address</span><span class="m">'+a+'</span></div>'
+'<div class="r"><span class="k">Balance</span><span class="v b">'+(ac.balance?.toFixed(8)||0)+' BOS</span></div>'
+'<div class="r"><span class="k">Nonce</span><span>'+(ac.nonce||0)+'</span></div></div>'+tbl
}catch(e){$('c').innerHTML='<p style="color:#f87171">Error</p>'}}

async function VT(hash){$('c').innerHTML='<div class="ld">Loading...</div>';
try{var r=await F('/tx/get?hash='+hash);if(r.error){$('c').innerHTML='<p style="color:#f87171">TX not found</p>';return}
var t=r.tx;$('c').innerHTML='<div class="dt"><h3>Transaction <span class="bg '+(r.status==='confirmed'?'ok':'pd')+'">'+r.status+'</span></h3>'
+'<div class="r"><span class="k">Hash</span><span class="m">'+t.hash+'</span></div>'
+'<div class="r"><span class="k">From</span><span class="m"><a href="#" onclick="VA(\''+t.from+'\');return false">'+t.from+'</a></span></div>'
+'<div class="r"><span class="k">To</span><span class="m"><a href="#" onclick="VA(\''+t.to+'\');return false">'+t.to+'</a></span></div>'
+'<div class="r"><span class="k">Amount</span><span>'+C(t.amount)+' BOS</span></div>'
+'<div class="r"><span class="k">Fee</span><span>'+C(t.fee)+' BOS</span></div>'
+'<div class="r"><span class="k">Nonce</span><span>'+t.nonce+'</span></div>'
+'<div class="r"><span class="k">Type</span><span>'+(t.type||'transfer')+'</span></div>'
+(r.block_height!==undefined?'<div class="r"><span class="k">Block</span><span><a href="#" onclick="VB('+r.block_height+');return false">#'+r.block_height+'</a></span></div>':'')
+'</div>'}catch(e){$('c').innerHTML='<p style="color:#f87171">Error</p>'}}

D();
</script>`
