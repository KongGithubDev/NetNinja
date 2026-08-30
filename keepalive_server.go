package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	totalBytes int64
	bytesMu    sync.Mutex
)

const manifestJSON = `{
  "name": "NetNinja Keepalive",
  "short_name": "Keepalive",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0a0a0a",
  "theme_color": "#00d4ff",
  "icons": [{"src":"/icon-192.png","sizes":"192x192","type":"image/png"}]
}`

const keepaliveHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#00d4ff">
<link rel="manifest" href="/manifest.json">
<title>NetNinja</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:0}
.top{position:fixed;top:0;left:0;right:0;z-index:999;height:40px;background:#0d0d1a;border-bottom:1px solid #1a1a2e;display:flex;align-items:center;justify-content:center}
.flow{display:flex;align-items:center;gap:0;width:280px;height:28px;position:relative}
.node{font-size:10px;font-weight:600;color:#333;z-index:2;position:relative;width:50px;text-align:center;transition:color 0.3s}
.node.g{color:#6bffb8;text-shadow:0 0 8px rgba(107,255,184,0.5)}
.node.y{color:#ffd76b;text-shadow:0 0 8px rgba(255,215,107,0.5)}
.pipe{position:absolute;top:50%;left:50px;right:50px;height:2px;background:#1a1a2e;transform:translateY(-50%);z-index:1}
.beam{position:absolute;top:50%;left:50px;right:50px;height:2px;transform:translateY(-50%);z-index:3;overflow:hidden;opacity:0;transition:opacity 0.3s}
.beam.on{opacity:1}
.beam::after{content:'';position:absolute;top:-1px;left:-30px;width:30px;height:4px;border-radius:2px;background:linear-gradient(90deg,transparent,#00d4ff,#6bffb8,transparent);animation:flow 1.5s linear infinite;box-shadow:0 0 10px #00d4ff}
@keyframes flow{from{left:-30px}to{left:100%}}
.beam.ret::after{animation:flowRet 1.5s linear infinite;background:linear-gradient(90deg,transparent,#6bffb8,#00d4ff,transparent)}
@keyframes flowRet{from{left:100%}to{left:-30px}}
.card{background:#1a1a2e;border-radius:16px;padding:20px;max-width:440px;margin:56px auto 16px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
h1{font-size:16px;margin-bottom:14px;color:#00d4ff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px}
.stat{background:#0d0d1a;border-radius:8px;padding:10px 12px}
.stat .l{font-size:9px;color:#555;text-transform:uppercase;letter-spacing:0.5px}
.stat .v{font-size:16px;font-weight:700;color:#00d4ff;margin-top:2px}
.stat .v.g{color:#6bffb8}
.stat .v.y{color:#ffd76b}
.stat .s{font-size:9px;color:#444;margin-top:2px}
canvas{width:100%;height:70px;border-radius:8px;background:#0d0d1a;margin-bottom:10px}
.btns{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
button{padding:10px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.2s}
.b1{background:#00d4ff;color:#0a0a0a}
.b2{background:#1a1a2e;color:#00d4ff;border:1px solid #00d4ff33}
.note{font-size:10px;color:#444;text-align:center;margin-top:8px}
.hint{background:#0d0d1a;border-radius:8px;padding:10px;margin-top:10px;font-size:11px;color:#666;text-align:center}
.hint b{color:#00d4ff}
</style>
</head>
<body>
<div class="top">
  <div class="flow">
    <div class="node" id="nC">iPad</div>
    <div class="pipe"></div>
    <div class="beam" id="beamFwd"></div>
    <div class="beam ret" id="beamRet"></div>
    <div class="node" id="nP">Proxy</div>
    <div class="pipe" style="left:140px;right:0"></div>
    <div class="beam" id="beamFwd2" style="left:140px;right:0"></div>
    <div class="beam ret" id="beamRet2" style="left:140px;right:0"></div>
    <div class="node" id="nS">Server</div>
  </div>
</div>
<div class="card">
<h1>&#x1F977; NetNinja</h1>
<div class="grid">
  <div class="stat"><div class="l">Latency</div><div class="v g" id="lat">-</div><div class="s" id="latAvg">avg - ms</div></div>
  <div class="stat"><div class="l">Uptime</div><div class="v" id="up">-</div><div class="s" id="upSince">-</div></div>
</div>
<div class="grid">
  <div class="stat"><div class="l">Data</div><div class="v y" id="bytes">0 B</div><div class="s" id="bytesRate">- /min</div></div>
  <div class="stat"><div class="l">Maintained</div><div class="v" id="pings">0</div><div class="s">CGNAT mappings</div></div>
</div>
<canvas id="chart"></canvas>
<div class="btns">
  <button id="btn" class="b1" onclick="toggle()">Start</button>
  <button class="b2" onclick="askNotif()">Alerts</button>
</div>
<div class="note">Maintains CGNAT mapping via ping every 5s</div>
<div class="hint" id="hint" style="display:none">
  <b>Add to Home Screen</b> for push notifications<br>Share > Add to Home Screen
</div>
</div>
<script>
var R=false,C=0,ST=0,PT=null,UT=null;
var LA=[],BT=0,LBT=0;
var cv=document.getElementById('chart'),cx=cv.getContext('2d');
var PS=0,beamT=null;
var SA=window.navigator.standalone||window.matchMedia('(display-mode:standalone)').matches;
if(!SA)document.getElementById('hint').style.display='block';

function fmt(b){return b<1024?b.toFixed(1)+' B':b<1048576?(b/1024).toFixed(1)+' KB':(b/1048576).toFixed(2)+' MB'}
function fmtT(s){var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),s2=s%60;return(h>0?h+'h ':'')+(m>0?m+'m ':'')+s2+'s'}
function toggle(){R?stop():start()}
function start(){
  if(R)return;ST=Date.now();LBT=Date.now();
  UT=setInterval(ui,1000);R=true;
  document.getElementById('btn').textContent='Stop';
  document.getElementById('btn').style.background='#ff6b6b';
  document.getElementById('beamFwd').classList.add('on');
  document.getElementById('beamRet').classList.add('on');
  document.getElementById('beamFwd2').classList.add('on');
  document.getElementById('beamRet2').classList.add('on');
  document.getElementById('nC').className='node g';
  document.getElementById('nP').className='node g';
  document.getElementById('nS').className='node g';
  ping();PT=setInterval(ping,5000);
}
function ping(){
  PS=Date.now();
  document.getElementById('nC').className='node y';
  document.getElementById('nP').className='node';
  document.getElementById('nS').className='node';
  var sz=Math.floor(Math.random()*200)+50;
  fetch('/ping',{method:'POST',body:new ArrayBuffer(sz)}).then(function(r){
    var l=Date.now()-PS;LA.push(l);if(LA.length>60)LA.shift();
    BT+=sz+200;C++;ui();draw();
    document.getElementById('nC').className='node g';
    document.getElementById('nP').className='node g';
    document.getElementById('nS').className='node g';
  }).catch(function(){
    document.getElementById('nC').className='node';
    document.getElementById('nP').className='node';
    document.getElementById('nS').className='node';
    LA.push(9999);if(LA.length>60)LA.shift();
  });
}
function stop(){
  R=false;clearInterval(PT);clearInterval(UT);
  ST=0;C=0;LA=[];BT=0;
  document.getElementById('btn').textContent='Start';
  document.getElementById('btn').style.background='#00d4ff';
  document.getElementById('beamFwd').classList.remove('on');
  document.getElementById('beamRet').classList.remove('on');
  document.getElementById('beamFwd2').classList.remove('on');
  document.getElementById('beamRet2').classList.remove('on');
  document.getElementById('nC').className='node';
  document.getElementById('nP').className='node';
  document.getElementById('nS').className='node';
  document.title='NetNinja';
  document.getElementById('lat').textContent='-';
  document.getElementById('up').textContent='-';
  document.getElementById('bytes').textContent='0 B';
  document.getElementById('pings').textContent='0';
  cx.clearRect(0,0,cv.width,cv.height);
}
function ui(){
  if(!ST)return;var n=Date.now(),s=Math.floor((n-ST)/1000),t=fmtT(s);
  document.getElementById('up').textContent=t;
  document.getElementById('upSince').textContent=new Date(ST).toLocaleTimeString();
  document.title='\u2022 '+t;
  document.getElementById('pings').textContent=C;
  if(LA.length>0){
    var l=LA[LA.length-1],a=LA.reduce(function(x,y){return x+y},0)/LA.length;
    document.getElementById('lat').textContent=l<9000?l+'ms':'timeout';
    document.getElementById('lat').className='v '+(l<200?'g':'y');
    document.getElementById('latAvg').textContent='avg '+Math.round(a)+' ms';
  }
  document.getElementById('bytes').textContent=fmt(BT);
  var bm=(n-LBT)/60000;
  document.getElementById('bytesRate').textContent=bm>0.05?fmt(BT/bm)+'/min':'- /min';
}
function draw(){
  var w=cv.width=cv.offsetWidth*2,h=cv.height=cv.offsetHeight*2;
  cx.clearRect(0,0,w,h);if(LA.length<2)return;
  var mx=0;for(var i=0;i<LA.length;i++)if(LA[i]>mx)mx=LA[i];
  if(mx<100)mx=100;
  cx.strokeStyle='#00d4ff';cx.lineWidth=2;cx.beginPath();
  for(var i=0;i<LA.length;i++){
    var x=i/(LA.length-1)*w,y=h-(LA[i]/mx)*(h-20)-10;
    i===0?cx.moveTo(x,y):cx.lineTo(x,y);
  }
  cx.stroke();cx.fillStyle='rgba(0,212,255,0.08)';cx.lineTo(w,h);cx.lineTo(0,h);cx.fill();
  cx.fillStyle='#444';cx.font='16px sans-serif';cx.fillText('max '+Math.round(mx)+'ms',8,16);
}
function askNotif(){
  if(!('Notification' in window)){alert('Add to Home Screen for push notifications');return}
  Notification.requestPermission().then(function(p){if(p==='granted')new Notification('NetNinja',{body:'Alerts enabled'})});
}
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible'&&R)ping()});
setTimeout(start,500);
</script>
</body>
</html>`

func main() {
	http.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, manifestJSON)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, keepaliveHTML)
	})

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		n, _ := fmt.Fprintf(w, "pong %d", time.Now().UnixMilli())
		bytesMu.Lock()
		totalBytes += int64(n)
		bytesMu.Unlock()
		_ = r.Body.Close()
		log.Printf("[KEEPALIVE] ping from %s", r.RemoteAddr)
	})

	addr := ":8080"
	log.Printf("=== NetNinja Keepalive Server on %s ===", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
