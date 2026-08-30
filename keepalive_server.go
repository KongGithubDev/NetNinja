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
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="theme-color" content="#00d4ff">
<link rel="manifest" href="/manifest.json">
<title>NetNinja Keepalive</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:0}
.bar-top{position:fixed;top:0;left:0;right:0;z-index:999;padding:8px 16px;text-align:center;font-size:13px;font-weight:600;transition:all 0.3s}
.bar-top.off{background:#4a1b1b;color:#ff6b6b}
.bar-top.on{background:#1b5e20;color:#6bffb8}
.bar-top.wait{background:#4a3b1b;color:#ffd76b}
.bar-top .pulse{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;animation:pulse 2s infinite}
.bar-top.on .pulse{background:#6bffb8}
.bar-top.wait .pulse{background:#ffd76b}
.bar-top.off .pulse{background:#ff6b6b}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
.card{background:#1a1a2e;border-radius:16px;padding:24px;max-width:480px;margin:48px auto 16px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
h1{font-size:18px;margin-bottom:12px;color:#00d4ff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}
.stat-box{background:#0d0d1a;border-radius:8px;padding:10px 12px}
.stat-box .label{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:0.5px}
.stat-box .value{font-size:18px;font-weight:700;color:#00d4ff;margin-top:2px}
.stat-box .value.green{color:#6bffb8}
.stat-box .value.yellow{color:#ffd76b}
.stat-box .sub{font-size:10px;color:#555;margin-top:2px}
canvas{width:100%;height:80px;border-radius:8px;background:#0d0d1a;margin-bottom:12px}
.btn-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
button{padding:12px;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s}
.btn-start{background:#00d4ff;color:#0a0a0a}
.btn-stop{background:#ff6b6b;color:#fff}
.btn-notif{background:#1a1a2e;color:#00d4ff;border:1px solid #00d4ff33}
.info{font-size:11px;color:#555;text-align:center;margin-top:8px}
.install{background:#0d0d1a;border-radius:8px;padding:12px;margin-top:12px;font-size:12px;color:#888;text-align:center}
.install b{color:#00d4ff}
</style>
</head>
<body>
<div id="bar" class="bar-top off">
  <span class="pulse"></span>
  <span id="barText">Stopped</span>
</div>
<div class="card">
<h1>&#x1F977; NetNinja Keepalive</h1>
<div class="grid">
  <div class="stat-box"><div class="label">Latency</div><div class="value green" id="lat">-</div><div class="sub" id="latAvg">avg - ms</div></div>
  <div class="stat-box"><div class="label">Uptime</div><div class="value" id="up">-</div><div class="sub" id="upSince">-</div></div>
</div>
<div class="grid">
  <div class="stat-box"><div class="label">Data Sent</div><div class="value yellow" id="bytes">0 B</div><div class="sub" id="bytesRate">- B/min</div></div>
  <div class="stat-box"><div class="label">Status</div><div class="value" id="pings">0</div><div class="sub">successful pings</div></div>
</div>
<canvas id="chart"></canvas>
<div class="btn-row">
  <button id="btn" class="btn-start" onclick="toggle()">Start</button>
  <button class="btn-notif" onclick="askNotif()">Enable Alerts</button>
</div>
<div class="info">Auto-starts on load. Sends ping every 5s.</div>
<div class="install" id="installHint" style="display:none">
  <b>Add to Home Screen</b> for true push notifications even when Safari is closed.<br>
  Tap Share > Add to Home Screen
</div>
</div>
<script>
var running=false,count=0,startTs=0,pingTimer=null,upTimer=null;
var latencies=[],bytesTotal=0,lastByteTs=0;
var canvas=document.getElementById('chart');
var ctx=canvas.getContext('2d');
var pingStart=0;
var isStandalone=window.navigator.standalone||window.matchMedia('(display-mode:standalone)').matches;

if(!isStandalone){
  document.getElementById('installHint').style.display='block';
}

function fmt(b){
  if(b<1024)return b.toFixed(1)+' B';
  if(b<1048576)return(b/1024).toFixed(1)+' KB';
  return(b/1048576).toFixed(2)+' MB';
}
function fmtTime(s){
  var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  return(h>0?h+'h ':'')+(m>0?m+'m ':'')+sec+'s';
}
function setBar(c,t){
  var b=document.getElementById('bar');
  b.className='bar-top '+c;
  document.getElementById('barText').textContent=t;
}
function toggle(){running?stop():start()}
function start(){
  if(running)return;
  startTs=Date.now();lastByteTs=Date.now();
  upTimer=setInterval(updateUI,1000);
  running=true;
  document.getElementById('btn').textContent='Stop';
  document.getElementById('btn').className='btn-stop';
  doPing();
  pingTimer=setInterval(doPing,5000);
}
function doPing(){
  pingStart=Date.now();
  var sz=Math.floor(Math.random()*200)+50;
  var body=new ArrayBuffer(sz);
  fetch('/ping',{method:'POST',body:body}).then(function(r){
    var lat=Date.now()-pingStart;
    latencies.push(lat);
    if(latencies.length>60)latencies.shift();
    bytesTotal+=sz+200;
    count++;
    updateUI();
    drawChart();
  }).catch(function(){
    setBar('wait','Retrying...');
    latencies.push(9999);
    if(latencies.length>60)latencies.shift();
  });
}
function stop(){
  running=false;clearInterval(pingTimer);clearInterval(upTimer);
  startTs=0;count=0;latencies=[];bytesTotal=0;
  document.getElementById('btn').textContent='Start';
  document.getElementById('btn').className='btn-start';
  setBar('off','Stopped');
  document.title='NetNinja Keepalive';
  document.getElementById('lat').textContent='-';
  document.getElementById('up').textContent='-';
  document.getElementById('bytes').textContent='0 B';
  document.getElementById('pings').textContent='0';
  ctx.clearRect(0,0,canvas.width,canvas.height);
}
function updateUI(){
  if(!startTs)return;
  var now=Date.now();
  var sec=Math.floor((now-startTs)/1000);
  var t=fmtTime(sec);
  document.getElementById('up').textContent=t;
  document.getElementById('upSince').textContent=new Date(startTs).toLocaleTimeString();
  document.title='\u2022 '+t+' \u2022 NetNinja';
  setBar('on','Active \u2022 '+t);
  document.getElementById('pings').textContent=count;
  if(latencies.length>0){
    var last=latencies[latencies.length-1];
    var avg=latencies.reduce(function(a,b){return a+b},0)/latencies.length;
    document.getElementById('lat').textContent=last<9000?last+'ms':'timeout';
    document.getElementById('lat').className='value '+(last<200?'green':'yellow');
    document.getElementById('latAvg').textContent='avg '+Math.round(avg)+' ms';
  }
  document.getElementById('bytes').textContent=fmt(bytesTotal);
  var bmins=(now-lastByteTs)/60000;
  document.getElementById('bytesRate').textContent=bmins>0.05?fmt(bytesTotal/bmins)+'/min':'-';
}
function drawChart(){
  var w=canvas.width=canvas.offsetWidth*2;
  var h=canvas.height=canvas.offsetHeight*2;
  ctx.clearRect(0,0,w,h);
  if(latencies.length<2)return;
  var max=0;
  for(var i=0;i<latencies.length;i++)if(latencies[i]>max)max=latencies[i];
  if(max<100)max=100;
  ctx.strokeStyle='#00d4ff';ctx.lineWidth=2;ctx.beginPath();
  for(var i=0;i<latencies.length;i++){
    var x=i/(latencies.length-1)*w;
    var y=h-(latencies[i]/max)*(h-20)-10;
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  }
  ctx.stroke();
  ctx.fillStyle='rgba(0,212,255,0.1)';ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.fill();
  ctx.fillStyle='#555';ctx.font='18px sans-serif';
  ctx.fillText('max '+Math.round(max)+'ms',8,18);
}
function askNotif(){
  if(!('Notification' in window)){
    alert('Notifications not supported. Add to Home Screen for push notifications.');
    return;
  }
  Notification.requestPermission().then(function(p){
    if(p==='granted'){
      new Notification('NetNinja Keepalive',{body:'Notifications enabled!'});
    }
  });
}
document.addEventListener('visibilitychange',function(){
  if(document.visibilityState==='visible'&&running){
    doPing();
  }
});
setTimeout(start,1000);
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
