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

const keepaliveHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetNinja Keepalive</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:16px}
.card{background:#1a1a2e;border-radius:16px;padding:24px;max-width:480px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
h1{font-size:18px;margin-bottom:12px;color:#00d4ff}
.status{padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;font-weight:600;text-align:center}
.status.off{background:#2d1b1b;color:#ff6b6b;border:1px solid #ff6b6b33}
.status.on{background:#1b2d1b;color:#6bffb8;border:1px solid #6bffb833}
.status.wait{background:#2d2d1b;color:#ffd76b;border:1px solid #ffd76b33}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}
.stat-box{background:#0d0d1a;border-radius:8px;padding:10px 12px}
.stat-box .label{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:0.5px}
.stat-box .value{font-size:18px;font-weight:700;color:#00d4ff;margin-top:2px}
.stat-box .value.green{color:#6bffb8}
.stat-box .value.yellow{color:#ffd76b}
.stat-box .value.red{color:#ff6b6b}
.stat-box .sub{font-size:10px;color:#555;margin-top:2px}
canvas{width:100%;height:80px;border-radius:8px;background:#0d0d1a;margin-bottom:12px}
button{width:100%;padding:12px;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.2s}
button.play{background:#00d4ff;color:#0a0a0a}
button.stop{background:#ff6b6b;color:#fff}
.bar{height:4px;border-radius:2px;background:#1a1a2e;margin-bottom:12px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,#00d4ff,#6bffb8);transition:width 0.3s}
.info{font-size:11px;color:#555;text-align:center;margin-top:8px}
.notif{position:fixed;top:0;left:0;right:0;padding:10px 16px;text-align:center;font-size:13px;font-weight:600;z-index:999;transform:translateY(-100%);transition:transform 0.3s}
.notif.show{transform:translateY(0)}
.notif.ok{background:#1b5e20;color:#6bffb8;border-bottom:1px solid #6bffb833}
.notif.err{background:#4a1b1b;color:#ff6b6b;border-bottom:1px solid #ff6b6b33}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
</style>
</head>
<body>
<div id="notif" class="notif"></div>
<div class="card">
<h1>&#x1F977; NetNinja Keepalive</h1>
<div id="status" class="status off">Stopped</div>
<div class="bar"><div class="bar-fill" id="bar" style="width:0%"></div></div>
<div class="grid">
  <div class="stat-box"><div class="label">Latency</div><div class="value green" id="lat">-</div><div class="sub" id="latAvg">avg - ms</div></div>
  <div class="stat-box"><div class="label">Uptime</div><div class="value" id="up">-</div><div class="sub" id="upSince">-</div></div>
</div>
<div class="grid">
  <div class="stat-box"><div class="label">Data Sent</div><div class="value yellow" id="bytes">0 B</div><div class="sub" id="bytesRate">- B/min</div></div>
  <div class="stat-box"><div class="label">Latency Chart</div><div class="sub" style="margin-top:6px">last 60 pings</div></div>
</div>
<canvas id="chart"></canvas>
<button id="btn" class="play" onclick="toggle()">Start Keepalive</button>
<div class="info">Sends ping every 5s to maintain CGNAT mapping</div>
</div>
<audio id="bgAudio" loop preload="none">
<source src="data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=" type="audio/wav">
</audio>
<script>
var running=false,count=0,startTs=0,pingTimer=null,upTimer=null,notifTimer=null;
var latencies=[],bytesTotal=0,lastByteTs=0;
var audio=document.getElementById('bgAudio');
var canvas=document.getElementById('chart');
var ctx=canvas.getContext('2d');
var pingStart=0;

function fmt(b){
  if(b<1024)return b.toFixed(1)+' B';
  if(b<1048576)return(b/1024).toFixed(1)+' KB';
  return(b/1048576).toFixed(2)+' MB';
}
function fmtTime(s){
  var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  return(h>0?h+'h ':'')+(m>0?m+'m ':'')+sec+'s';
}
function updateStatus(c,t){
  var s=document.getElementById('status');
  s.className='status '+c;s.textContent=t;
}
function showNotif(msg,type){
  var n=document.getElementById('notif');
  n.textContent=msg;n.className='notif '+type+' show';
  setTimeout(function(){n.classList.remove('show')},4000);
}
function sendBrowserNotif(title,body){
  if(Notification.permission==='granted'){
    new Notification(title,{body:body,tag:'keepalive',renotify:true});
  }
}
function toggle(){running?stop():start()}
function start(){
  if(running)return;
  audio.play().catch(function(){});
  if(Notification.permission==='default'){
    Notification.requestPermission();
  }
  updateStatus('wait','Connecting...');
  startTs=Date.now();lastByteTs=Date.now();
  upTimer=setInterval(updateUI,1000);
  running=true;
  document.getElementById('btn').textContent='Stop Keepalive';
  document.getElementById('btn').className='stop';
  document.title='\u2022 NetNinja Keepalive';
  doPing();
  pingTimer=setInterval(doPing,5000);
  notifTimer=setInterval(sendPeriodicNotif,60000);
  showNotif('Keepalive started','ok');
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
    updateStatus('wait','Retrying...');
    showNotif('Ping failed - retrying...','err');
    latencies.push(9999);
    if(latencies.length>60)latencies.shift();
  });
}
function sendPeriodicNotif(){
  if(!running||!startTs)return;
  var sec=Math.floor((Date.now()-startTs)/1000);
  var msg='Active \u2022 Uptime: '+fmtTime(sec);
  if(latencies.length>0){
    var last=latencies[latencies.length-1];
    msg+=' \u2022 '+last+'ms';
  }
  document.title='\u2022 '+fmtTime(sec)+' \u2022 NetNinja';
  sendBrowserNotif('NetNinja Keepalive',msg);
}
function stop(){
  running=false;clearInterval(pingTimer);clearInterval(upTimer);clearInterval(notifTimer);
  startTs=0;count=0;latencies=[];bytesTotal=0;
  document.getElementById('btn').textContent='Start Keepalive';
  document.getElementById('btn').className='play';
  updateStatus('off','Stopped');
  document.title='NetNinja Keepalive';
  document.getElementById('lat').textContent='-';
  document.getElementById('up').textContent='-';
  document.getElementById('bytes').textContent='0 B';
  document.getElementById('bar').style.width='0%';
  ctx.clearRect(0,0,canvas.width,canvas.height);
  showNotif('Keepalive stopped','err');
}
function updateUI(){
  if(!startTs)return;
  var now=Date.now();
  var sec=Math.floor((now-startTs)/1000);
  document.getElementById('up').textContent=fmtTime(sec);
  document.getElementById('upSince').textContent=new Date(startTs).toLocaleTimeString();
  document.title='\u2022 '+fmtTime(sec)+' \u2022 NetNinja';
  if(latencies.length>0){
    var last=latencies[latencies.length-1];
    var avg=latencies.reduce(function(a,b){return a+b},0)/latencies.length;
    document.getElementById('lat').textContent=last<9000?last+'ms':'timeout';
    document.getElementById('lat').className='value '+(last<200?'green':last<500?'yellow':'red');
    document.getElementById('latAvg').textContent='avg '+Math.round(avg)+' ms';
  }
  document.getElementById('bytes').textContent=fmt(bytesTotal);
  var bmins=(now-lastByteTs)/60000;
  document.getElementById('bytesRate').textContent=bmins>0.05?fmt(bytesTotal/bmins)+'/min':'-';
  var pingSec=sec%5;
  document.getElementById('bar').style.width=(pingSec/5*100)+'%';
  updateStatus('on','Active');
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
document.addEventListener('visibilitychange',function(){
  if(document.visibilityState==='visible'&&running){
    doPing();audio.play().catch(function(){});
  }
});
</script>
</body>
</html>`

func main() {
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
