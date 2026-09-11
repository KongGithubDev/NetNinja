package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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
.top{position:fixed;top:0;left:0;right:0;z-index:999;height:36px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;transition:background 0.3s}
.top.on{background:#0d3320;color:#6bffb8;border-bottom:1px solid #1a4a2e}
.top.off{background:#331111;color:#ff6b6b;border-bottom:1px solid #4a1a1a}
.top.wait{background:#332e11;color:#ffd76b;border-bottom:1px solid #4a421a}
.top{animation:none}
.card{background:#1a1a2e;border-radius:16px;padding:20px;max-width:440px;margin:52px auto 16px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
h1{font-size:16px;margin-bottom:14px;color:#00d4ff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px}
.stat{background:#0d0d1a;border-radius:8px;padding:10px 12px}
.stat .l{font-size:9px;color:#555;text-transform:uppercase;letter-spacing:0.5px}
.stat .v{font-size:16px;font-weight:700;color:#00d4ff;margin-top:2px}
.stat .v.g{color:#6bffb8}
.stat .v.y{color:#ffd76b}
.stat .v.r{color:#ff6b6b}
.stat .s{font-size:9px;color:#444;margin-top:2px}
canvas{width:100%;height:70px;border-radius:8px;background:#0d0d1a;margin-bottom:10px}
.btns{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
button{padding:10px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.2s}
.b1{background:#00d4ff;color:#0a0a0a}
.b2{background:#1a1a2e;color:#00d4ff;border:1px solid #00d4ff33}
.note{font-size:10px;color:#444;text-align:center;margin-top:8px}
.hint{background:#0d0d1a;border-radius:8px;padding:10px;margin-top:10px;font-size:11px;color:#666;text-align:center}
.hint b{color:#00d4ff}
.geo{background:#0d0d1a;border-radius:8px;padding:10px 12px;margin-bottom:10px;border-left:3px solid #333;transition:border-color 0.3s}
.geo.ok{border-left-color:#6bffb8}
.geo.warn{border-left-color:#ffd76b}
.geo.bad{border-left-color:#ff6b6b}
.geo .gl{font-size:13px;font-weight:700;color:#888}
.geo.ok .gl{color:#6bffb8}
.geo.warn .gl{color:#ffd76b}
.geo.bad .gl{color:#ff6b6b}
.geo .gs{font-size:10px;color:#555;margin-top:3px;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
</style>
</head>
<body>
<div class="top off" id="top">Stopped</div>
<div class="card">
<h1>&#x1F977; NetNinja</h1>
<div class="geo warn" id="geo">
  <div class="gl"><span id="gFlag">&#x1F30F;</span> <b id="gTitle">Checking…</b></div>
  <div class="gs" id="gSub">server -</div>
</div>
<div class="grid">
  <div class="stat"><div class="l">Latency</div><div class="v g" id="lat">-</div><div class="s" id="latAvg">avg - ms</div></div>
  <div class="stat"><div class="l">Uptime</div><div class="v" id="up">-</div><div class="s" id="upSince">-</div></div>
</div>
<div class="grid">
  <div class="stat"><div class="l">Upload</div><div class="v y" id="upBytes">0 B</div><div class="s" id="upRate">- /min</div></div>
  <div class="stat"><div class="l">Download</div><div class="v g" id="dlBytes">0 B</div><div class="s" id="dlRate">- /min</div></div>
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
var LA=[],UB=0,DB=0,LBT=0;
var cv=document.getElementById('chart'),cx=cv.getContext('2d');
var PS=0;
var SA=window.navigator.standalone||window.matchMedia('(display-mode:standalone)').matches;
if(!SA)document.getElementById('hint').style.display='block';

function fmt(b){return b<1024?b.toFixed(1)+' B':b<1048576?(b/1024).toFixed(1)+' KB':(b/1048576).toFixed(2)+' MB'}
function fmtT(s){var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),s2=s%60;return(h>0?h+'h ':'')+(m>0?m+'m ':'')+s2+'s'}
function setTop(c,t){var el=document.getElementById('top');el.className='top '+c;el.textContent=t}
function toggle(){R?stop():start()}
function start(){
  if(R)return;ST=Date.now();LBT=Date.now();
  UT=setInterval(ui,1000);R=true;
  document.getElementById('btn').textContent='Stop';
  document.getElementById('btn').style.background='#ff6b6b';
  setTop('on','Active');
  ping();PT=setInterval(ping,5000);
}
function ping(){
  PS=Date.now();
  var pingTimeout=setTimeout(function(){setTop('wait','Pinging...')},800);
  var sz=Math.floor(Math.random()*200)+50;
  fetch('/ping',{method:'POST',body:new ArrayBuffer(sz)}).then(function(r){
    clearTimeout(pingTimeout);
    var l=Date.now()-PS;LA.push(l);if(LA.length>60)LA.shift();
    UB+=sz;DB+=200;C++;ui();draw();
    setTop('on','Active');
  }).catch(function(){
    clearTimeout(pingTimeout);
    setTop('off','Connection Lost');
    LA.push(9999);if(LA.length>60)LA.shift();
  });
}
function stop(){
  R=false;clearInterval(PT);clearInterval(UT);
  ST=0;C=0;LA=[];UB=0;DB=0;
  document.getElementById('btn').textContent='Start';
  document.getElementById('btn').style.background='#00d4ff';
  setTop('off','Stopped');
  document.title='NetNinja';
  document.getElementById('lat').textContent='-';
  document.getElementById('up').textContent='-';
  document.getElementById('upBytes').textContent='0 B';
  document.getElementById('dlBytes').textContent='0 B';
  cx.clearRect(0,0,cv.width,cv.height);
}
function ui(){
  if(!ST)return;var n=Date.now(),s=Math.floor((n-ST)/1000),t=fmtT(s);
  document.getElementById('up').textContent=t;
  document.getElementById('upSince').textContent=new Date(ST).toLocaleTimeString();
  document.title='\u2022 '+t;
  if(LA.length>0){
    var l=LA[LA.length-1],a=LA.reduce(function(x,y){return x+y},0)/LA.length;
    document.getElementById('lat').textContent=l<9000?l+'ms':'timeout';
    document.getElementById('lat').className='v '+(l<200?'g':'y');
    document.getElementById('latAvg').textContent='avg '+Math.round(a)+' ms';
  }
  document.getElementById('upBytes').textContent=fmt(UB);
  document.getElementById('dlBytes').textContent=fmt(DB);
  var bm=(n-LBT)/60000;
  document.getElementById('upRate').textContent=bm>0.05?fmt(UB/bm)+'/min':'- /min';
  document.getElementById('dlRate').textContent=bm>0.05?fmt(DB/bm)+'/min':'- /min';
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
function geo(){
  fetch('/status.json',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
    var el=document.getElementById('geo'),c='warn',f='\uD83C\uDF10',t='Direct connection \u2014 Thai egress not configured';
    if(!d.geo_known){c='warn';t='Proxy status unavailable'}
    else if(d.thai){c='ok';f='\uD83C\uDDF9\uD83C\uDDED';t='Thailand Connected'}
    else if(d.pool&&d.pool.on){c='bad';t='Thai egress unavailable'+(d.country?' ('+d.country+')':'')}
    el.className='geo '+c;
    document.getElementById('gFlag').textContent=f;
    document.getElementById('gTitle').textContent=t;
    var s='server '+(d.server_known?d.server:'unknown');
    if(d.geo_known&&d.pool&&d.pool.on){
      s+=' \u00b7 '+d.pool.nodes+' thai node'+(d.pool.nodes===1?'':'s');
      if(d.sessions)s+=' \u00b7 '+d.sessions+' session'+(d.sessions===1?'':'s');
    }
    document.getElementById('gSub').textContent=s;
  }).catch(function(){
    document.getElementById('geo').className='geo warn';
    document.getElementById('gTitle').textContent='Proxy status unavailable';
  });
}
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible'&&R){ping();geo()}});
setTimeout(start,500);
geo();setInterval(geo,10000);
</script>
</body>
</html>`

// ===========================================================================
// Server identity + Thai egress state
//
// The page tells the client which server it is going through (with the address
// partially masked) and whether geo traffic is exiting Thailand right now.
// Nothing is compiled in: the address comes from PROXY_ADDR / SERVER_ADDR when
// set and is otherwise looked up at runtime, and the Thai state is read from the
// proxy itself on 127.0.0.1 — the proxy is the only process that knows which
// egress node is current, because the keepalive page deliberately never travels
// the Thai path.
//
//   PROXY_ADDR / SERVER_ADDR  address to show — no lookup at all
//   SERVER_LOOKUP_URL         what to ask when neither is set (ip-api default)
//   SERVER_LOOKUP_TTL         how long a lookup is reused (default 10m)
//   GEO_STATUS_URL            default http://127.0.0.1:5988/geo-status.json
//   GEO_STATUS_TTL            how long a proxy answer is reused (default 15s)
//   MASK_KEEP_OCTETS          IPv4 octets left visible (default 2, max 3)
// ===========================================================================

type geoStatus struct {
	Expect   string `json:"expect"`
	Thai     bool   `json:"thai"`
	Country  string `json:"country"`
	Sessions int64  `json:"sessions"`
	Pool     struct {
		On      bool   `json:"on"`
		Nodes   int    `json:"nodes"`
		Current string `json:"current"`
	} `json:"pool"`
}

type poolState struct {
	On    bool `json:"on"`
	Nodes int  `json:"nodes"`
}

// pageStatus is the whole payload the browser is allowed to see: the server
// address is already masked, and the egress node address never leaves the box.
type pageStatus struct {
	Server      string    `json:"server"`
	ServerKnown bool      `json:"server_known"`
	GeoKnown    bool      `json:"geo_known"`
	Thai        bool      `json:"thai"`
	Country     string    `json:"country,omitempty"`
	Expect      string    `json:"expect,omitempty"`
	Sessions    int64     `json:"sessions"`
	Pool        poolState `json:"pool"`
}

var (
	displayAddrEnv = firstNonEmpty(os.Getenv("PROXY_ADDR"), os.Getenv("SERVER_ADDR"))
	lookupURL      = envOr("SERVER_LOOKUP_URL", "http://ip-api.com/json/?fields=query,countryCode")
	lookupTTL      = envDur("SERVER_LOOKUP_TTL", 10*time.Minute)
	geoStatusURL   = envOr("GEO_STATUS_URL", "http://127.0.0.1:5988/geo-status.json")
	geoStatusTTL   = envDur("GEO_STATUS_TTL", 15*time.Second)
	maskKeep       = envInt("MASK_KEEP_OCTETS", 2)

	addrMu  sync.Mutex
	addrVal string
	addrAt  time.Time

	geoMu  sync.Mutex
	geoVal geoStatus
	geoAt  time.Time
	geoHit bool
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func envDur(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// httpGet is a tiny GET that never goes through an HTTP proxy: a stray
// HTTP_PROXY in the service environment must not turn a local call into a loop.
func httpGet(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// maskAddr hides the tail of an address so that opening the page never spells
// the host out in full. A hostname is left alone — DNS already publishes it.
func maskAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	keep := maskKeep
	if keep < 1 {
		keep = 1
	}
	if keep > 3 {
		keep = 3
	}
	if v4 := ip.To4(); v4 != nil {
		parts := [4]string{"xxx", "xxx", "xxx", "xxx"}
		for i, octet := range strings.Split(v4.String(), ".") {
			if i < keep {
				parts[i] = octet
			}
		}
		return strings.Join(parts[:], ".")
	}
	if s := ip.String(); strings.Contains(s, ":") {
		return s[:strings.LastIndex(s, ":")] + ":xxx"
	}
	return "xxx"
}

// displayAddr is the address of this server, pinned by env or looked up at most
// once per lookupTTL.
func displayAddr() string {
	addrMu.Lock()
	defer addrMu.Unlock()
	if displayAddrEnv != "" {
		addrVal = displayAddrEnv
		return addrVal
	}
	if addrVal != "" && time.Since(addrAt) < lookupTTL {
		return addrVal
	}
	body, err := httpGet(lookupURL, 4*time.Second)
	if err != nil {
		log.Printf("[KEEPALIVE] address lookup failed: %v", err)
		return addrVal
	}
	var out struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Query == "" {
		return addrVal
	}
	addrVal, addrAt = out.Query, time.Now()
	return addrVal
}

// readGeoStatus asks the proxy for its cached state and remembers the answer
// briefly, so a page refresh storm cannot turn into a request storm.
func readGeoStatus() (geoStatus, bool) {
	geoMu.Lock()
	defer geoMu.Unlock()
	if geoHit && time.Since(geoAt) < geoStatusTTL {
		return geoVal, true
	}
	if !geoHit && !geoAt.IsZero() && time.Since(geoAt) < 5*time.Second {
		return geoVal, false // the proxy just failed; do not hammer it
	}
	body, err := httpGet(geoStatusURL, 3*time.Second)
	if err != nil {
		geoAt = time.Now()
		return geoVal, false
	}
	var st geoStatus
	if err := json.Unmarshal(body, &st); err != nil {
		log.Printf("[KEEPALIVE] geo status: %v", err)
		geoAt = time.Now()
		return geoVal, false
	}
	geoVal, geoHit, geoAt = st, true, time.Now()
	return geoVal, true
}

func currentStatus() pageStatus {
	addr := displayAddr()
	out := pageStatus{Server: maskAddr(addr), ServerKnown: addr != ""}
	if gs, ok := readGeoStatus(); ok {
		out.GeoKnown = true
		out.Thai = gs.Thai
		out.Country = gs.Country
		out.Expect = gs.Expect
		out.Sessions = gs.Sessions
		out.Pool = poolState{On: gs.Pool.On, Nodes: gs.Pool.Nodes}
	}
	return out
}

func main() {
	http.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(currentStatus()); err != nil {
			log.Printf("[KEEPALIVE] status.json: %v", err)
		}
	})

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
