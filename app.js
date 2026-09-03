const $ = (id) => document.getElementById(id);
const state = {
  stream: null,
  scanTimer: null,
  history: loadHistory(),
  game: null,
  criticalAlert: false
};

// PATRONES DE MALWARE ULTRA DETECTADOS (del análisis de payloads)
const MALWARE_PATTERNS = {
  critico: /@.*(?:192\.168|10\.|172\.)|\.ru\/|\.tk\b|\.onion\b|exploit-kit|c2-darknet|malware-server|phishing-site|trojan\.win32|emotet|ransomware|locky|encrypt=all|powershell.*enc|cmd.*bitsadmin|reg add.*run|net.*administrator|svchost\.exe|\.exe\?|payload\.exe|backdoor|shell\.exe|root@|ssh.*execute|ftp.*malware|data:text\/html.*script|file:\/\/\/c:|smb.*malware|execute.*command|root:.*@|pwned|btc=steal|decrypt=never|steal.*cookie|exfiltrate|autorun|spread=network|credentials|hardcoded.*password/i,
  alto: /phishing|spoofing|verify.*account|confirm.*identity|update.*urgently|account.*locked|suspended|unauthorized|unusual.*activity|action.*required|click.*immediately|confirm.*credentials|verify.*password|banking|paypal|amazon|apple|microsoft.*account|refund.*pending|claim.*prize|congratulations.*won|secure.*verification|unusual.*login|compromised/i
};

const EXTRA_RISK_PATTERN = /auto[_-]?exfil|stolen\s*data|attachment=|charge=premium|fraud=enabled|smishing|malicious|virus|malware|trojan|ransomware|exploit|backdoor|rootkit|payload|phishing|pwned|steal|decrypt=never|encrypt=all|credentials|passwords?|\b(?:cmd|powershell)\b/i;

function hasDangerousContent(value){
  return MALWARE_PATTERNS.critico.test(value) ||
    MALWARE_PATTERNS.alto.test(value) ||
    EXTRA_RISK_PATTERN.test(value);
}

function loadHistory(){
  try{
    const saved = JSON.parse(localStorage.getItem("qrShieldHistory") || "[]");
    return Array.isArray(saved) ? saved : [];
  }catch{
    localStorage.removeItem("qrShieldHistory");
    return [];
  }
}

// NAVEGACIÓN
document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => showSection(btn.dataset.section));
});
document.querySelectorAll("[data-go]").forEach(btn => {
  btn.addEventListener("click", () => showSection(btn.dataset.go));
});

// BOTONES DE DEMOSTRACIÓN
document.querySelectorAll(".demo-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const demo = btn.dataset.demo;
    $("urlInput").value = demo;
    $("analyzeBtn").click();
  });
});

function showSection(id){
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  $(id).classList.add("active");
  const nav = document.querySelector(`[data-section="${id}"]`);
  if(nav) nav.classList.add("active");
  if(id === "historial") renderHistory();
}

// RECONOCIMIENTO DE TIPO DE CONTENIDO QR
function detectQRType(content){
  const lower = content.toLowerCase().trim();
  const riskDetected = hasDangerousContent(lower);
  
  if(lower.startsWith("tel:")) {
    const phone = content.substring(4);
    return { type:"TELÉFONO", icon:"📞", display:phone, advice:"Confirma la identidad antes de llamar", analyzeRisk:riskDetected };
  }
  
  if(lower.startsWith("mailto:")) {
    const email = content.substring(7);
    return { type:"CORREO", icon:"📧", display:email, advice:"No envíes datos sensibles por correo", analyzeRisk:riskDetected };
  }
  
  if(lower.startsWith("wifi:")) {
    try {
      const wifiMatch = content.match(/S:([^;]+)/i);
      const ssid = wifiMatch ? wifiMatch[1] : "Red desconocida";
      return { type:"RED WI-FI", icon:"📡", display:`SSID: ${ssid}`, advice:"No conectes a redes desconocidas", analyzeRisk:riskDetected };
    } catch(e) {
      return { type:"RED WI-FI", icon:"📡", display:"Configuración de Wi-Fi", advice:"Verifica la red antes de conectar", analyzeRisk:riskDetected };
    }
  }
  
  if(lower.startsWith("geo:")) {
    const coords = content.substring(4);
    return { type:"GEOLOCALIZACIÓN", icon:"📍", display:`Coordenadas: ${coords}`, advice:"Verifica la ubicación antes de actuar", analyzeRisk:riskDetected };
  }
  
  if(lower.startsWith("http://") || lower.startsWith("https://")) {
    return { type:"URL/SITIO WEB", icon:"🌐", display:content, advice:"Análisis de riesgo basado en el dominio", analyzeRisk:true };
  }

  if(/^(?:data|file|ftp|ssh|magnet|sms):/i.test(content) || content.startsWith("\\\\") || /^(?:cmd|powershell)\b/i.test(lower) || riskDetected){
    return { type:"CONTENIDO DE RIESGO", icon:"⚠️", display:content, advice:"No ejecutes ni abras este contenido; verifica su origen.", analyzeRisk:true };
  }
  
  return { type:"TEXTO PLANO", icon:"📝", display:content, advice:"Revisa el contenido antes de actuar", analyzeRisk:false };
}

// CÁMARA Y ESCANEO
$("startCamera").addEventListener("click", startCamera);
$("stopCamera").addEventListener("click", stopCamera);
$("analyzeBtn").addEventListener("click", () => {
  const value = $("urlInput").value.trim();
  if(!value) return showMessage("Introduce un enlace o texto para analizar.");
  analyzeContent(value);
});

$("qrImage").addEventListener("change", handleImage);
$("clearHistory").addEventListener("click", () => {
  if(confirm("¿Eliminar todo el historial?")){
    state.history = [];
    localStorage.removeItem("qrShieldHistory");
    renderHistory();
    showMessage("Historial borrado completamente.");
  }
});

async function startCamera(){
  if(!navigator.mediaDevices?.getUserMedia){
    return showMessage("Tu navegador no permite acceder a la cámara.");
  }
  if(state.stream) return;
  try{
    state.stream = await navigator.mediaDevices.getUserMedia({
      video:{facingMode:{ideal:"environment"}}, audio:false
    });
    $("video").srcObject = state.stream;
    $("cameraMessage").textContent = "✓ Cámara iniciada. Apunta el QR dentro del marco.";
    scanFrame();
  }catch(err){
    showMessage("No se pudo acceder a la cámara. Revisa los permisos del navegador.");
  }
}

function stopCamera(){
  if(state.stream){
    state.stream.getTracks().forEach(t => t.stop());
    state.stream = null;
  }
  clearTimeout(state.scanTimer);
  $("cameraMessage").textContent = "La cámara está detenida.";
}

function scanFrame(){
  if(!state.stream) return;
  const video = $("video"), canvas = $("canvas"), ctx = canvas.getContext("2d");
  if(video.readyState >= 2){
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video,0,0,canvas.width,canvas.height);
    const image = ctx.getImageData(0,0,canvas.width,canvas.height);
    if(window.jsQR){
      const code = jsQR(image.data, image.width, image.height, {inversionAttempts:"attemptBoth"});
      if(code?.data){
        $("urlInput").value = code.data;
        $("cameraMessage").textContent = "✓ Código detectado. Analizando...";
        stopCamera();
        analyzeContent(code.data);
        return;
      }
    }
  }
  state.scanTimer = setTimeout(scanFrame, 300);
}

function handleImage(event){
  const file = event.target.files[0];
  if(!file) return;
  const img = new Image();
  img.onload = () => {
    const canvas = $("canvas"), ctx = canvas.getContext("2d");
    canvas.width = img.width; 
    canvas.height = img.height;
    ctx.drawImage(img,0,0);
    const image = ctx.getImageData(0,0,canvas.width,canvas.height);
    const code = window.jsQR ? jsQR(image.data,image.width,image.height,{inversionAttempts:"attemptBoth"}) : null;
    if(code?.data){
      $("urlInput").value = code.data;
      analyzeContent(code.data);
    }else{
      showMessage("No se detectó un código QR válido en la imagen. Intenta con una imagen más nítida.");
    }
  };
  img.src = URL.createObjectURL(file);
}

// MOTOR DE ANÁLISIS MEJORADO
function normalizeUrl(value){
  try{
    return new URL(/^[a-z][a-z\d+.-]*:/i.test(value) ? value : "https://" + value);
  }catch{
    return null;
  }
}

// Detectar homoglyphs y Unicode sospechosos
function detectHomoglyphs(hostname){
  const suspiciousRanges = [
    /[\u0400-\u04FF]/,  // Cirílico
    /[\u0370-\u03FF]/,  // Griego
    /[\u0590-\u05FF]/,  // Hebreo
    /[\u0600-\u06FF]/,  // Árabe
  ];
  
  for(const range of suspiciousRanges){
    if(range.test(hostname)){
      return true;
    }
  }
  return false;
}

function calculateRisk(raw){
  const qrType = detectQRType(raw);
  
  // El texto normal se informa, pero los esquemas o patrones especiales se analizan.
  if(!qrType.analyzeRisk){
    return {
      score: 15,
      level: "INFORMACIÓN",
      className: "risk-low",
      type: qrType.type,
      icon: qrType.icon,
      display: qrType.display,
      recommendation: qrType.advice,
      indicators: [
        ["Tipo de Contenido", "ok", qrType.type],
        ["Análisis", "ok", "No es una URL web"]
      ],
      url: raw,
      isNonWeb: true
    };
  }
  
  const url = normalizeUrl(raw);
  let score = 0;
  const indicators = [];
  const lower = raw.toLowerCase();
  
  if(!url){
    const isCriticalPattern = MALWARE_PATTERNS.critico.test(lower);
    const isHighPattern = MALWARE_PATTERNS.alto.test(lower);
    const score = isCriticalPattern ? 90 : isHighPattern ? 75 : 60;
    const level = score >= 80 ? "CRÍTICO" : score >= 65 ? "ALTO" : "MEDIO";
    const className = score >= 80 ? "risk-critical" : score >= 65 ? "risk-high" : "risk-medium";
    return {
      score,
      level,
      className,
      type: qrType.type,
      icon: qrType.icon,
      recommendation: "Contenido potencialmente peligroso. No lo ejecutes ni lo abras; verifica su origen por un medio independiente.",
      indicators: [
        ["Tipo de contenido", "bad", qrType.type],
        ["Patrón detectado", "bad", isCriticalPattern ? "Señales críticas locales" : "Señales de riesgo locales"]
      ],
      url: raw,
      isNonWeb: false
    };
  }

  if(qrType.type !== "URL/SITIO WEB"){
    score += 25;
    indicators.push(["Esquema especial", "warn", `Tipo detectado: ${qrType.type}`]);
  }

  if(MALWARE_PATTERNS.critico.test(lower)){
    score += 50;
    indicators.push(["Patrón crítico", "bad", "Señales locales de alto riesgo detectadas"]);
  }else if(MALWARE_PATTERNS.alto.test(lower) || EXTRA_RISK_PATTERN.test(lower)){
    score += 30;
    indicators.push(["Patrón de riesgo", "warn", "Señales locales sospechosas detectadas"]);
  }
  
  // ANÁLISIS DE PROTOCOLO
  if(url.protocol !== "https:"){
    score += 20;
    indicators.push(["HTTPS", "bad", "No utiliza HTTPS"]);
  }else{
    score -= 5;
    indicators.push(["HTTPS", "ok", "Utiliza HTTPS"]);
  }
  
  const host = url.hostname.toLowerCase();
  
  // ANÁLISIS DE DOMINIO/IP
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(host)){
    score += 30;
    indicators.push(["Dirección IP", "bad", "Usa dirección IP en lugar de dominio"]);
  }else{
    indicators.push(["Dominio", "ok", "Usa nombre de dominio"]);
  }
  
  // PUNYCODE (internacionalización)
  if(host.includes("xn--")){
    score += 25;
    indicators.push(["Punycode", "bad", "El dominio contiene Punycode (señal de ofuscación)"]);
  }
  
  // HOMOGLYPHS (caracteres Unicode sospechosos)
  if(detectHomoglyphs(host)){
    score += 22;
    indicators.push(["Caracteres Unicode", "bad", "Dominio contiene caracteres extraños"]);
  }
  
  // ACORTADORES DE URL
  const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","ow.ly","short.link","abre.link"];
  if(shorteners.some(d => host === d || host.endsWith("." + d))){
    score += 20;
    indicators.push(["URL Acortada", "warn", "Destino oculto; verifica antes de hacer clic"]);
  }else{
    indicators.push(["URL Acortada", "ok", "No es un acortador conocido"]);
  }
  
  // PALABRAS SOSPECHOSAS
  const suspiciousWords = ["login","verify","verification","password","bank","secure","account","update","upgrade","bonus","prize","regalo","premio","gift","free","gratis","wallet","confirm","signin","urgent","urgente","hurry","immediate","action required","activar","suspender","bloqueado"];
  const hits = suspiciousWords.filter(w => lower.includes(w));
  if(hits.length >= 3){
    score += 30;
    indicators.push(["Palabras Sospechosas", "bad", `Detectadas ${hits.length} palabras de riesgo`]);
  }else if(hits.length > 0){
    score += 15;
    indicators.push(["Palabras Sospechosas", "warn", `Detectada(s) ${hits.length} palabra(s) sospechosa(s)`]);
  }else{
    indicators.push(["Palabras Sospechosas", "ok", "Sin indicadores de phishing"]);
  }
  
  // LONGITUD DE URL
  if((url.pathname + url.search).length > 120){
    score += 12;
    indicators.push(["URL Extensa", "warn", "URL anormalmente extensa"]);
  }else{
    indicators.push(["URL Extensa", "ok", "Longitud normal"]);
  }
  
  // NÚMERO DE SUBDOMINIOS
  const subdomainCount = (host.match(/\./g)||[]).length;
  if(subdomainCount > 3){
    score += 15;
    indicators.push(["Subdominios", "warn", `${subdomainCount} niveles detectados (>3 es sospechoso)`]);
  }else{
    indicators.push(["Subdominios", "ok", "Estructura normal"]);
  }
  
  // CARÁCTER @ (ofuscación de dominio)
  if(/@/.test(url.href)){
    score += 35;
    indicators.push(["Ofuscación @", "bad", "URL contiene @; técnica de ofuscación"]);
  }else{
    indicators.push(["Ofuscación @", "ok", "Sin técnicas de ofuscación"]);
  }
  
  // CARACTERES EXTRAÑOS
  if(/[<>{}\[\]\\^`~|]/.test(raw)){
    score += 20;
    indicators.push(["Caracteres Extraños", "warn", "Se detectaron caracteres inusuales"]);
  }
  
  // NORMALIZAR PUNTAJE
  score = Math.max(0, Math.min(100, score));
  
  let level, className, recommendation;
  if(score <= 20){
    level="BAJO";
    className="risk-low";
    recommendation="Riesgo bajo según indicadores locales. Aun así, verifica que sea el sitio oficial antes de introducir datos.";
  }else if(score <= 40){
    level="MEDIO";
    className="risk-medium";
    recommendation="Precaución. Revisa el dominio cuidadosamente. Evita introducir información sensible hasta verificar el sitio por otro medio.";
  }else if(score <= 65){
    level="ALTO";
    className="risk-high";
    recommendation="Riesgo significativo. NO continúes sin verificar el sitio de forma independiente (búsqueda en Google, llamada al comercio, etc.).";
  }else{
    level="CRÍTICO";
    className="risk-critical";
    recommendation="Riesgo crítico detectado. Se recomienda NO continuar ni introducir ningún dato personal, contraseña o información bancaria.";
  }
  
  return {
    score,
    level,
    className,
    recommendation,
    indicators,
    url: url.href,
    type: qrType.type,
    icon: qrType.icon,
    isNonWeb: false
  };
}

function analyzeContent(raw){
  const result = calculateRisk(raw);
  saveHistory(result);
  renderResult(result);
}

function renderResult(r){
  $("result").classList.remove("hidden");
  
  let typeInfo = "";
  if(r.icon && r.type){
    typeInfo = `<p style="font-size: 0.95rem; color: var(--muted); margin: 0.5rem 0 0;"><strong>Tipo:</strong> ${r.icon} ${r.type}</p>`;
  }
  
  $("result").innerHTML = `
    <div class="risk-header">
      <div>
        <span class="badge">RESULTADO DEL ANÁLISIS</span>
        <h2 class="${r.className}">${r.level}</h2>
        <p>${escapeHtml(r.url)}</p>
        ${typeInfo}
      </div>
      <div class="risk-score ${r.className}">${r.score}/100</div>
    </div>
    <div class="progress ${r.className}">
      <div style="width:${r.score}%"></div>
    </div>
    <p><strong>Recomendación:</strong> ${escapeHtml(r.recommendation)}</p>
    <div class="indicators">
      ${r.indicators.map(i => `
        <div class="indicator">
          <span>${escapeHtml(i[0])}</span>
          <strong class="${i[1]}">${i[1]==="ok"?"✓":"⚠"} ${escapeHtml(i[2])}</strong>
        </div>
      `).join("")}
    </div>
    <div class="safe-note">
      ✓ <strong>Analizado localmente</strong> • Evaluación preventiva y educativa • Este resultado NO garantiza seguridad absoluta.
    </div>
  `;
  
  $("result").scrollIntoView({behavior:"smooth", block:"start"});
}

function saveHistory(r){
  state.history.unshift({
    date: new Date().toLocaleString("es-ES"),
    score: r.score,
    level: r.level,
    url: r.url,
    type: r.type || "URL"
  });
  state.history = state.history.slice(0, 20);
  localStorage.setItem("qrShieldHistory", JSON.stringify(state.history));
}

function renderHistory(){
  if(!state.history.length){
    $("historyList").innerHTML = `<div class="panel">Todavía no hay análisis registrados.</div>`;
    return;
  }
  
  $("historyList").innerHTML = state.history.map((h, idx) => `
    <div class="history-item">
      <div>
        <strong>${escapeHtml(h.level)}</strong>
        <br><small>${escapeHtml(h.url)}</small>
        <br><span style="font-size: 0.75rem; color: var(--muted);">🔍 ${h.type || 'URL'}</span>
      </div>
      <div>
        <strong>${h.score}/100</strong>
        <br><small>${escapeHtml(h.date)}</small>
        <br><span style="font-size: 0.75rem; color: var(--primary);">✓ Local</span>
      </div>
    </div>
  `).join("");
}

function showMessage(message){
  alert(message);
}

// ESCAPEHTML
function escapeHtml(value){
  return String(value).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

// ==================== JUEGO EDUCATIVO: QUIZ DE CIBERSEGURIDAD ====================

// Banco de 30 preguntas: desde qué es un virus hasta cómo detectarlo y prevenirlo
const QUESTION_BANK = [
  { q:"¿Qué es un virus informático?", options:["Un programa que se replica e infecta otros archivos","Un antivirus gratuito","Un tipo de red inalámbrica","Un componente físico del computador"], correct:0, explain:"Un virus se adjunta a archivos o programas y se replica para propagarse, dañando el sistema." },
  { q:"¿Qué diferencia a un gusano (worm) de un virus?", options:["El gusano se propaga solo, sin necesitar un archivo anfitrión","El gusano no puede dañar archivos","El gusano solo afecta a impresoras","No hay ninguna diferencia"], correct:0, explain:"Un gusano se replica y viaja por redes de forma autónoma, sin necesitar infectar un archivo host." },
  { q:"¿Qué es un troyano?", options:["Un programa que se disfraza de software legítimo para dañar el sistema","Un cable de red","Un tipo de firewall","Un protocolo de correo"], correct:0, explain:"El troyano aparenta ser útil o inofensivo, pero oculta funciones maliciosas." },
  { q:"¿Qué hace un ransomware?", options:["Cifra tus archivos y exige un pago para liberarlos","Mejora la velocidad de tu computador","Bloquea anuncios en el navegador","Actualiza tus programas automáticamente"], correct:0, explain:"El ransomware secuestra archivos mediante cifrado y pide un rescate económico." },
  { q:"¿Qué es el spyware?", options:["Software que espía tu actividad sin tu consentimiento","Un programa para editar fotos","Un tipo de red social","Un antivirus premium"], correct:0, explain:"El spyware recopila información de tus actividades y datos sin autorización." },
  { q:"¿Qué es el phishing?", options:["Un intento de engañarte para robar datos haciéndose pasar por una entidad confiable","Una técnica para acelerar el internet","Un tipo de virus de hardware","Un método de respaldo de archivos"], correct:0, explain:"El phishing usa mensajes o sitios falsos que imitan entidades reales para robar información." },
  { q:"¿Qué es el 'quishing'?", options:["Phishing realizado mediante códigos QR maliciosos","Un juego de mesa sobre seguridad","Un tipo de conexión Bluetooth","Un antivirus para móviles"], correct:0, explain:"El quishing usa códigos QR falsos para dirigir a la víctima a sitios de phishing." },
  { q:"¿Cuál es una señal común de un correo de phishing?", options:["Urgencia excesiva y errores ortográficos","Un saludo formal correcto","Un remitente conocido y verificado","Un enlace al sitio oficial verificado"], correct:0, explain:"Los mensajes de phishing suelen crear presión de tiempo y contener errores de redacción." },
  { q:"¿Qué significa que un sitio use HTTPS?", options:["La conexión está cifrada, pero no garantiza que el sitio sea legítimo","El sitio es 100% seguro y confiable","El sitio no puede tener virus","Es un sitio gubernamental verificado"], correct:0, explain:"HTTPS cifra la comunicación, pero un sitio falso también puede tener HTTPS." },
  { q:"¿Qué es un ataque de 'fuerza bruta'?", options:["Probar muchas combinaciones de contraseñas hasta acertar","Un virus que daña el hardware físicamente","Un tipo de red 5G","Un método para comprimir archivos"], correct:0, explain:"Consiste en probar sistemáticamente combinaciones hasta encontrar la contraseña correcta." },
  { q:"¿Cuál es una buena práctica para crear contraseñas seguras?", options:["Usar combinaciones largas, únicas y con distintos tipos de caracteres","Usar la misma contraseña en todos los sitios","Usar tu fecha de nacimiento","Usar contraseñas de menos de 4 caracteres"], correct:0, explain:"Las contraseñas largas, únicas y variadas dificultan los ataques de fuerza bruta." },
  { q:"¿Qué es la autenticación de dos factores (2FA)?", options:["Un segundo paso de verificación además de la contraseña","Un segundo antivirus instalado","Tener dos contraseñas iguales","Un tipo de conexión wifi"], correct:0, explain:"2FA agrega una capa extra de seguridad, como un código enviado al celular." },
  { q:"¿Qué deberías hacer si recibes un QR de una fuente desconocida ofreciendo un premio?", options:["Desconfiar y verificarlo antes de escanearlo","Escanearlo de inmediato para reclamar el premio","Compartirlo con tus contactos","Ingresar tus datos bancarios para confirmar"], correct:0, explain:"Los premios inesperados son una técnica clásica de ingeniería social para robar datos." },
  { q:"¿Qué es la ingeniería social en ciberseguridad?", options:["Manipular psicológicamente a una persona para obtener información o acceso","Una red social para programadores","Un curso de programación","Un tipo de firewall avanzado"], correct:0, explain:"La ingeniería social explota la confianza y las emociones humanas en lugar de fallas técnicas." },
  { q:"¿Cuál es una señal de que un dominio podría ser falso (typosquatting)?", options:["Tiene letras cambiadas o similares al dominio original (ej. paypa1.com)","Usa el mismo nombre exacto que el sitio oficial","Tiene certificado SSL válido","Aparece primero en los resultados de búsqueda"], correct:0, explain:"El typosquatting usa nombres muy parecidos al original para engañar visualmente." },
  { q:"¿Qué es el 'punycode' en una URL?", options:["Una codificación de caracteres internacionales, a veces usada para simular dominios reales","Un tipo de antivirus","Un protocolo de correo electrónico","Una extensión de archivo segura"], correct:0, explain:"El punycode puede usarse para crear dominios visualmente idénticos a los legítimos (spoofing)." },
  { q:"¿Qué deberías hacer antes de escanear un QR pegado en la vía pública?", options:["Verificar que no esté pegado sobre otro QR y confirmar la fuente","Escanearlo sin dudar","Compartirlo en redes sociales antes de revisarlo","Ingresar tus datos personales de inmediato"], correct:0, explain:"Los delincuentes suelen pegar QR falsos sobre los originales en carteles o parquímetros." },
  { q:"¿Qué es un 'firewall' (cortafuegos)?", options:["Un sistema que filtra el tráfico de red para bloquear accesos no autorizados","Un tipo de virus","Un cable de conexión a internet","Un programa para editar videos"], correct:0, explain:"El firewall controla qué conexiones de red se permiten o se bloquean." },
  { q:"¿Por qué es importante mantener el sistema operativo y las apps actualizadas?", options:["Las actualizaciones corrigen vulnerabilidades de seguridad conocidas","Solo cambian el diseño de los íconos","Hacen que el dispositivo funcione más lento","No tienen relación con la seguridad"], correct:0, explain:"Las actualizaciones suelen incluir parches de seguridad contra vulnerabilidades descubiertas." },
  { q:"¿Qué deberías hacer si un QR te redirige a pedir tu contraseña bancaria?", options:["No ingresarla y verificar directamente con el banco por un canal oficial","Ingresarla porque parece urgente","Compartir la contraseña con un familiar primero","Escanear el QR nuevamente para confirmar"], correct:0, explain:"Ninguna entidad legítima solicita contraseñas mediante QR o enlaces no verificados." },
  { q:"¿Qué es un 'keylogger'?", options:["Un programa que registra las teclas que presionas para robar información","Un teclado inalámbrico","Un tipo de antivirus","Una aplicación para tomar notas"], correct:0, explain:"El keylogger captura pulsaciones de teclado, incluyendo contraseñas, sin que la víctima lo note." },
  { q:"¿Qué precaución debes tomar al usar wifi público?", options:["Evitar ingresar datos sensibles o usar una VPN","Conectar automáticamente a cualquier red abierta","Compartir tu contraseña bancaria libremente","Desactivar el antivirus para navegar más rápido"], correct:0, explain:"Las redes públicas pueden ser interceptadas por atacantes; una VPN cifra tu tráfico." },
  { q:"¿Qué es un backup (copia de seguridad) y por qué es importante?", options:["Una copia de tus archivos que te protege ante ataques como el ransomware","Un segundo computador de repuesto","Una función para borrar archivos duplicados","Un tipo de virus benigno"], correct:0, explain:"Los backups permiten recuperar tu información sin pagar rescates ni perderla definitivamente." },
  { q:"¿Qué deberías verificar antes de pagar escaneando un QR?", options:["El nombre del beneficiario y el monto exacto en tu app bancaria","Solo el color del código QR","Que el QR tenga muchos cuadros negros","Nada, los QR de pago siempre son seguros"], correct:0, explain:"Confirmar beneficiario y monto evita pagos a cuentas incorrectas o fraudulentas." },
  { q:"¿Qué es un ataque de 'hombre en el medio' (Man in the Middle)?", options:["Un atacante intercepta la comunicación entre dos partes sin que lo noten","Un técnico que repara computadoras","Un tipo de antivirus en la nube","Un protocolo de cifrado seguro"], correct:0, explain:"El atacante se posiciona entre víctima y servidor para espiar o alterar la comunicación." },
  { q:"¿Qué significa que un enlace use una URL acortada (bit.ly, tinyurl)?", options:["Oculta el destino real, por lo que conviene verificar antes de hacer clic","Siempre es más seguro que una URL larga","Garantiza que el sitio es oficial","Aumenta la velocidad de carga del sitio"], correct:0, explain:"Los acortadores ocultan el destino final, una técnica usada también para enmascarar enlaces maliciosos." },
  { q:"¿Qué deberías hacer si sospechas que tu dispositivo está infectado con malware?", options:["Desconectarlo de internet y ejecutar un antivirus actualizado","Seguir usándolo con normalidad","Compartir archivos con otros dispositivos de inmediato","Ignorar el problema si sigue funcionando"], correct:0, explain:"Aislar el dispositivo evita que el malware se propague mientras se elimina la amenaza." },
  { q:"¿Qué es el 'adware'?", options:["Software que muestra publicidad no deseada, a veces junto a spyware","Un tipo de hardware gráfico","Un antivirus gratuito confiable","Un protocolo de red seguro"], correct:0, explain:"El adware inunda el dispositivo de anuncios y puede venir acompañado de rastreo de datos." },
  { q:"¿Cuál es una señal de alerta en un código QR sospechoso según QR-SHIELD?", options:["Contiene una IP directa, el símbolo @ o palabras como 'verify' y 'urgent'","Contiene solo el nombre de un sitio conocido","Usa HTTPS y un dominio corto","No tiene ningún símbolo especial"], correct:0, explain:"IPs directas, el símbolo @ y palabras de urgencia o verificación son indicadores de riesgo." },
  { q:"¿Qué deberías hacer si una app pide permisos sin relación con su función (ej. una linterna pidiendo acceso a tus contactos)?", options:["Denegar el permiso y desconfiar de la app","Aceptar todos los permisos sin revisar","Desinstalar el antivirus para que funcione mejor","Compartir tu ubicación en tiempo real"], correct:0, explain:"Permisos innecesarios pueden indicar que la app recopila datos de forma abusiva o maliciosa." }
];

const TOTAL_QUESTIONS = 30;
const MAX_HEARTS = 5;
const QUESTION_SECONDS = 20;
const POINTS_CORRECT = 1;
const POINTS_WRONG = -2;
const BONUS_EVERY = 5;
const BONUS_POINTS = 2;

function shuffleArray(arr){
  const a = arr.slice();
  for(let i = a.length - 1; i > 0; i--){
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Baraja el orden de las opciones de una pregunta (y recalcula el índice correcto)
// para que la respuesta correcta no quede siempre en la misma posición.
function shuffleOptions(item){
  const order = shuffleArray(item.options.map((_, i) => i));
  const options = order.map(i => item.options[i]);
  const correct = order.indexOf(item.correct);
  return { q: item.q, options, correct, explain: item.explain };
}

$("startGame").addEventListener("click", startGame);

function startGame(){
  const mode = Number($("gameMode").value);
  state.game = {
    mode,
    players: Array.from({ length: mode }, () => ({
      name: "", phone: "", score: 0, hearts: MAX_HEARTS, correctCount: 0, eliminated: false
    })),
    order: shuffleArray(QUESTION_BANK).slice(0, TOTAL_QUESTIONS).map(shuffleOptions),
    qIndex: 0,
    turn: 0,
    timerId: null,
    timeLeft: QUESTION_SECONDS
  };
  renderRegistration();
}

// REGISTRO OBLIGATORIO ANTES DE INICIAR
function renderRegistration(){
  const g = state.game;
  $("gameArea").classList.remove("hidden");

  const fields = g.players.map((_, i) => `
    <div class="reg-player">
      <h4>Jugador ${i + 1}</h4>
      <label class="input-label" for="regName${i}">Nombre completo</label>
      <input type="text" id="regName${i}" class="reg-input" placeholder="Ej: Ana Pérez" autocomplete="off">
      <label class="input-label" for="regPhone${i}">Número de celular</label>
      <input type="tel" id="regPhone${i}" class="reg-input" placeholder="Ej: 70012345" autocomplete="off">
    </div>
  `).join("");

  $("gameArea").innerHTML = `
    <div class="panel game-card">
      <h3 style="margin-top:0;">📝 Registro obligatorio</h3>
      <p class="safe-note" style="margin-top:0;">Completa tus datos para comenzar. El puntaje inicia en 0 pts.</p>
      <form id="regForm">
        ${fields}
        <p id="regError" class="safe-note" style="color:var(--danger); display:none;"></p>
        <button type="submit" class="primary full">🎮 Iniciar Juego</button>
      </form>
    </div>
  `;

  $("regForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const err = $("regError");
    for(let i = 0; i < g.players.length; i++){
      const name = $(`regName${i}`).value.trim();
      const phone = $(`regPhone${i}`).value.trim().replace(/[\s-]/g, "");
      if(name.length < 3 || !/^[a-zA-ZÀ-ÿ\s]+$/.test(name)){
        err.textContent = `Ingresa un nombre completo válido para el Jugador ${i + 1}.`;
        err.style.display = "block";
        return;
      }
      if(!/^\d{7,15}$/.test(phone)){
        err.textContent = `Ingresa un número de celular válido para el Jugador ${i + 1}.`;
        err.style.display = "block";
        return;
      }
      g.players[i].name = name;
      g.players[i].phone = phone;
    }
    g.qIndex = 0;
    g.turn = 0;
    renderQuestion();
  });
}

function activePlayerIndex(g){
  if(g.mode === 1) return g.players[0].eliminated ? -1 : 0;
  let idx = g.turn;
  for(let i = 0; i < g.players.length; i++){
    if(!g.players[idx].eliminated) return idx;
    idx = (idx + 1) % g.players.length;
  }
  return -1;
}

function heartsHtml(hearts){
  let out = "";
  for(let i = 0; i < MAX_HEARTS; i++) out += i < hearts ? "❤️" : "🖤";
  return `<span class="hearts">${out}</span>`;
}

function renderQuestion(){
  const g = state.game;
  clearInterval(g.timerId);

  const activeIdx = activePlayerIndex(g);
  if(activeIdx === -1){ endGame(); return; }
  g.turn = activeIdx;

  const item = g.order[g.qIndex];
  const player = g.players[activeIdx];
  g.timeLeft = QUESTION_SECONDS;

  const scoreboard = g.players.map((p, i) => `
    <span class="${i === activeIdx ? "sb-active" : ""}">👤 ${escapeHtml(p.name)}: ${p.score} pts ${heartsHtml(p.hearts)}</span>
  `).join("");

  const optionsHtml = item.options.map((opt, i) => `
    <button class="answer" data-opt="${i}">${escapeHtml(opt)}</button>
  `).join("");

  $("gameArea").innerHTML = `
    <div class="panel game-card">
      <div class="scoreboard">${scoreboard}</div>
      <div class="timer-wrap">
        <div class="timer-bar"><div id="timerFill" style="width:100%"></div></div>
        <span id="timerText">${g.timeLeft}s</span>
      </div>
      <strong style="display:block;margin:.75rem 0;color:var(--primary);">
        ${g.mode === 2 ? `Turno de ${escapeHtml(player.name)}` : escapeHtml(player.name)}
      </strong>
      <div class="scenario">${escapeHtml(item.q)}</div>
      <div class="answers quiz-options">${optionsHtml}</div>
      <p id="gameFeedback" class="safe-note">Pregunta ${g.qIndex + 1} de ${TOTAL_QUESTIONS}</p>
      <div id="sparkLayer" class="spark-layer"></div>
    </div>
  `;

  document.querySelectorAll(".answer").forEach(b => {
    b.addEventListener("click", () => answerQuestion(Number(b.dataset.opt)));
  });

  g.timerId = setInterval(() => {
    g.timeLeft--;
    const fill = $("timerFill");
    const text = $("timerText");
    if(fill) fill.style.width = `${Math.max(g.timeLeft, 0) / QUESTION_SECONDS * 100}%`;
    if(text) text.textContent = `${Math.max(g.timeLeft, 0)}s`;
    if(g.timeLeft <= 0){
      clearInterval(g.timerId);
      answerQuestion(-1);
    }
  }, 1000);
}

function answerQuestion(selected){
  const g = state.game;
  clearInterval(g.timerId);
  const item = g.order[g.qIndex];
  const player = g.players[g.turn];
  const feedback = $("gameFeedback");
  const correct = selected === item.correct;

  document.querySelectorAll(".answer").forEach((b, i) => {
    b.disabled = true;
    if(i === item.correct) b.classList.add("answer-correct");
    if(i === selected && !correct) b.classList.add("answer-wrong");
  });

  let bonusMsg = "";
  if(correct){
    player.score += POINTS_CORRECT;
    player.correctCount++;
    if(player.correctCount % BONUS_EVERY === 0){
      player.score += BONUS_POINTS;
      bonusMsg = ` ⚡ ¡Racha de ${BONUS_EVERY} aciertos! +${BONUS_POINTS} pts bono.`;
      triggerSparkEffect();
    }
  }else{
    player.score += POINTS_WRONG;
    player.hearts = Math.max(0, player.hearts - 1);
    if(player.hearts === 0) player.eliminated = true;
  }

  feedback.innerHTML = correct
    ? `✅ <strong>Correcto. +${POINTS_CORRECT} pts.</strong>${bonusMsg}<br>${escapeHtml(item.explain)}`
    : `❌ <strong>Incorrecto${selected === -1 ? " (tiempo agotado)" : ""}. ${POINTS_WRONG} pts, -1 ❤️.</strong><br>${escapeHtml(item.explain)}`;

  setTimeout(() => {
    if(g.mode === 1 && player.eliminated){
      endGame();
      return;
    }
    g.qIndex++;
    if(g.qIndex >= TOTAL_QUESTIONS){
      endGame();
      return;
    }
    if(g.mode === 2) g.turn = (g.turn + 1) % g.players.length;
    if(activePlayerIndex(g) === -1){
      endGame();
      return;
    }
    renderQuestion();
  }, 2200);
}

function triggerSparkEffect(){
  const layer = $("sparkLayer");
  if(!layer) return;
  for(let i = 0; i < 10; i++){
    const spark = document.createElement("span");
    spark.className = "spark";
    spark.textContent = "✨";
    spark.style.left = `${Math.random() * 100}%`;
    spark.style.animationDelay = `${(Math.random() * 0.3).toFixed(2)}s`;
    layer.appendChild(spark);
    setTimeout(() => spark.remove(), 1300);
  }
}

function endGame(){
  const g = state.game;
  clearInterval(g.timerId);

  const lostPlayers = g.players.filter(p => p.hearts <= 0);
  const summaryRows = g.players.map(p =>
    `<p>${escapeHtml(p.name)}: <strong>${p.score}</strong> pts ${p.hearts <= 0 ? "💔 (sin vidas)" : ""}</p>`
  ).join("");

  let title = "🏁 Juego Terminado";
  if(g.mode === 2 && g.players[0].score !== g.players[1].score){
    title = g.players[0].score > g.players[1].score
      ? `🏆 GANA ${escapeHtml(g.players[0].name)}`
      : `🏆 GANA ${escapeHtml(g.players[1].name)}`;
  }

  const lossNote = lostPlayers.map(p =>
    `<div class="loss-banner">💔 <strong>¡${escapeHtml(p.name)} ha perdido!</strong> La cantidad de puntos es: <strong>${p.score}</strong></div>`
  ).join("");

  $("gameArea").innerHTML = `
    <div class="panel game-card">
      <h2 style="margin-top:0;">${title}</h2>
      ${lossNote}
      <div class="scenario">${summaryRows}</div>
      <p style="color:var(--muted); font-size:.9rem;">Ejercitaste tu pensamiento crítico sobre ciberseguridad. ¡Bien hecho!</p>
      <button class="primary full" id="playAgainBtn" type="button">Jugar Nuevamente</button>
    </div>
  `;

  $("playAgainBtn").addEventListener("click", startGame);

  let lastId = null;
  g.players.forEach(p => { lastId = addToLeaderboard(p.name, p.phone, p.score); });
  renderLeaderboard(lastId);
}

// ==================== TABLA DE PUNTAJES (LEADERBOARD) ====================
function loadLeaderboard(){
  try{
    const saved = JSON.parse(localStorage.getItem("qrShieldLeaderboard") || "[]");
    return Array.isArray(saved) ? saved : [];
  }catch{
    localStorage.removeItem("qrShieldLeaderboard");
    return [];
  }
}

function saveLeaderboard(list){
  localStorage.setItem("qrShieldLeaderboard", JSON.stringify(list));
}

function addToLeaderboard(name, phone, score){
  const list = loadLeaderboard();
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  list.push({ id, name, phone, score, date: new Date().toLocaleString("es-ES") });
  list.sort((a, b) => b.score - a.score);
  saveLeaderboard(list.slice(0, 15));
  return id;
}


function renderLeaderboard(highlightId){
  const board = $("leaderboardList");
  if(!board) return;
  const entries = loadLeaderboard();

  if(!entries.length){
    board.innerHTML = `<div class="panel">Todavía no hay puntajes registrados. ¡Sé el primero en jugar!</div>`;
    return;
  }

  const previousTops = {};
  board.querySelectorAll("[data-lid]").forEach(el => {
    previousTops[el.dataset.lid] = el.getBoundingClientRect().top;
  });

  board.innerHTML = entries.map((e, i) => `
    <div class="leaderboard-item ${e.id === highlightId ? "lb-highlight" : ""}" data-lid="${e.id}">
      <span class="lb-rank">#${i + 1}</span>
      <span class="lb-name">${escapeHtml(e.name)}</span>
      <span class="lb-phone">${escapeHtml(e.phone)}</span>
      <span class="lb-score">${e.score} pts</span>
    </div>
  `).join("");

  board.querySelectorAll("[data-lid]").forEach(el => {
    const id = el.dataset.lid;
    const prevTop = previousTops[id];
    if(prevTop != null){
      const newTop = el.getBoundingClientRect().top;
      const delta = prevTop - newTop;
      if(delta && el.animate){
        el.animate([
          { transform: `translateY(${delta}px)` },
          { transform: "translateY(0)" }
        ], { duration: 550, easing: "ease-out" });
      }
    }
  });
}

// MENÚ RESPONSIVO
const menuToggle = document.getElementById("menuToggle");
const mainNav = document.getElementById("mainNav");

if(menuToggle && mainNav){
  menuToggle.addEventListener("click", () => {
    const isOpen = mainNav.classList.toggle("menu-open");
    menuToggle.classList.toggle("active", isOpen);
    menuToggle.setAttribute("aria-expanded", String(isOpen));
    menuToggle.setAttribute("aria-label", isOpen ? "Cerrar menú" : "Abrir menú");
  });
  
  const menuButtons = mainNav.querySelectorAll(".nav-btn");
  menuButtons.forEach(button => {
    button.addEventListener("click", () => {
      menuToggle.classList.remove("active");
      mainNav.classList.remove("menu-open");
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.setAttribute("aria-label", "Abrir menú");
    });
  });
}

// ==================== ALERTA CRÍTICA PARA QR MALICIOSO ====================
function showCriticalAlert(url) {
  // Crear modal rojo crítico
  const modal = document.createElement("div");
  modal.id = "criticalModal";
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    animation: fadeIn 0.3s ease-out;
  `;
  
  const content = document.createElement("div");
  content.style.cssText = `
    background: linear-gradient(135deg, #8b0000 0%, #ff4444 100%);
    border: 2px solid #ff0000;
    border-radius: 1rem;
    padding: clamp(1.1rem, 3vw, 1.6rem);
    width: min(92vw, 430px);
    max-height: 88vh;
    overflow-y: auto;
    text-align: center;
    color: white;
    box-shadow: 0 0 32px rgba(255, 0, 0, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    animation: slideDown 0.4s ease-out;
  `;
  
  content.innerHTML = `
    <div style="font-size: clamp(2.1rem, 9vw, 3.3rem); line-height: 1; margin-bottom: .45rem; animation: pulse 1s infinite;">⚠️</div>
    <h2 style="font-size: clamp(1.45rem, 6vw, 2rem); margin: 0; font-weight: 900; text-transform: uppercase; letter-spacing: 1px;">QR sospechoso</h2>
    <p style="font-size: clamp(.88rem, 3.4vw, 1rem); font-weight: 700; margin: .75rem 0 1rem;">No abras el enlace ni ingreses datos personales.</p>
    <div style="background: rgba(0,0,0,0.25); padding: .75rem; border-radius: .55rem; margin: 0 0 1rem; border-left: 3px solid #ffff00; word-break: break-all;">
      <p style="margin: 0 0 .35rem; font-size: .74rem; opacity: .9;">URL analizada</p>
      <code style="font-size: .72rem; display: block;">${escapeHtml(url)}</code>
    </div>
    <p style="margin: 0 0 1rem; font-size: .8rem;">Verifica el sitio desde una fuente oficial antes de continuar.</p>
    <button onclick="closeCriticalModal()" style="
      width: 100%;
      margin: 0;
      padding: .8rem 1rem;
      font-size: .95rem;
      font-weight: bold;
      background: #ffff00;
      color: #8b0000;
      border: none;
      border-radius: 0.8rem;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: 1px;
      box-shadow: 0 4px 15px rgba(255, 255, 0, 0.5);
      transition: all 0.3s;
    " onmouseover="this.style.background='#ffffff'" onmouseout="this.style.background='#ffff00'">
      ✓ Entendido - Cerrar Alerta
    </button>
  `;
  
  modal.appendChild(content);
  document.body.appendChild(modal);
  
  // Agregar estilos de animación
  if(!document.getElementById("criticalAlertStyles")) {
    const style = document.createElement("style");
    style.id = "criticalAlertStyles";
    style.textContent = `
      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      @keyframes slideDown {
        from { transform: translateY(-50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
      }
    `;
    document.head.appendChild(style);
  }
}

function closeCriticalModal() {
  const modal = document.getElementById("criticalModal");
  if(modal) {
    modal.style.animation = "fadeOut 0.3s ease-out";
    setTimeout(() => modal.remove(), 300);
  }
}

// Mejorar renderResult para mostrar modal si es CRÍTICO
const originalRenderResult = renderResult;
renderResult = function(r) {
  originalRenderResult(r);
  
  // Mostrar una alerta preventiva para resultados de riesgo medio, alto o crítico.
  if(r.score >= 40 && !r.isNonWeb) {
    setTimeout(() => showCriticalAlert(r.url), 500);
  }
};

// INICIALIZAR
renderHistory();
renderLeaderboard();
