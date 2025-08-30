// static/main.js — robust UI + QR scan fallback
(() => {
  const $ = id => document.getElementById(id);

  // DOM elements
  const initBtn = $('initBtn');
  const unlockBtn = $('unlockBtn');
  const fab = $('fab');
  const accountsDiv = $('accounts');

  const addDialog = $('addDialog');
  const uriInput = $('uriInput');
  const secretInput = $('secretInput');
  const issuerInput = $('issuerInput');
  const labelInput = $('labelInput');
  const addConfirmBtn = $('addConfirmBtn');
  const addCancelBtn = $('addCancelBtn');
  const scanQrBtn = $('scanQrBtn');
  const fileInput = $('fileInput');

  const qrCamera = $('qrCamera');
  const video = $('video');
  const qrCanvas = $('qrCanvas');
  const qrStop = $('qrStop');

  let password = null;
  let accounts = [];
  let ticker = null;
  let streamRef = null;

  function show(el){ el.classList.remove('hidden'); }
  function hide(el){ el.classList.add('hidden'); }
  function api(path, data){ return fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)}).then(r=>r.json()); }

  // Init vault
  initBtn.onclick = async () => {
    const pw = prompt('Create a master password for your vault:');
    if(!pw) return;
    const r = await api('/api/init', {password: pw});
    if(r.ok) alert('Vault created');
    else alert('Error: ' + (r.error || 'unknown'));
  };

  // Unlock vault (returns accounts)
  unlockBtn.onclick = async () => {
    const pw = prompt('Master password:');
    if(!pw) return;
    const r = await api('/api/unlock', {password: pw});
    if(!r.ok){ alert('Error: ' + (r.error||'')); return; }
    password = pw;
    accounts = r.accounts || [];
    renderAccounts();
    startTicker();
  };

  // open Add dialog
  fab.onclick = () => show(addDialog);
  addCancelBtn.onclick = () => hide(addDialog);

  // Add confirm
  addConfirmBtn.onclick = async () => {
    if(!password){ alert('Unlock the vault first'); return; }
    const uri = uriInput.value.trim();
    const secret = secretInput.value.trim();
    const issuer = issuerInput.value.trim();
    const label = labelInput.value.trim();
    if(!uri && !secret){ alert('Provide otpauth URI or secret'); return; }

    let accountPayload;
    if(uri){
      try{
        const u = new URL(uri);
        const params = Object.fromEntries(u.searchParams.entries());
        const rawLabel = decodeURIComponent(u.pathname.replace(/^\//,''));
        let issuerFromLabel = null, lab = rawLabel;
        if(rawLabel.includes(':')) [issuerFromLabel, lab] = rawLabel.split(':',2);
        accountPayload = {
          issuer: params.issuer || issuerFromLabel || null,
          label: lab || label || 'Account',
          secret: params.secret || params['secret'],
          digits: params.digits || 6,
          period: params.period || 30,
          algorithm: params.algorithm || 'SHA1'
        };
      }catch(e){
        alert('Bad otpauth URI');
        return;
      }
    } else {
      accountPayload = { issuer: issuer || null, label: label || 'Account', secret: secret, digits: 6, period: 30, algorithm: 'SHA1' };
    }

    const r = await api('/api/add', {password, account: accountPayload});
    if(!r.ok){ alert('Add failed: ' + (r.error||'')); return; }
    accounts.push(r.account);
    hide(addDialog);
    renderAccounts();
  };

  // Render accounts
  function renderAccounts(){
    accountsDiv.innerHTML = '';
    accounts.forEach(a => {
      const card = document.createElement('div'); card.className = 'account';
      const name = document.createElement('div'); name.className = 'account-name'; name.textContent = a.issuer ? (a.issuer + ' · ' + a.label) : a.label;
      const code = document.createElement('div'); code.className = 'code'; code.id = `code-${a.id}`; code.textContent = '------';
      const controls = document.createElement('div'); controls.className = 'row';
      const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy'; copyBtn.onclick = async () => {
        const r = await api('/api/code', {password, id: a.id});
        if(r.ok){ navigator.clipboard.writeText(r.code); alert('Copied ' + r.code); } else alert('Error: ' + (r.error||''));
      };
      const removeBtn = document.createElement('button'); removeBtn.textContent = 'Remove'; removeBtn.onclick = async () => {
        if(!confirm('Remove account?')) return;
        const r = await api('/api/remove', {password, id: a.id});
        if(r.ok){ accounts = accounts.filter(x => x.id !== a.id); renderAccounts(); } else alert('Error: ' + (r.error||''));
      };
      controls.appendChild(copyBtn); controls.appendChild(removeBtn);
      card.appendChild(name); card.appendChild(code); card.appendChild(controls);
      accountsDiv.appendChild(card);
    });
  }

  // Ticker: update codes every second (requests each account code once per second)
  function startTicker(){
    if(ticker) clearInterval(ticker);
    if(!password) return;
    const tick = async () => {
      for(const a of accounts){
        try{
          const r = await api('/api/code', {password, id: a.id});
          if(r.ok){
            const el = $(`code-${a.id}`);
            if(el) el.textContent = r.code;
          }
        }catch(e){
          console.error('code fetch', e);
        }
      }
    };
    tick();
    ticker = setInterval(tick, 1000);
  }

  // --- QR scanning using getUserMedia + jsQR + fallback file input ---
  function stopCamera(){
    if(streamRef){
      streamRef.getTracks().forEach(t=>t.stop());
      streamRef = null;
    }
    hide(qrCamera);
  }

  async function startCameraScan(){
    try{
      show(qrCamera);
      const stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}});
      streamRef = stream;
      video.srcObject = stream;
      await video.play();

      // ensure canvas size matches video
      qrCanvas.width = video.videoWidth || 320;
      qrCanvas.height = video.videoHeight || 240;
      const ctx = qrCanvas.getContext('2d');

      let scanning = true;
      const loop = () => {
        if(!scanning) return;
        if(video.readyState === video.HAVE_ENOUGH_DATA){
          qrCanvas.width = video.videoWidth;
          qrCanvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0, qrCanvas.width, qrCanvas.height);
          const img = ctx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
          const code = jsQR(img.data, img.width, img.height);
          if(code){
            scanning = false;
            stopCamera();
            uriInput.value = code.data;
            show(addDialog);
            return;
          }
        }
        requestAnimationFrame(loop);
      };
      requestAnimationFrame(loop);
    }catch(err){
      console.error('Camera start error:', err);
      alert('Unable to access camera. Use the file upload fallback or open on desktop localhost.');
      hide(qrCamera);
    }
  }

  qrStop.onclick = () => stopCamera();
  scanQrBtn.onclick = () => startCameraScan();

  // File input fallback: upload image, parse with jsQR
  fileInput.onchange = async (ev) => {
    const f = ev.target.files && ev.target.files[0];
    if(!f) return;
    const img = new Image();
    img.onload = () => {
      const canvas = qrCanvas;
      const ctx = canvas.getContext('2d');
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imgData.data, canvas.width, canvas.height);
      if(code){ uriInput.value = code.data; show(addDialog); }
      else alert('No QR detected in image.');
    };
    img.onerror = () => alert('Failed to read image file.');
    img.src = URL.createObjectURL(f);
  };

  // Start minimal UI state
  hide(addDialog);
  hide(qrCamera);

  // OPTIONAL: if you want debug log visible in page (helpful)
  window._debug = { accounts };

})();
