// ----- DOM Elements -----
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

const masterPass = $("#masterPass"), unlockBtn = $("#unlockBtn"), lockBtn = $("#lockBtn"), changeMasterBtn = $("#changeMasterBtn");
const masterPassStrength = $("#masterPassStrength");
const genBtn = $("#genBtn"), generated = $("#generated"), genLen = $("#genLen"), copyGenBtn = $("#copyGenBtn");
const gUpper = $("#gUpper"), gLower = $("#gLower"), gDigits = $("#gDigits"), gSymbols = $("#gSymbols");
const entryTitle = $("#entryTitle"), entryUser = $("#entryUser"), entryPass = $("#entryPass");
const addBtn = $("#addBtn"), fillGen = $("#fillGen"), clearBtn = $("#clearBtn");
const listEl = $("#list"), status = $("#status"), search = $("#search"), lastBackupStatus = $("#lastBackupStatus");
const exportBtn = $("#exportBtn"), importBtn = $("#importBtn"), importFile = $("#importFile"), clearAll = $("#clearAll");
const auditBtn = $("#auditBtn"), auditResults = $("#auditResults");
const modal = $("#modal"), modalText = $("#modal-text"), modalInput = $("#modal-input"), modalButtons = $("#modal-buttons");
const helpBtn = $("#helpBtn");

// ----- App State -----
let vault = [];
let key = null;
let salt = null;
const DB_NAME = "ArxVaultDB";
const STORE_NAME = "vaultStore";
const STORAGE_KEY = "arx_vault_v1";
const LAST_BACKUP_KEY = "arx_vault_last_backup";
const INACTIVITY_TIMEOUT = 5 * 60 * 1000; // 5 minutos em milissegundos
let inactivityTimer;
let failedAttempts = 0;
const MAX_FAILED_ATTEMPTS = 3;
const BASE_DELAY_MS = 1000; // 1 segundo
const MIN_MASTER_LENGTH = 12; // Mínimo para senha mestra
const MIN_MASTER_STRENGTH = 3; // Força mínima (de 0 a 4)

// ----- IndexedDB Helpers -----
async function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1); // Versão fixa, mas lida com upgrades
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "key" });
      }
    };
    request.onsuccess = (event) => {
      const db = event.target.result;
      if (db.version > 1) {
        db.close();
        const upgradeRequest = indexedDB.open(DB_NAME, db.version);
        upgradeRequest.onsuccess = () => resolve(upgradeRequest.result);
        upgradeRequest.onerror = () => reject(upgradeRequest.error);
      } else {
        resolve(db);
      }
    };
    request.onerror = (event) => reject(event.target.error);
  });
}

async function getFromDB(keyValue) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readonly");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(keyValue);
    request.onsuccess = () => resolve(request.result ? request.result.value : null);
    request.onerror = () => reject(request.error);
  });
}

async function setToDB(keyValue, value) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put({ key: keyValue, value });
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function removeFromDB(keyValue) {
  const db = await initDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(keyValue);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// ----- Helpers -----
const utf8 = new TextEncoder();
const dec = new TextDecoder();
const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromBase64 = (str) => { const bin = atob(str); const arr = new Uint8Array(bin.length); for(let i=0; i<bin.length; i++) arr[i] = bin.charCodeAt(i); return arr.buffer; };
const randBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const escapeHTML = (str) => str.replace(/[&<>'"`]/g, (match) => {
  const escape = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    '\u0027': '&#x27;',
    '`': '&#x60;'
  };
  return escape[match];
});

// ----- Crypto -----
const deriveKey = async (master, salt, iterations = 250000) => {
  const baseKey = await crypto.subtle.importKey('raw', utf8.encode(master), {name: 'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', salt, iterations, hash: 'SHA-256'}, baseKey, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
};
const encryptVault = async (vaultObj, key) => {
  const iv = randBytes(12);
  const data = utf8.encode(JSON.stringify(vaultObj));
  const ct = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, data);
  return {iv: toBase64(iv), ct: toBase64(ct)};
};
const decryptVault = async (encrypted, key) => {
  const iv = fromBase64(encrypted.iv);
  const ct = fromBase64(encrypted.ct);
  const plain = await crypto.subtle.decrypt({name: 'AES-GCM', iv: new Uint8Array(iv)}, key, ct);
  return JSON.parse(dec.decode(plain));
};

// ----- Modal Logic -----
const showModal = (text, options = {}) => {
  return new Promise(resolve => {
    modalText.textContent = text;
    modalInput.style.display = options.prompt ? 'block' : 'none';
    modalInput.value = '';
    modalInput.type = options.inputType || 'password';
    modalButtons.innerHTML = '';

    options.buttons.forEach(btn => {
      const button = document.createElement('button');
      button.textContent = btn.text;
      button.className = btn.class || '';
      button.onclick = () => {
        modal.classList.remove('visible');
        modal.removeAttribute('inert'); // Remove inert ao fechar
        resolve(btn.value(modalInput.value));
      };
      modalButtons.appendChild(button);
    });
    modal.classList.add('visible');
    modal.removeAttribute('inert'); // Remove inert ao abrir
    if(options.prompt) modalInput.focus();
  });
};
const notify = (text) => showModal(text, { buttons: [{text: 'OK', value: () => true}] });
const confirmAction = (text) => showModal(text, { buttons: [{text: 'Cancelar', value: () => false}, {text: 'Confirmar', class: 'btn-danger', value: () => true}] });
const promptInput = (text, type = 'password') => showModal(text, { prompt: true, inputType: type, buttons: [{text: 'Cancelar', value: (val) => null}, {text: 'OK', value: (val) => val}] });

// ----- Tutorial Modal -----
const showTutorial = () => {
  const tutorialText = `Bem-vindo ao ArxVault!\n\n- Crie uma senha mestra forte (mín. 12 caracteres).\n- Adicione entradas com título, usuário e senha.\n- Gere senhas seguras no painel esquerdo.\n- Faça backups regulares exportando o cofre.\n- A auditoria verifica senhas fracas ou reutilizadas.\n- O cofre bloqueia após 5 min de inatividade.\n\nPara mais ajuda, clique em "Ajuda" no header.`;
  notify(tutorialText);
};

// ----- Inactivity Lock -----
const resetInactivityTimer = () => {
  clearTimeout(inactivityTimer);
  if (key) { // Only set timer if vault is unlocked
    inactivityTimer = setTimeout(() => {
      updateUIState(true);
      notify('Cofre bloqueado automaticamente por inatividade.');
    }, INACTIVITY_TIMEOUT);
  }
};

// ----- UI Rendering & State -----
const updateUIState = (isLocked) => {
  key = isLocked ? null : key;
  salt = isLocked ? null : salt;
  vault = isLocked ? [] : vault;

  $$('input, button').forEach(el => {
    if (!el.closest('#authArea, header, footer, .modal-overlay')) {
      el.disabled = isLocked;
    }
  });
  
  masterPass.disabled = !isLocked;
  unlockBtn.disabled = !isLocked;
  lockBtn.disabled = isLocked;
  changeMasterBtn.disabled = isLocked;
  auditBtn.disabled = isLocked;

  if (isLocked) {
    status.textContent = 'Estado: Bloqueado';
    listEl.innerHTML = '<div class="entry-item" style="justify-content: center; color: var(--text-secondary);">Cofre bloqueado.</div>';
    addBtn.textContent = 'Adicionar Entrada';
    delete addBtn.dataset.edit;
    [entryTitle, entryUser, entryPass, search, generated].forEach(el => el.value = '');
    updateLastBackupStatus();
    clearTimeout(inactivityTimer);
    auditResults.innerHTML = '';
  } else {
    status.textContent = `Estado: Desbloqueado — ${vault.length} entrada(s)`;
    renderList();
    updateLastBackupStatus();
    resetInactivityTimer();
  }
};

const updateLastBackupStatus = async () => {
  const lastBackupTime = await getFromDB(LAST_BACKUP_KEY);
  if (lastBackupTime) {
    const lastBackupDate = new Date(parseInt(lastBackupTime));
    const now = new Date();
    const diffTime = Math.abs(now - lastBackupDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    lastBackupStatus.textContent = `Último backup: ${diffDays === 0 ? 'hoje' : `${diffDays} dia(s) atrás`}.`;
  } else {
    lastBackupStatus.textContent = 'Nenhum backup registrado.';
  }
};

const renderList = (filter = '') => {
  listEl.innerHTML = '';
  const f = filter.trim().toLowerCase();
  const items = vault.filter(it => !f || (it.title + it.user).toLowerCase().includes(f));

  if (items.length === 0) {
    listEl.innerHTML = `<div class="entry-item" style="justify-content: center; color: var(--text-secondary);">${filter ? 'Nenhum resultado' : 'Nenhuma entrada no cofre.'}</div>`;
    return;
  }

  items.forEach(it => {
    const el = document.createElement('div');
    el.className = 'entry-item';
    el.setAttribute('role', 'listitem');
    el.innerHTML = `
      <div class="meta">
        <div class="title">${escapeHTML(it.title)}</div>
        <div class="user">${escapeHTML(it.user || '')}</div>
      </div>
      <div class="controls">
        <button class="btn-secondary btn-view" aria-label="Ver senha de ${escapeHTML(it.title)}">Ver</button>
        <button class="btn-secondary btn-copy" aria-label="Copiar senha de ${escapeHTML(it.title)}">Copiar</button>
        <button class="btn-secondary btn-edit" aria-label="Editar entrada ${escapeHTML(it.title)}">Editar</button>
        <button class="btn-danger btn-delete" aria-label="Excluir entrada ${escapeHTML(it.title)}">Excluir</button>
      </div>`;
    
    el.querySelector('.btn-view').onclick = () => notify(`Senha: ${it.pass}\nUsuário: ${it.user || ''}`);
    el.querySelector('.btn-copy').onclick = async (e) => {
      try {
        await navigator.clipboard.writeText(it.pass);
        const btn = e.target;
        btn.textContent = 'Copiado!';
        setTimeout(() => {
          btn.textContent = 'Copiar';
          clearClipboard();
        }, 1500);
      } catch (err) { notify('Erro ao copiar senha.'); }
    };
    el.querySelector('.btn-edit').onclick = () => {
      entryTitle.value = it.title;
      entryUser.value = it.user;
      entryPass.value = it.pass;
      addBtn.dataset.edit = it.id;
      addBtn.textContent = 'Salvar Alterações';
      entryTitle.focus();
    };
    el.querySelector('.btn-delete').onclick = async () => {
      if (!await confirmAction(`Tem certeza que deseja excluir a entrada "${escapeHTML(it.title)}"?`)) return;
      vault = vault.filter(x => x.id !== it.id);
      saveVault();
      renderList(search.value);
    };
    listEl.appendChild(el);
  });
};

// ----- Vault Operations -----
const saveVault = async () => {
  if (!key) return;
  const enc = await encryptVault(vault, key);
  const payload = { salt: toBase64(salt), encrypted: enc };
  await setToDB(STORAGE_KEY, JSON.stringify(payload));
  status.textContent = `Estado: Desbloqueado — ${vault.length} entrada(s)`;
  resetInactivityTimer();
};

const unlock = async () => {
  const pass = masterPass.value;
  if (!pass) { notify('Por favor, digite a senha mestra.'); return; }

  if (pass.length < MIN_MASTER_LENGTH) {
    notify(`Senha mestra deve ter pelo menos ${MIN_MASTER_LENGTH} caracteres.`);
    return;
  }
  const strength = calculateStrength(pass);
  if (strength < MIN_MASTER_STRENGTH) {
    notify('Senha mestra deve ser pelo menos "média" em força (inclua maiúsculas, números e símbolos).');
    return;
  }

  const delay = BASE_DELAY_MS * Math.pow(2, failedAttempts);
  if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
    notify(`Muitas tentativas falhas. Tente novamente em ${delay / 1000} segundos.`);
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  const stored = await getFromDB(STORAGE_KEY);
  const parsedStored = stored ? JSON.parse(stored) : null;
  if (parsedStored) {
    try {
      salt = fromBase64(parsedStored.salt);
      key = await deriveKey(pass, salt);
      vault = await decryptVault(parsedStored.encrypted, key);
      masterPass.value = '';
      failedAttempts = 0;
      updateUIState(false);
      notify('Cofre desbloqueado com sucesso!');
    } catch (e) {
      failedAttempts++;
      key = null;
      notify('Senha mestra incorreta ou cofre corrompido.');
    }
  } else {
    if (await confirmAction('Nenhum cofre encontrado. Deseja criar um novo com a senha mestra fornecida?')) {
      salt = randBytes(16);
      key = await deriveKey(pass, salt);
      vault = [];
      await saveVault();
      masterPass.value = '';
      failedAttempts = 0;
      updateUIState(false);
      notify('Novo cofre criado e desbloqueado!');
    } else {
      failedAttempts++;
    }
  }
};

const calculateStrength = (password) => {
  let strength = 0;
  if (password.length > 7) strength++;
  if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
  if (password.match(/\d/)) strength++;
  if (password.match(/[^a-zA-Z\d]/)) strength++;
  return strength;
};

// ----- Password Strength Indicator -----
const checkPasswordStrength = (password) => {
  let strength = calculateStrength(password);

  masterPassStrength.className = 'password-strength-indicator';
  const strengthBar = masterPassStrength.querySelector('div');
  strengthBar.style.width = '0%';

  if (password.length === 0) {
    strengthBar.style.width = '0%';
  } else if (strength < 2) {
    masterPassStrength.classList.add('weak');
  } else if (strength === 2 || strength === 3) {
    masterPassStrength.classList.add('medium');
  } else if (strength >= 4) {
    masterPassStrength.classList.add('strong');
  }
};

// ----- Clipboard Clearing -----
const clearClipboard = () => {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText('').then(() => {
      console.log('Área de transferência limpa.');
    }).catch(err => {
      console.warn('Falha ao limpar a área de transferência:', err);
    });
  }
};

// ----- Password Audit -----
const runPasswordAudit = () => {
  auditResults.innerHTML = '';
  if (vault.length === 0) {
    auditResults.innerHTML = '<p class="info">Nenhuma senha para auditar.</p>';
    return;
  }

  let weakPasswords = 0;
  let reusedPasswords = 0;
  let oldPasswords = 0;
  const passwordMap = new Map();
  const now = new Date();

  vault.forEach(entry => {
    const pass = entry.pass;
    const updatedDate = new Date(entry.updated);

    let strength = calculateStrength(pass);
    if (strength < 3) {
      weakPasswords++;
      auditResults.innerHTML += `<p class="issue">Senha fraca: ${escapeHTML(entry.title)}</p>`;
    }

    if (passwordMap.has(pass)) {
      reusedPasswords++;
      auditResults.innerHTML += `<p class="issue">Senha reutilizada: ${escapeHTML(entry.title)} (também em ${escapeHTML(passwordMap.get(pass))})</p>`;
    } else {
      passwordMap.set(pass, entry.title);
    }

    const daysSinceUpdate = Math.ceil(Math.abs(now - updatedDate) / (1000 * 60 * 60 * 24));
    if (daysSinceUpdate > 180) {
      oldPasswords++;
      auditResults.innerHTML += `<p class="issue">Senha antiga: ${escapeHTML(entry.title)} (última atualização há ${daysSinceUpdate} dias)</p>`;
    }
  });

  if (weakPasswords === 0 && reusedPasswords === 0 && oldPasswords === 0) {
    auditResults.innerHTML = '<p class="info">Nenhum problema encontrado na auditoria de senhas!</p>';
  } else {
    auditResults.innerHTML = `<p class="info">Auditoria concluída. Problemas encontrados:</p>` + auditResults.innerHTML;
  }
};

// ----- Event Listeners -----
unlockBtn.onclick = unlock;
masterPass.onkeydown = (e) => { if (e.key === 'Enter') unlock(); };
masterPass.oninput = (e) => checkPasswordStrength(e.target.value);
lockBtn.onclick = async () => { if (await confirmAction('Deseja bloquear o cofre?')) updateUIState(true); };

genBtn.onclick = () => {
  const len = Math.max(4, Math.min(128, parseInt(genLen.value) || 20));
  const pool = (gUpper.checked ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '') +
               (gLower.checked ? 'abcdefghijklmnopqrstuvwxyz' : '') +
               (gDigits.checked ? '0123456789' : '') +
               (gSymbols.checked ? '!@#$%^&*()-_=+[]{};:,.<>?/~' : '');
  if (!pool) { notify('Selecione ao menos um tipo de caractere para gerar a senha.'); return; }
  const rand = new Uint32Array(len);
  crypto.getRandomValues(rand);
  generated.value = Array.from(rand, r => pool[r % pool.length]).join('');
};

copyGenBtn.onclick = async (e) => {
  if (!generated.value) return;
  await navigator.clipboard.writeText(generated.value);
  const btn = e.target;
  btn.textContent = 'Copiado!';
  setTimeout(() => {
    btn.textContent = 'Copiar';
    clearClipboard();
  }, 1500);
};

fillGen.onclick = () => { if (generated.value) entryPass.value = generated.value; };
clearBtn.onclick = () => {
  [entryTitle, entryUser, entryPass].forEach(el => el.value = '');
  delete addBtn.dataset.edit;
  addBtn.textContent = 'Adicionar Entrada';
};

addBtn.onclick = () => {
  if (!key) { notify('Desbloqueie o cofre primeiro.'); return; }
  const title = entryTitle.value.trim();
  if (!title) { notify('O campo "Título" é obrigatório.'); return; }
  
  const id = addBtn.dataset.edit || Math.random().toString(36).slice(2, 10);
  const now = new Date().toISOString();
  const existing = vault.find(x => x.id === id);

  if (existing) {
    Object.assign(existing, { title, user: entryUser.value.trim(), pass: entryPass.value, updated: now });
    delete addBtn.dataset.edit;
    addBtn.textContent = 'Adicionar Entrada';
  } else {
    vault.push({ id, title, user: entryUser.value.trim(), pass: entryPass.value, created: now, updated: now });
  }
  saveVault();
  renderList(search.value);
  [entryTitle, entryUser, entryPass].forEach(el => el.value = '');
};

search.oninput = () => renderList(search.value);

exportBtn.onclick = async () => {
  const raw = await getFromDB(STORAGE_KEY);
  if (!raw) { notify('Cofre vazio. Nada para exportar.'); return; }
  const blob = new Blob([raw], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'arxvault_backup.json';
  a.click();
  URL.revokeObjectURL(url);
  await setToDB(LAST_BACKUP_KEY, Date.now().toString());
  updateLastBackupStatus();
};

importBtn.onclick = () => importFile.click();
importFile.onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    const txt = await f.text();
    const parsed = JSON.parse(txt);
    if (!parsed || typeof parsed.salt !== 'string' || typeof parsed.encrypted !== 'object' ||
        typeof parsed.encrypted.iv !== 'string' || typeof parsed.encrypted.ct !== 'string') {
      notify('Arquivo de backup inválido ou corrompido.');
      return;
    }
    if (await confirmAction('Isso substituirá seu cofre atual. Deseja continuar?')) {
      await setToDB(STORAGE_KEY, JSON.stringify(parsed));
      updateUIState(true);
      notify('Cofre importado com sucesso. Desbloqueie com a senha mestra correspondente.');
    }
  } catch (er) { notify('Erro ao ler o arquivo.'); }
  importFile.value = '';
};

clearAll.onclick = async () => {
  if (await confirmAction('ATENÇÃO: ISSO APAGARÁ PERMANENTEMENTE TODO O SEU COFRE. Deseja continuar?')) {
    await removeFromDB(STORAGE_KEY);
    await removeFromDB(LAST_BACKUP_KEY);
    updateUIState(true);
    notify('Cofre apagado.');
  }
};

changeMasterBtn.onclick = async () => {
  if (!key) { notify('Desbloqueie o cofre primeiro.'); return; }
  const current = await promptInput('Digite a senha mestra ATUAL para confirmar:');
  if (!current) return;

  try {
    const testKey = await deriveKey(current, salt);
    await decryptVault(JSON.parse(await getFromDB(STORAGE_KEY)).encrypted, testKey);
  } catch (e) { notify('Senha mestra atual incorreta.'); return; }

  const novo = await promptInput('Digite a NOVA senha mestra:');
  if (!novo) return;
  const confirmNovo = await promptInput('Confirme a NOVA senha mestra:');
  if (novo !== confirmNovo) { notify('As novas senhas não coincidem.'); return; }

  const newSalt = randBytes(16);
  const newKey = await deriveKey(novo, newSalt);
  
  const currentVaultData = await decryptVault(JSON.parse(await getFromDB(STORAGE_KEY)).encrypted, key);
  const newEncryptedVault = await encryptVault(currentVaultData, newKey);

  await setToDB(STORAGE_KEY, JSON.stringify({ salt: toBase64(newSalt), encrypted: newEncryptedVault }));
  salt = newSalt;
  key = newKey;
  notify('Senha mestra alterada com sucesso!');
};

auditBtn.onclick = runPasswordAudit;

// ----- Help Button -----
helpBtn.onclick = showTutorial;

// ----- Initial Load -----
document.addEventListener('DOMContentLoaded', async () => {
  updateUIState(true); // Start in locked state
  const stored = await getFromDB(STORAGE_KEY);
  if (stored) {
    unlockBtn.textContent = 'Desbloquear';
  } else {
    unlockBtn.textContent = 'Criar Cofre';
    masterPass.placeholder = 'Crie sua senha mestra';
    showTutorial(); // Mostra tutorial na primeira vez
  }
  updateLastBackupStatus();

  // Add global event listeners for inactivity
  document.addEventListener('mousemove', resetInactivityTimer);
  document.addEventListener('keydown', resetInactivityTimer);
  document.addEventListener('click', resetInactivityTimer);

  // Initial check for password strength if there's a value (e.g., from browser autofill)
  checkPasswordStrength(masterPass.value);
});