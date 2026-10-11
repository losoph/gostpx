let originalData = null;
let clearPasswordFlag = false;
let passwordChanged = false;
let storedDnsDoh = '';

document.addEventListener('DOMContentLoaded', () => {
  loadSettings();

  document.getElementById('btn-check').addEventListener('click', checkConnection);
  document.getElementById('settings-form').addEventListener('submit', saveSettings);
  document.getElementById('btn-cancel').addEventListener('click', closeWindow);
  document.getElementById('btn-clear-password').addEventListener('click', () => {
    clearPasswordFlag = true;
    passwordChanged = true;
    const pwdInput = document.getElementById('proxy_password');
    pwdInput.value = '';
    pwdInput.placeholder = '';
    document.getElementById('btn-clear-password').classList.add('hidden');
  });

  const pwdInput = document.getElementById('proxy_password');
  pwdInput.addEventListener('input', () => {
    passwordChanged = true;
    if (pwdInput.value !== '') {
      clearPasswordFlag = false;
      document.getElementById('btn-clear-password').classList.remove('hidden');
    } else {
      document.getElementById('btn-clear-password').classList.add('hidden');
    }
  });

  ['proxy_type', 'proxy_host', 'proxy_port', 'proxy_user'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', onProxyFieldsChanged);
      el.addEventListener('change', onProxyFieldsChanged);
    }
  });
});

function isProxyChanged() {
  if (!originalData) return false;
  const currentType = document.getElementById('proxy_type').value;
  const currentHost = document.getElementById('proxy_host').value.trim();
  const currentPort = parseInt(document.getElementById('proxy_port').value, 10) || 0;
  const currentUser = document.getElementById('proxy_user').value.trim();

  const origType = originalData.proxy_type || 'socks5';
  const origHost = (originalData.proxy_host || '').trim();
  const origPort = originalData.proxy_port || 0;
  const origUser = (originalData.proxy_user || '').trim();

  return currentType !== origType ||
         currentHost !== origHost ||
         currentPort !== origPort ||
         currentUser !== origUser;
}

function onProxyFieldsChanged() {
  const pwdInput = document.getElementById('proxy_password');
  const clearBtn = document.getElementById('btn-clear-password');
  const hintEl = document.getElementById('proxy-changed-hint');

  if (isProxyChanged()) {
    pwdInput.value = '';
    pwdInput.placeholder = 'пароль';
    passwordChanged = false;
    clearPasswordFlag = false;
    if (clearBtn) clearBtn.classList.add('hidden');
    if (hintEl) {
      hintEl.textContent = 'Прокси изменён — введите пароль нового прокси (если он нужен)';
      hintEl.classList.remove('hidden');
    }
  } else {
    if (!passwordChanged) {
      if (originalData && originalData.has_password) {
        pwdInput.placeholder = '••••••••';
        if (clearBtn) clearBtn.classList.remove('hidden');
      } else {
        pwdInput.placeholder = 'пароль';
        if (clearBtn) clearBtn.classList.add('hidden');
      }
    }
    if (hintEl && hintEl.textContent !== 'Пароль прежнего прокси сброшен') {
      hintEl.classList.add('hidden');
      hintEl.textContent = '';
    }
  }
}

async function loadSettings() {
  passwordChanged = false;
  clearPasswordFlag = false;
  const hintEl = document.getElementById('proxy-changed-hint');
  if (hintEl && hintEl.textContent !== 'Пароль прежнего прокси сброшен') {
    hintEl.classList.add('hidden');
    hintEl.textContent = '';
  }
  try {
    const res = await fetch('/api/settings');
    if (!res.ok) {
      throw new Error(`HTTP error ${res.status}`);
    }
    const data = await res.json();
    originalData = data;

    document.getElementById('mode').value = data.mode || 'sysproxy';
    document.getElementById('proxy_type').value = data.proxy_type || 'socks5';
    document.getElementById('proxy_host').value = data.proxy_host || '';
    document.getElementById('proxy_port').value = data.proxy_port || '';
    document.getElementById('proxy_user').value = data.proxy_user || '';
    storedDnsDoh = data.dns_doh || '';
    const dohEl = document.getElementById('dns_doh');
    if (dohEl) {
      dohEl.value = storedDnsDoh;
    }
    document.getElementById('autostart').checked = !!data.autostart;

    const pwdInput = document.getElementById('proxy_password');
    const clearBtn = document.getElementById('btn-clear-password');
    const credErrEl = document.getElementById('credentials-error');
    if (data.credentials_error) {
      credErrEl.textContent = `⚠ Ошибка чтения пароля: ${data.credentials_error}`;
      credErrEl.classList.remove('hidden');
      pwdInput.placeholder = 'ошибка чтения';
      clearBtn.classList.add('hidden');
    } else {
      credErrEl.classList.add('hidden');
      if (data.has_password) {
        pwdInput.placeholder = '••••••••';
        clearBtn.classList.remove('hidden');
      } else {
        pwdInput.placeholder = 'пароль';
        clearBtn.classList.add('hidden');
      }
    }

    if (!data.config_writable) {
      document.getElementById('readonly-banner').classList.remove('hidden');
      disableInputs(true);
    } else {
      document.getElementById('readonly-banner').classList.add('hidden');
      disableInputs(false);
    }
  } catch (err) {
    console.error('Failed to load settings:', err);
    showSaveStatus(`Ошибка загрузки: ${err.message}`, true);
  }
}

function disableInputs(disabled) {
  const form = document.getElementById('settings-form');
  const elements = form.querySelectorAll('input:not(#proxy_password), select');
  elements.forEach(el => el.disabled = disabled);
  document.getElementById('proxy_password').disabled = disabled;
  document.getElementById('btn-clear-password').disabled = disabled;
  document.getElementById('btn-save').disabled = disabled;
}

async function checkConnection() {
  const statusEl = document.getElementById('check-status');
  statusEl.className = 'status-indicator testing';
  statusEl.textContent = 'Проверка…';

  const host = document.getElementById('proxy_host').value.trim();
  const port = parseInt(document.getElementById('proxy_port').value, 10);
  const type = document.getElementById('proxy_type').value;
  const user = document.getElementById('proxy_user').value.trim();
  const password = document.getElementById('proxy_password').value;

  if (!host || isNaN(port) || port <= 0) {
    statusEl.className = 'status-indicator error';
    statusEl.textContent = '✗ Укажите хост и порт';
    return;
  }

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type,
        host,
        port,
        user,
        password,
        password_changed: passwordChanged
      })
    });
    const result = await res.json();
    if (result.ok) {
      statusEl.className = 'status-indicator success';
      statusEl.textContent = `✓ Доступен (${result.rtt_ms} мс)`;
    } else {
      statusEl.className = 'status-indicator error';
      statusEl.textContent = `✗ ${result.error || 'Недоступен'}`;
    }
  } catch (err) {
    statusEl.className = 'status-indicator error';
    statusEl.textContent = `✗ Ошибка: ${err.message}`;
  }
}

async function saveSettings(e) {
  e.preventDefault();
  const saveBtn = document.getElementById('btn-save');
  saveBtn.disabled = true;
  showSaveStatus('Сохранение…', false);

  const payload = {
    mode: document.getElementById('mode').value,
    proxy_type: document.getElementById('proxy_type').value,
    proxy_host: document.getElementById('proxy_host').value.trim(),
    proxy_port: parseInt(document.getElementById('proxy_port').value, 10) || 0,
    proxy_user: document.getElementById('proxy_user').value.trim(),
    dns_doh: storedDnsDoh,
    autostart: document.getElementById('autostart').checked,
    password: document.getElementById('proxy_password').value,
    password_changed: passwordChanged,
    clear_password: clearPasswordFlag
  };

  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    if (!res.ok || !result.success) {
      throw new Error(result.error || `HTTP ${res.status}`);
    }
    const hintEl = document.getElementById('proxy-changed-hint');
    if (result.password_cleared) {
      showSaveStatus('Пароль прежнего прокси сброшен', false, true);
      if (hintEl) {
        hintEl.textContent = 'Пароль прежнего прокси сброшен';
        hintEl.classList.remove('hidden');
        setTimeout(() => {
          if (hintEl.textContent === 'Пароль прежнего прокси сброшен') {
            hintEl.classList.add('hidden');
            hintEl.textContent = '';
          }
        }, 3000);
      }
    } else {
      showSaveStatus('Сохранено ✓', false, true);
      if (hintEl) {
        hintEl.classList.add('hidden');
        hintEl.textContent = '';
      }
    }
    setTimeout(() => {
      loadSettings();
    }, 500);
  } catch (err) {
    console.error('Save failed:', err);
    showSaveStatus(`Ошибка: ${err.message}`, true);
  } finally {
    saveBtn.disabled = false;
  }
}

function showSaveStatus(msg, isError, isSuccess) {
  const el = document.getElementById('save-status');
  el.textContent = msg;
  if (isError) {
    el.className = 'save-status error';
  } else if (isSuccess) {
    el.className = 'save-status success';
    setTimeout(() => {
      if (el.textContent === msg) {
        el.textContent = '';
      }
    }, 3000);
  } else {
    el.className = 'save-status';
  }
}

function closeWindow() {
  if (window.wails && window.wails.Window && typeof window.wails.Window.Close === 'function') {
    window.wails.Window.Close();
  } else {
    window.close();
  }
}
