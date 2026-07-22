(() => {
  const TOKEN_KEY = "xuexidazi-auth-token";
  const LEGACY_TOKEN_KEYS = ["exam-auth-token"];
  const LOCAL_API_BASE = "http://127.0.0.1:8090";

  const dialog = document.querySelector("#auth-dialog");
  const openButtons = document.querySelectorAll("[data-auth-open]");
  const closeButton = document.querySelector("[data-auth-close]");
  const logoutButton = document.querySelector("[data-auth-logout]");
  const loginButton = document.querySelector(".login-link");
  const userMenu = document.querySelector("[data-auth-user]");
  const userName = document.querySelector("[data-auth-name]");
  const tabButtons = document.querySelectorAll("[data-auth-tab]");
  const forms = document.querySelectorAll("[data-auth-form]");
  const authTitle = document.querySelector("#auth-title");
  const authSubtitle = document.querySelector("#auth-subtitle");
  const message = document.querySelector("[data-auth-message]");

  if (!dialog) return;

  let mode = "login";
  let sessionUser = null;
  let submitting = false;

  function apiBase() {
    const configured = window.STUDYMATE_API_BASE || "";
    const base = configured || (window.location.protocol === "file:" ? LOCAL_API_BASE : "");
    return String(base).replace(/\/$/, "");
  }

  function apiUrl(path) {
    const normalized = path.startsWith("/") ? path : `/${path}`;
    return `${apiBase()}${normalized}`;
  }

  function readToken() {
    try {
      return localStorage.getItem(TOKEN_KEY) || LEGACY_TOKEN_KEYS.map((key) => localStorage.getItem(key)).find(Boolean) || null;
    } catch {
      return null;
    }
  }

  function writeToken(token) {
    try {
      localStorage.setItem(TOKEN_KEY, token);
      LEGACY_TOKEN_KEYS.forEach((key) => localStorage.removeItem(key));
    } catch {
      /* ignore */
    }
  }

  function removeToken() {
    try {
      localStorage.removeItem(TOKEN_KEY);
      LEGACY_TOKEN_KEYS.forEach((key) => localStorage.removeItem(key));
    } catch {
      /* ignore */
    }
  }

  async function apiFetch(path, init = {}, token = readToken()) {
    const headers = new Headers(init.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    return fetch(apiUrl(path), { ...init, headers });
  }

  async function readPayload(response) {
    try {
      return await response.json();
    } catch {
      return {};
    }
  }

  function setSession(token, user) {
    writeToken(token);
    sessionUser = user;
    updateNav();
  }

  function logout() {
    removeToken();
    sessionUser = null;
    updateNav();
  }

  async function bootstrap() {
    const token = readToken();
    if (!token) {
      sessionUser = null;
      updateNav();
      return;
    }

    try {
      const response = await apiFetch("/api/auth/me", {}, token);
      if (!response.ok) {
        logout();
        return;
      }
      const data = await readPayload(response);
      sessionUser = data.user || null;
      updateNav();
    } catch {
      sessionUser = null;
      updateNav();
    }
  }

  function updateNav() {
    if (sessionUser && userName && userMenu && loginButton) {
      userName.textContent = sessionUser.displayName || sessionUser.email;
      userMenu.hidden = false;
      loginButton.hidden = true;
      return;
    }
    if (userMenu && loginButton) {
      userMenu.hidden = true;
      loginButton.hidden = false;
    }
  }

  function setMessage(text, type = "error") {
    if (!message) return;
    message.textContent = text;
    message.hidden = !text;
    message.classList.toggle("success", type === "success");
  }

  function setFormBusy(form, busy, busyText) {
    const submit = form.querySelector(".auth-submit");
    form.querySelectorAll("input, button").forEach((control) => {
      control.disabled = busy;
    });
    if (submit) {
      if (!submit.dataset.idleText) submit.dataset.idleText = submit.textContent || "";
      submit.textContent = busy ? busyText : submit.dataset.idleText;
    }
  }

  function selectMode(nextMode) {
    mode = nextMode === "register" ? "register" : "login";
    if (authTitle) {
      authTitle.textContent = mode === "register" ? "开始学习" : "继续学习";
    }
    if (authSubtitle) {
      authSubtitle.textContent = mode === "register" ? "创建账号，收藏资料并开启工具使用。" : "登录后同步资料、工具和练习记录。";
    }
    tabButtons.forEach((button) => {
      const active = button.dataset.authTab === mode;
      if (button.getAttribute("role") === "tab") {
        button.setAttribute("aria-selected", String(active));
      }
    });
    forms.forEach((form) => {
      form.hidden = form.dataset.authForm !== mode;
    });
    setMessage("");
  }

  function openAuth(nextMode = "login") {
    selectMode(nextMode);
    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }
    const firstInput = dialog.querySelector(`[data-auth-form="${mode}"] input`);
    if (firstInput) firstInput.focus();
  }

  function closeAuth() {
    dialog.close();
    if (window.location.hash === "#login" || window.location.hash === "#register") {
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  function normalizeEmail(value) {
    return value.trim().toLowerCase();
  }

  function validEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  function field(form, name) {
    return form.elements[name] ? String(form.elements[name].value) : "";
  }

  async function submitLogin(form) {
    const email = normalizeEmail(field(form, "email"));
    const password = field(form, "password");
    if (!validEmail(email)) {
      setMessage("请输入有效邮箱。");
      return;
    }
    if (password.length < 8) {
      setMessage("密码至少 8 位。");
      return;
    }

    submitting = true;
    setFormBusy(form, true, "登录中...");
    setMessage("");
    try {
      const response = await apiFetch(
        "/api/auth/login",
        {
          method: "POST",
          body: JSON.stringify({ email, password }),
        },
        null
      );
      const data = await readPayload(response);
      if (!response.ok) {
        setMessage(data.error || "登录失败。");
        return;
      }
      if (!data.token || !data.user) {
        setMessage("登录服务响应无效。");
        return;
      }
      setSession(data.token, data.user);
      setMessage("登录成功。", "success");
      window.setTimeout(closeAuth, 350);
    } catch {
      setMessage("暂时无法连接登录服务。");
    } finally {
      setFormBusy(form, false, "登录中...");
      submitting = false;
    }
  }

  async function submitRegister(form) {
    const displayName = field(form, "displayName").trim().slice(0, 10);
    const email = normalizeEmail(field(form, "email"));
    const password = field(form, "password");
    const confirmPassword = field(form, "confirmPassword");
    if (!validEmail(email)) {
      setMessage("请输入有效邮箱。");
      return;
    }
    if (password.length < 8) {
      setMessage("密码至少 8 位。");
      return;
    }
    if (password !== confirmPassword) {
      setMessage("两次输入的密码不一致。");
      return;
    }

    submitting = true;
    setFormBusy(form, true, "注册中...");
    setMessage("");
    try {
      const response = await apiFetch(
        "/api/auth/register",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
            displayName: displayName || undefined,
          }),
        },
        null
      );
      const data = await readPayload(response);
      if (!response.ok) {
        setMessage(data.error || "注册失败。");
        return;
      }
      if (!data.token || !data.user) {
        setMessage("注册服务响应无效。");
        return;
      }
      setSession(data.token, data.user);
      form.reset();
      setMessage("注册成功。", "success");
      window.setTimeout(closeAuth, 350);
    } catch {
      setMessage("暂时无法连接注册服务。");
    } finally {
      setFormBusy(form, false, "注册中...");
      submitting = false;
    }
  }

  openButtons.forEach((button) => {
    button.addEventListener("click", () => openAuth(button.dataset.authOpen));
  });

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => selectMode(button.dataset.authTab));
  });

  forms.forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (submitting) return;
      if (form.dataset.authForm === "register") {
        void submitRegister(form);
      } else {
        void submitLogin(form);
      }
    });
  });

  closeButton?.addEventListener("click", closeAuth);
  logoutButton?.addEventListener("click", logout);
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) closeAuth();
  });
  dialog.addEventListener("cancel", () => setMessage(""));

  if (window.location.hash === "#login") openAuth("login");
  if (window.location.hash === "#register") openAuth("register");
  void bootstrap();
})();
