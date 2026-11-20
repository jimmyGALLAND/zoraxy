(async () => {
  if (
    window.top !== window ||
    document.getElementById("skynet-sso-bar")
  ) {
    return;
  }

  const allowed = await browser.runtime.sendMessage({
    type: "SKYNET_SSO_IS_HOST_ALLOWED",
    host: location.hostname
  }).catch(() => false);

  if (!allowed || document.getElementById("skynet-sso-bar")) {
    return;
  }

  const prefs = await browser.storage.local.get({
    showNotch: true
  });

  const bar = document.createElement("aside");
  bar.id = "skynet-sso-bar";
  bar.dataset.collapsed = "false";
  bar.dataset.showNotch = String(prefs.showNotch !== false);
  bar.setAttribute("aria-live", "polite");

  bar.innerHTML = `
    <button
      class="skynet-sso-brand"
      type="button"
      title="Accueil SKYNET"
    >
      <img
        class="skynet-sso-mark"
        src="${browser.runtime.getURL("icons/skynet.png")}"
        alt=""
      >
      <span>SKYNET <b>SSO</b></span>
    </button>

    <div class="skynet-sso-status">
      <i></i>
      <span class="skynet-sso-label">Vérification de la session…</span>
    </div>

    <div class="skynet-sso-user"></div>

    <div class="skynet-sso-actions">
      <button class="skynet-sso-logout" type="button" hidden>
        Déconnexion
      </button>

      <button
        class="skynet-sso-collapse"
        type="button"
        aria-label="Masquer la barre SKYNET"
        title="Masquer la barre"
      >
        <span aria-hidden="true"></span>
      </button>
    </div>

    <button
      class="skynet-sso-tab"
      type="button"
      aria-label="Afficher la barre SKYNET"
      title="Afficher la barre"
    ><span aria-hidden="true"></span></button>
  `;

  document.documentElement.appendChild(bar);

  const label = bar.querySelector(".skynet-sso-label");
  const user = bar.querySelector(".skynet-sso-user");
  const logout = bar.querySelector(".skynet-sso-logout");
  const tab = bar.querySelector(".skynet-sso-tab");
  const collapse = bar.querySelector(".skynet-sso-collapse");
  const brand = bar.querySelector(".skynet-sso-brand");

  brand.addEventListener("click", async event => {
    event.preventDefault();
    event.stopPropagation();

    const cfg = await browser.storage.local.get({
      homeUrl: "https://celjim.fr"
    });

    const destination = String(
      cfg.homeUrl || "https://celjim.fr"
    ).trim();

    if (/^https?:\/\//i.test(destination)) {
      window.location.assign(destination);
    }
  });

  document.addEventListener("click", event => {
    if (
      bar.dataset.collapsed !== "true" &&
      !bar.contains(event.target)
    ) {
      bar.dataset.collapsed = "true";
    }
  }, true);

  collapse.addEventListener("click", event => {
    event.preventDefault();
    event.stopPropagation();
    bar.dataset.collapsed = "true";
  });

  function revealBar(event) {
    event?.preventDefault();
    event?.stopPropagation();
    bar.dataset.collapsed = "false";
  }

  tab.addEventListener("mouseenter", revealBar);
  tab.addEventListener("click", revealBar);

  function render(state) {
    bar.dataset.state = state.status;
    user.textContent = state.username || "";
    logout.hidden = state.status !== "authenticated";

    if (state.status === "authenticated") {
      label.textContent = "Session SSO active";
    } else if (state.status === "anonymous") {
      label.textContent = "Aucune session SSO";
    } else if (state.status === "unavailable") {
      label.textContent = "Serveur SSO indisponible";
    } else {
      label.textContent = "Vérification de la session…";
    }
  }

  browser.runtime.sendMessage({
    type: "SKYNET_SSO_GET_STATE"
  }).then(render).catch(() => {
    render({ status: "unavailable" });
  });

  browser.runtime.onMessage.addListener(message => {
    if (message?.type === "SKYNET_SSO_STATE") {
      render(message.state);
    }
  });

  browser.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.showNotch) {
      bar.dataset.showNotch = String(
        changes.showNotch.newValue !== false
      );
    }
  });

  logout.addEventListener("click", async event => {
    event.stopPropagation();
    logout.disabled = true;
    logout.textContent = "Déconnexion…";

    try {
      await browser.runtime.sendMessage({
        type: "SKYNET_SSO_LOGOUT"
      });

      render({ status: "anonymous" });
    } catch (error) {
      label.textContent = error.message || "Échec de la déconnexion";
    } finally {
      logout.disabled = false;
      logout.textContent = "Déconnexion";
    }
  });
})();
