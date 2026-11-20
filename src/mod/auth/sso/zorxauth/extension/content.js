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

  const dialog = document.createElement("div");
  dialog.id = "skynet-sso-dialog";
  dialog.innerHTML = `
    <div class="skynet-sso-dialog-backdrop"></div>
    <section
      class="skynet-sso-dialog-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="skynet-sso-dialog-title"
      aria-describedby="skynet-sso-dialog-description"
      tabindex="-1"
    >
      <div class="skynet-sso-dialog-symbol" aria-hidden="true">
        <span></span>
      </div>
      <p class="skynet-sso-dialog-eyebrow">SKYNET SECURITY</p>
      <h2 id="skynet-sso-dialog-title">Confirmer la déconnexion</h2>
      <p id="skynet-sso-dialog-description">
        Souhaitez-vous vraiment fermer votre session SKYNET sur l’ensemble des services ?
      </p>
      <p class="skynet-sso-dialog-error" role="alert" hidden></p>
      <div class="skynet-sso-dialog-progress" aria-live="polite" hidden>
        <span class="skynet-sso-spinner" aria-hidden="true"></span>
        <span class="skynet-sso-dialog-progress-label">Déconnexion en cours…</span>
      </div>
      <div class="skynet-sso-dialog-actions">
        <button class="skynet-sso-dialog-cancel" type="button">Annuler</button>
        <button class="skynet-sso-dialog-confirm" type="button">
          <span>Me déconnecter</span>
          <span class="skynet-sso-dialog-arrow" aria-hidden="true">↗</span>
        </button>
      </div>
    </section>
  `;
  document.documentElement.appendChild(dialog);

  const dialogPanel = dialog.querySelector(".skynet-sso-dialog-panel");
  const dialogCancel = dialog.querySelector(".skynet-sso-dialog-cancel");
  const dialogConfirm = dialog.querySelector(".skynet-sso-dialog-confirm");
  const dialogError = dialog.querySelector(".skynet-sso-dialog-error");
  const dialogProgress = dialog.querySelector(".skynet-sso-dialog-progress");
  const dialogProgressLabel = dialog.querySelector(".skynet-sso-dialog-progress-label");
  const dialogDescription = dialog.querySelector("#skynet-sso-dialog-description");

  function closeLogoutDialog() {
    if (dialog.dataset.busy === "true") return;
    dialog.dataset.open = "false";
    dialogError.hidden = true;
    logout.focus();
  }

  function openLogoutDialog() {
    dialog.dataset.open = "true";
    dialog.dataset.busy = "false";
    dialogError.hidden = true;
    dialogProgress.hidden = true;
    dialogDescription.hidden = false;
    dialogConfirm.disabled = false;
    dialogCancel.disabled = false;
    dialogConfirm.querySelector("span").textContent = "Me déconnecter";
    dialogPanel.focus();
  }

  function setLogoutBusy(busy) {
    dialog.dataset.busy = String(busy);
    dialogProgress.hidden = !busy;
    dialogDescription.hidden = busy;
    dialogCancel.disabled = busy;
    dialogConfirm.disabled = busy;
    dialogConfirm.querySelector("span").textContent = busy
      ? "Déconnexion…"
      : "Me déconnecter";
    dialogProgressLabel.textContent = "Déconnexion en cours…";
    dialogError.hidden = true;
  }

  dialogCancel.addEventListener("click", closeLogoutDialog);
  dialog.querySelector(".skynet-sso-dialog-backdrop")
    .addEventListener("click", closeLogoutDialog);
  dialogConfirm.addEventListener("click", async () => {
    if (dialog.dataset.busy === "true") return;

    setLogoutBusy(true);

    try {
      const result = await browser.runtime.sendMessage({
        type: "SKYNET_SSO_LOGOUT"
      });

      if (!result?.success) {
        throw new Error("Le serveur n’a pas confirmé la déconnexion.");
      }

      dialogProgressLabel.textContent = "Session fermée. Actualisation…";
      render({ status: "anonymous" });
      window.location.reload();
    } catch (error) {
      dialog.dataset.busy = "false";
      dialogProgress.hidden = true;
      dialogDescription.hidden = false;
      dialogCancel.disabled = false;
      dialogConfirm.disabled = false;
      dialogConfirm.querySelector("span").textContent = "Réessayer";
      dialogError.textContent = error.message || "La déconnexion a échoué. Veuillez réessayer.";
      dialogError.hidden = false;
    }
  });

  document.addEventListener("keydown", event => {
    if (dialog.dataset.open !== "true") return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeLogoutDialog();
    }
    if (event.key === "Tab") {
      const focusable = [dialogCancel, dialogConfirm].filter(
        element => !element.disabled
      );
      if (!focusable.length) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });

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

  logout.addEventListener("click", event => {
    event.preventDefault();
    event.stopPropagation();
    openLogoutDialog();
  });
})();
