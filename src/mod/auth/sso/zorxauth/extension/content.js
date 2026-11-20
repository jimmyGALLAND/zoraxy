(async () => {
  if (window.top !== window || document.getElementById("skynet-sso-bar")) return;
  const allowed = await browser.runtime.sendMessage({
    type: "SKYNET_SSO_IS_HOST_ALLOWED", host: location.hostname
  }).catch(() => false);
  if (!allowed || document.getElementById("skynet-sso-bar")) return;

  const bar = document.createElement("aside");
  bar.id = "skynet-sso-bar";
  bar.setAttribute("aria-live", "polite");
  bar.innerHTML = `
    <div class="skynet-sso-brand"><span class="skynet-sso-mark">S</span><span>SKYNET <b>SSO</b></span></div>
    <div class="skynet-sso-status"><i></i><span class="skynet-sso-label">Vérification de la session…</span></div>
    <div class="skynet-sso-user"></div>
    <button class="skynet-sso-logout" type="button" hidden>Déconnexion globale</button>
    <button class="skynet-sso-hide" type="button" aria-label="Masquer la barre" title="Masquer">×</button>`;
  document.documentElement.appendChild(bar);

  const label = bar.querySelector(".skynet-sso-label");
  const user = bar.querySelector(".skynet-sso-user");
  const logout = bar.querySelector(".skynet-sso-logout");

  function render(state) {
    bar.dataset.state = state.status;
    user.textContent = state.username || "";
    logout.hidden = state.status !== "authenticated";
    if (state.status === "authenticated") label.textContent = "Session SSO active";
    else if (state.status === "anonymous") label.textContent = "Aucune session SSO";
    else if (state.status === "unavailable") label.textContent = "Serveur SSO indisponible";
    else label.textContent = "Vérification de la session…";
  }

  browser.runtime.sendMessage({ type: "SKYNET_SSO_GET_STATE" })
    .then(render).catch(() => render({ status: "unavailable" }));
  browser.runtime.onMessage.addListener(message => {
    if (message?.type === "SKYNET_SSO_STATE") render(message.state);
  });

  logout.addEventListener("click", async () => {
    logout.disabled = true;
    logout.textContent = "Déconnexion…";
    try {
      await browser.runtime.sendMessage({ type: "SKYNET_SSO_LOGOUT" });
      render({ status: "anonymous" });
    } catch (error) {
      label.textContent = error.message || "Échec de la déconnexion";
    } finally {
      logout.disabled = false;
      logout.textContent = "Déconnexion globale";
    }
  });
  bar.querySelector(".skynet-sso-hide").addEventListener("click", () => bar.remove());
})();