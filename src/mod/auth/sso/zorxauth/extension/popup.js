const stateNode = document.getElementById("state");
const logout = document.getElementById("logout");

browser.runtime.sendMessage({
  type: "SKYNET_SSO_GET_STATE"
}).then(state => {
  stateNode.textContent = state.status === "authenticated"
    ? "Connecté : " + state.username
    : state.status === "anonymous"
      ? "Aucune session active"
      : "Service SSO indisponible";

  logout.hidden = state.status !== "authenticated";
}).catch(() => {
  stateNode.textContent = "Impossible de joindre le service SSO";
});

logout.addEventListener("click", async () => {
  logout.disabled = true;
  logout.textContent = "Déconnexion…";

  try {
    await browser.runtime.sendMessage({
      type: "SKYNET_SSO_LOGOUT"
    });

    stateNode.textContent = "Session centrale fermée";
    logout.hidden = true;
  } catch (error) {
    stateNode.textContent = error.message || "Échec de la déconnexion";
    logout.disabled = false;
    logout.textContent = "Déconnexion";
  }
});
