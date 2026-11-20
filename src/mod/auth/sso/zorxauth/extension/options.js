const homeUrl = document.getElementById("homeUrl");
const issuer = document.getElementById("issuer");
const hosts = document.getElementById("hosts");
const showNotch = document.getElementById("showNotch");
const result = document.getElementById("result");
browser.storage.local.get({
  homeUrl: "https://celjim.fr",
  issuer: "https://auth.celjim.fr",
  protectedHosts: ["celjim.fr", "diagimm.fr"],
  showNotch: true
}).then(cfg => {
  homeUrl.value = cfg.homeUrl || "https://celjim.fr";
  issuer.value = cfg.issuer;
  hosts.value = cfg.protectedHosts.join("\n");
  showNotch.checked = cfg.showNotch !== false;
});
document.getElementById("save").addEventListener("click", async () => {
  const value = issuer.value.trim().replace(/\/$/, "");
  if (!/^https:\/\//i.test(value)) { result.textContent = "L’URL doit commencer par https://"; return; }
  const domains = [...new Set(hosts.value.split(/[\r\n,;]+/).map(x => x.trim().toLowerCase()).filter(Boolean))];
  if (!domains.length || domains.some(x => /[\s/:?#]/.test(x))) { result.textContent = "Vérifiez la liste des domaines."; return; }
  const home = homeUrl.value.trim();
  if (!/^https?:\/\//i.test(home)) { result.textContent = "L’URL de la page d’accueil doit commencer par http:// ou https://"; return; }
  await browser.storage.local.set({ homeUrl: home, issuer: value, protectedHosts: domains, showNotch: showNotch.checked });
  result.textContent = "Paramètres enregistrés.";
});