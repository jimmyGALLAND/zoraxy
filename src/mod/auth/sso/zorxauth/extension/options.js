const issuer = document.getElementById("issuer");
const hosts = document.getElementById("hosts");
const showNotch = document.getElementById("showNotch");
const result = document.getElementById("result");
browser.storage.local.get({
  issuer: "https://auth.celjim.fr",
  protectedHosts: ["celjim.fr", "diagimm.fr"],
  showNotch: true
}).then(cfg => {
  issuer.value = cfg.issuer;
  hosts.value = cfg.protectedHosts.join("\n");
  showNotch.checked = cfg.showNotch !== false;
});
document.getElementById("save").addEventListener("click", async () => {
  const value = issuer.value.trim().replace(/\/$/, "");
  if (!/^https:\/\//i.test(value)) { result.textContent = "L’URL doit commencer par https://"; return; }
  const domains = [...new Set(hosts.value.split(/[\r\n,;]+/).map(x => x.trim().toLowerCase()).filter(Boolean))];
  if (!domains.length || domains.some(x => /[\s/:?#]/.test(x))) { result.textContent = "Vérifiez la liste des domaines."; return; }
  await browser.storage.local.set({ issuer: value, protectedHosts: domains, showNotch: showNotch.checked });
  result.textContent = "Paramètres enregistrés.";
});