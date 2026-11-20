const DEFAULTS = {
  issuer: "https://auth.celjim.fr",
  protectedHosts: ["celjim.fr", "diagimm.fr"],
  pollIntervalMs: 60000
};

let state = {
  status: "checking",
  username: "",
  expiresAt: null,
  error: ""
};

async function settings() {
  return {
    ...DEFAULTS,
    ...(await browser.storage.local.get(DEFAULTS))
  };
}

function hostMatches(host, suffix) {
  const normalized = String(suffix || "")
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "");

  return normalized && (
    host === normalized ||
    host.endsWith("." + normalized)
  );
}

async function refreshSession() {
  const cfg = await settings();

  try {
    const response = await fetch(
      cfg.issuer.replace(/\/$/, "") + "/user/api/info",
      {
        method: "GET",
        credentials: "include",
        cache: "no-store"
      }
    );

    if (response.status === 401) {
      state = {
        status: "anonymous",
        username: "",
        expiresAt: null,
        error: ""
      };
    } else if (!response.ok) {
      throw new Error("HTTP " + response.status);
    } else {
      const data = await response.json();

      state = {
        status: "authenticated",
        username: data.username || "",
        expiresAt: null,
        error: ""
      };
    }
  } catch (error) {
    state = {
      ...state,
      status: "unavailable",
      error: error.message || String(error)
    };
  }

  await browser.storage.local.set({ sessionState: state });

  await browser.tabs.query({}).then(tabs => {
    for (const tab of tabs) {
      if (tab.id) {
        browser.tabs.sendMessage(
          tab.id,
          { type: "SKYNET_SSO_STATE", state }
        ).catch(() => {});
      }
    }
  });

  return state;
}

browser.runtime.onMessage.addListener(async message => {
  if (message?.type === "SKYNET_SSO_IS_HOST_ALLOWED") {
    const cfg = await settings();

    return (cfg.protectedHosts || []).some(suffix =>
      hostMatches(message.host, suffix)
    );
  }

  if (message?.type === "SKYNET_SSO_GET_STATE") {
    return refreshSession();
  }

  if (message?.type === "SKYNET_SSO_LOGOUT") {
    const cfg = await settings();
    const response = await fetch(
      cfg.issuer.replace(/\/$/, "") + "/logout",
      {
        method: "POST",
        credentials: "include",
        cache: "no-store"
      }
    );

    if (!response.ok) {
      throw new Error(
        "Déconnexion refusée (HTTP " + response.status + ")"
      );
    }

    state = {
      status: "anonymous",
      username: "",
      expiresAt: null,
      error: ""
    };

    await browser.storage.local.set({ sessionState: state });

    await browser.tabs.query({}).then(tabs => {
      for (const tab of tabs) {
        if (tab.id) {
          browser.tabs.sendMessage(
            tab.id,
            { type: "SKYNET_SSO_STATE", state }
          ).catch(() => {});
        }
      }
    });

    return { success: true };
  }
});

browser.runtime.onInstalled.addListener(() => refreshSession());
browser.runtime.onStartup.addListener(() => refreshSession());

refreshSession();
setInterval(refreshSession, DEFAULTS.pollIntervalMs);
