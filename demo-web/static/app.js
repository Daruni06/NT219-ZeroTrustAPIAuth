let sessionId = null;
let activeUser = null;

const claimsOutput = document.getElementById("claimsOutput");
const resultOutput = document.getElementById("resultOutput");
const sessionStatus = document.getElementById("sessionStatus");

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    throw new Error(pretty({ status: response.status, body: data }));
  }
  return data;
}

async function login(username) {
  const password = username === "admin" ? "admin123" : "alice123";
  resultOutput.textContent = `Logging in ${username}...`;
  const data = await postJson("/api/login", { username, password });
  sessionId = data.session_id;
  activeUser = username;
  sessionStatus.textContent = `Logged in: ${username}`;
  claimsOutput.textContent = pretty({
    public_jwk: data.public_jwk,
    claims: data.claims,
  });
  resultOutput.textContent = "Login complete.";
}

async function call(path, attack = null) {
  if (!sessionId) {
    resultOutput.textContent = "Login first.";
    return;
  }

  const targetPath = attack === "opa_deny" ? "/admin/users" : path;
  resultOutput.textContent = `Calling ${targetPath}...`;
  const data = await postJson("/api/call", {
    session_id: sessionId,
    method: "GET",
    path: targetPath,
    attack: attack === "opa_deny" ? null : attack,
  });
  resultOutput.textContent = pretty(data);
}

document.querySelectorAll("[data-login]").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await login(button.dataset.login);
    } catch (error) {
      resultOutput.textContent = error.message;
    }
  });
});

document.querySelectorAll("[data-call]").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await call(button.dataset.call);
    } catch (error) {
      resultOutput.textContent = error.message;
    }
  });
});

document.querySelectorAll("[data-attack]").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      if (button.dataset.attack === "opa_deny" && activeUser !== "alice") {
        await login("alice");
      }
      await call("/users", button.dataset.attack);
    } catch (error) {
      resultOutput.textContent = error.message;
    }
  });
});
