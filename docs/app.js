import { checkPassword } from "./hibp.js";

const form = document.getElementById("form");
const input = document.getElementById("password");
const toggle = document.getElementById("toggle");
const button = document.getElementById("submit");
const result = document.getElementById("result");
const steps = document.getElementById("steps");
const fmt = (n) => n.toLocaleString("en-GB");

toggle.addEventListener("click", () => {
  const hidden = input.type === "password";
  input.type = hidden ? "text" : "password";
  toggle.textContent = hidden ? "Hide" : "Show";
  toggle.setAttribute("aria-pressed", String(hidden));
});

function setText(id, text) {
  document.getElementById(id).textContent = text;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = input.value;
  if (!password) {
    input.focus();
    return;
  }
  button.disabled = true;
  button.textContent = "Checking…";
  result.hidden = true;
  try {
    const r = await checkPassword(password);
    result.className = `result ${r.count ? "result-bad" : "result-good"}`;
    setText("verdict", r.count ? `Found ${fmt(r.count)} times in data breaches` : "Not found in any known breach");
    setText("advice", r.count
      ? "Attackers try leaked passwords first. Don't use this one anywhere, and change it wherever you do."
      : "Good sign, but not a guarantee of strength. Use a long, unique password for every account, ideally from a password manager.");
    setText("step-prefix", r.prefix);
    setText("step-kept", `${r.keptLocally} characters`);
    setText("step-returned", fmt(r.hashesReturned));
    setText("step-decoys", fmt(r.decoys));
    setText("step-count", r.count ? `a match, seen ${fmt(r.count)} times` : "no match");
    result.hidden = false;
    steps.hidden = false;
  } catch (err) {
    result.className = "result result-error";
    setText("verdict", "Couldn't reach Have I Been Pwned");
    setText("advice", `${err.message}. Check your connection and try again.`);
    result.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Check password";
  }
});
