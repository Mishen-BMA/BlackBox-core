async function getHealth() {
  const response = await fetch("/health");
  return response.json();
}

window.BlackBoxCore = {
  getHealth,
};

