let inactivityTimer;
const logoutAfter = 60 * 10 * 1000; // 10 secondes pour test

let activityTimer;

// Fonction pour déconnecter et rediriger
function logoutAndRedirect() {
    fetch("/logout", { method: "POST" })
        .finally(() => {
            window.location.href = "/"; // redirection vers login
        });
}

// Fonction pour reset le timer d'inactivité
function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(logoutAndRedirect, logoutAfter);
}

// Fonction pour ping serveur
function pingActivity() {
    fetch("/activity", { method: "POST" });
}

// Fonction pour reset timer + ping serveur
function resetActivityTimer() {
    resetInactivityTimer();
    pingActivity();
    clearTimeout(activityTimer);
    activityTimer = setTimeout(pingActivity, 10 * 1000); // ping toutes les 10s si actif
}

// Détecte interactions utilisateur
["mousemove", "keydown", "scroll", "click", "input"].forEach(evt => {
    window.addEventListener(evt, resetActivityTimer);
});

// Initialisation
resetActivityTimer();