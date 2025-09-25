// Variables pour détecter les types de navigation
    let isFormSubmission = false;
    let isReload = false;
    let isInternalNavigation = false;

    // Marquer quand c'est un submit de formulaire
    document.querySelector('form').addEventListener('submit', function() {
      isFormSubmission = true;
      sessionStorage.setItem('lastAction', 'form_submit');
    });

    // Détecter les raccourcis de reload
    document.addEventListener('keydown', function(e) {
      if (e.key === 'F5' || (e.ctrlKey && e.key === 'r') || (e.metaKey && e.key === 'r')) {
        isReload = true;
        sessionStorage.setItem('lastAction', 'reload');
      }
    });

    // Détecter la navigation interne (liens)
    document.addEventListener('click', function(e) {
      if (e.target.tagName === 'A' && e.target.href) {
        isInternalNavigation = true;
        sessionStorage.setItem('lastAction', 'navigation');
      }
    });

    // Gérer la fermeture d'onglet/navigateur
    window.addEventListener('beforeunload', function(e) {
      // Ne pas logout si c'est un reload, form submit ou navigation
      if (isReload || isFormSubmission || isInternalNavigation) {
        return;
      }

      // Vérifier l'historique des actions récentes
      const lastAction = sessionStorage.getItem('lastAction');
      if (lastAction === 'reload' || lastAction === 'form_submit' || lastAction === 'navigation') {
        return;
      }

      // Si aucune action détectée, c'est probablement une fermeture
      navigator.sendBeacon('/logout');
    });

    // Nettoyer les flags après un délai
    window.addEventListener('load', function() {
      setTimeout(() => {
        sessionStorage.removeItem('lastAction');
        isFormSubmission = false;
        isReload = false;
        isInternalNavigation = false;
      }, 1000);
    });