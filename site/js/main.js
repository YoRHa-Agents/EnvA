(function () {
  'use strict';

  function copyText(text, button) {
    navigator.clipboard.writeText(text).then(() => {
      if (!button) {
        return;
      }
      const original = button.textContent;
      button.textContent = 'Copied';
      window.setTimeout(() => {
        button.textContent = original;
      }, 1800);
    }).catch(() => {
      const helper = document.createElement('textarea');
      helper.value = text;
      document.body.appendChild(helper);
      helper.select();
      document.execCommand('copy');
      document.body.removeChild(helper);
      if (!button) {
        return;
      }
      const original = button.textContent;
      button.textContent = 'Copied';
      window.setTimeout(() => {
        button.textContent = original;
      }, 1800);
    });
  }

  document.querySelectorAll('[data-copy-text]').forEach((button) => {
    button.addEventListener('click', () => {
      copyText(button.getAttribute('data-copy-text') || '', button);
    });
  });

  const currentHash = window.location.hash;
  if (currentHash) {
    const activeLink = document.querySelector(`.topnav a[href="${currentHash}"]`);
    if (activeLink) {
      document.querySelectorAll('.topnav a').forEach((link) => {
        link.classList.toggle('active', link === activeLink);
      });
    }
  }
})();
