// static/js/autocomplete.js

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('search-input');
  const suggestionBox = document.getElementById('suggestion-list');
  const form = document.querySelector('.search-form');

  input.addEventListener('input', async () => {
    const query = input.value.trim();
    if (query.length === 0) {
      suggestionBox.innerHTML = '';
      return;
    }

    const res = await fetch(`/autocomplete?q=${encodeURIComponent(query)}`);
    const data = await res.json();

    suggestionBox.innerHTML = '';
    data.forEach(suggestion => {
      const li = document.createElement('li');
      li.textContent = suggestion;
      li.classList.add('suggestion-item');
      li.addEventListener('click', () => {
        input.value = suggestion;
        suggestionBox.innerHTML = '';
      });
      suggestionBox.appendChild(li);
    });
  });

  document.addEventListener('click', e => {
    if (!suggestionBox.contains(e.target) && e.target !== input) {
      suggestionBox.innerHTML = '';
    }
  });
  
  document.querySelectorAll('.suggest-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const keyword = btn.dataset.keyword;
        input.value = keyword;
        form.submit();
      });
    });

});
