document.addEventListener('DOMContentLoaded', function() {
  const toggle = document.getElementById('receive_reminders');
  toggle.addEventListener('change', () => {
    fetch(toggleReminderUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ receive_reminders: toggle.checked })
    })
    .then(response => response.json())
    .then(data => {
      alert(data.message);
    })
    .catch(err => console.error('Error:', err));
  });
});
