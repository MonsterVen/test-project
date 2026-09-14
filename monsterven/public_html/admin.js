document.querySelector('form').addEventListener('submit', async (e) => {
    e.preventDefault();

    // Сбор значений из полей формы
    const data = {
        name: document.querySelector('input#name').value.trim(),
        disc: document.querySelector('textarea#disc').value.trim(),
        tag: document.querySelector('input#tag').value.trim(),
        place: document.querySelector('textarea#place').value.trim(),
        img: document.querySelector('input#img').value.trim()
    };

    try {
        const res = await fetch('./add_card.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await res.json();

        if (res.ok) {
            alert(result.message); // Успешное добавление
        } else {
            alert(`Error: ${result.error}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to send data. Please try again.');
    }
});
