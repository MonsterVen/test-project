getData();

async function getData() {
    try {
        const res = await fetch('./card.php'); // Запрашиваем все карточки
        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }
        const data = await res.json();
        console.log('Data received:', data);
        createProfiles(data);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

function createProfiles(cards) {
    // Проверяем, есть ли карточки
    if (!cards || cards.length === 0) {
        console.error('No cards received');
        return;
    }

    const dashboard = document.querySelector('.dashboard-main');

    // Проходимся по каждой карточке и создаём HTML
    cards.forEach(card => {
        const cardHTML = `
            <div class="card" data-category="${card.tag}" onclick="window.location.href='${card.place}'" style="cursor: pointer;">
                <img class="left-image" src="images/${card.img}" alt="Left Image">
                <h3 class="title">${card.name}</h3>
                <p class="content">${card.disc}</p>
            </div>`;
        dashboard.insertAdjacentHTML('beforeend', cardHTML); // Добавляем карточки после card-1
    });
}

