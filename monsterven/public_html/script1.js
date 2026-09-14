
    // Функция для фильтрации карточек
    $(document).ready(function() {
    $('#search').on('keyup', function() {
        var searchTerm = $(this).val().toLowerCase(); // Получаем значение из поля поиска и приводим к нижнему регистру
        $('.dashboard-main .card').each(function() {
            // Проверяем, если это card-1, пропускаем
            if ($(this).hasClass('card-1')) {
                return; // Пропускаем обработку
            }

            var itemText = $(this).text().toLowerCase(); // Получаем текст элемента и приводим к нижнему регистру
            if (itemText.indexOf(searchTerm) !== -1) {
                $(this).show(); // Если текст элемента содержит поисковый запрос, показываем элемент
            } else {
                $(this).hide(); // Иначе скрываем
            }
        });
    });
});


//функция для сортировки карточек
function sortCards() {
    const container = document.querySelector(".dashboard-main");
    const cards = Array.from(container.querySelectorAll(".card"));
    const excludedCard = container.querySelector(".card-1");
    const cardsToSort = cards.filter(card => card !== excludedCard);

    let dir = container.getAttribute("data-sort-dir") || "asc";

    const sortedCards = cardsToSort.sort((a, b) => {
        const titleA = a.querySelector(".title")?.textContent.trim().toLowerCase() || "";
        const titleB = b.querySelector(".title")?.textContent.trim().toLowerCase() || "";

        return dir === "asc" 
            ? titleA.localeCompare(titleB)
            : titleB.localeCompare(titleA);
    });

    container.innerHTML = "";
    
    if (excludedCard) {
        container.appendChild(excludedCard);
    }

    sortedCards.forEach(card => container.appendChild(card));
    container.setAttribute("data-sort-dir", dir === "asc" ? "desc" : "asc");
}

// Добавляем кнопки на сайдбаре(функционал)
        // Add card filtering functionality
        document.querySelectorAll('.nav-item').forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const filter = button.getAttribute('data-filter');
                filterCards(filter);
                
                // Update active state of buttons
                document.querySelectorAll('.nav-item').forEach(btn => {
                    btn.classList.remove('active');
                });
                button.classList.add('active');
            });
        });

        function filterCards(category) {
            const cards = document.querySelectorAll('.card');
            
            cards.forEach(card => {
                if (category === 'all' || card.getAttribute('data-category') === category) {
                    card.style.display = 'grid';
                } else {
                    card.style.display = 'none';
                }
            });
        }

//анимация сайдбара
            const resizeBtn = document.getElementById('resize');
            resizeBtn.addEventListener('click', function(e) {
                e.preventDefault();
                document.body.classList.toggle('sb-expand');
            });

// курсор
const coords = { x: 0, y: 0 };
const circles = document.querySelectorAll(".circle");

const colors = [
  "#ffb56b",
  "#fdaf69",
  "#f89d63",
  "#f59761",
  "#ef865e",
  "#ec805d",
  "#e36e5c",
  "#df685c",
  "#d5585c",
  "#d1525c",
  "#c5415d",
  "#c03b5d",
  "#b22c5e",
  "#ac265e",
  "#9c155f",
  "#950f5f",
  "#830060",
  "#7c0060",
  "#680060",
  "#60005f",
  "#48005f",
  "#3d005e"
];

circles.forEach(function (circle, index) {
  circle.x = 0;
  circle.y = 0;
  circle.style.backgroundColor = colors[index % colors.length];
});

window.addEventListener("mousemove", function(e){
  coords.x = e.clientX;
  coords.y = e.clientY;
  
});

function animateCircles() {
  
  let x = coords.x;
  let y = coords.y;
  
  circles.forEach(function (circle, index) {
    circle.style.left = x - 12 + "px";
    circle.style.top = y - 12 + "px";
    
    circle.style.scale = (circles.length - index) / circles.length;
    
    circle.x = x;
    circle.y = y;

    const nextCircle = circles[index + 1] || circles[0];
    x += (nextCircle.x - x) * 0.3;
    y += (nextCircle.y - y) * 0.3;
  });
 
  requestAnimationFrame(animateCircles);
}

animateCircles();
