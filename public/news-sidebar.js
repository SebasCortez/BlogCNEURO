// --- START OF FILE public/news-sidebar.js ---
document.addEventListener('DOMContentLoaded', () => {
    const toggleButton = document.getElementById('toggleNewsSidebarBtn');
    const closeButton = document.getElementById('closeNewsSidebarBtn');
    const sidebar = document.getElementById('newsSidebar');
    const newsList = document.getElementById('newsList');
    const backdrop = document.getElementById('sidebarBackdrop'); // Opcional

    let newsLoaded = false; // Bandera para cargar noticias solo una vez

    // Función para abrir el sidebar
    function openSidebar() {
        if (!sidebar) return;
        sidebar.classList.add('open');
        if (backdrop) backdrop.classList.add('visible'); // Mostrar backdrop
        // Cargar noticias solo la primera vez que se abre
        if (!newsLoaded) {
            loadNews();
        }
    }

    // Función para cerrar el sidebar
    function closeSidebar() {
        if (!sidebar) return;
        sidebar.classList.remove('open');
        if (backdrop) backdrop.classList.remove('visible'); // Ocultar backdrop
    }

    // Función para cargar noticias desde la API
    async function loadNews() {
        if (!newsList || !sidebar) return;

        newsList.innerHTML = '<li class="news-loading"><i class="fas fa-spinner fa-spin"></i> Cargando...</li>'; // Mostrar carga

        try {
            const response = await fetch('/api/news');
            if (!response.ok) {
                 const errorData = await response.json().catch(()=>({}));
                 throw new Error(errorData.message || `Error ${response.status}`);
            }
            const newsItems = await response.json();
            newsLoaded = true; // Marcar como cargadas
            renderNews(newsItems);

        } catch (error) {
            console.error("Error fetching news:", error);
            newsList.innerHTML = `<li class="news-error">Error al cargar noticias: ${error.message}</li>`;
        }
    }

    // Función para renderizar las noticias en la lista
    function renderNews(newsItems) {
        if (!newsList) return;
        newsList.innerHTML = ''; // Limpiar lista (incluyendo mensaje de carga/error)

        if (newsItems.length === 0) {
            newsList.innerHTML = '<li class="news-loading">No hay noticias recientes.</li>';
            return;
        }

        newsItems.forEach(item => {
            const li = document.createElement('li');

            let imageHtml = '';
            if (item.image_url) {
                imageHtml = `<img src="${item.image_url}" alt="${item.title || 'Noticia'}" class="news-item-image" loading="lazy" onerror="this.style.display='none'">`;
            }

            const titleHtml = item.link
                ? `<a href="${item.link}" target="_blank" rel="noopener noreferrer" class="news-item-title">${item.title}</a>`
                : `<span class="news-item-title">${item.title}</span>`;

            const formattedDate = new Date(item.publish_date).toLocaleDateString('es-ES', {
                day: 'numeric', month: 'short', year: 'numeric'
            });

            li.innerHTML = `
                ${imageHtml}
                ${titleHtml}
                <p class="news-item-content">${item.content}</p>
                <span class="news-item-date">${formattedDate}</span>
            `;
            newsList.appendChild(li);
        });
    }

    // --- Event Listeners ---
    if (toggleButton) {
        toggleButton.addEventListener('click', openSidebar);
    }

    if (closeButton) {
        closeButton.addEventListener('click', closeSidebar);
    }

    // Cerrar al hacer clic en el backdrop (opcional)
    if (backdrop) {
        backdrop.addEventListener('click', closeSidebar);
    }

    // Cerrar al presionar la tecla Escape
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && sidebar && sidebar.classList.contains('open')) {
            closeSidebar();
        }
    });

});
// --- END OF FILE public/news-sidebar.js ---