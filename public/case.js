// --- START OF FILE case.js ---
document.addEventListener('DOMContentLoaded', () => {
    // --- Elementos DOM ---
    const loadingIndicator = document.getElementById('loadingIndicator');
    const errorIndicator = document.getElementById('errorIndicator');
    const caseArticle = document.getElementById('caseArticle'); // El <article> que contiene todo

    // Elementos dentro del <article>
    const caseTitleElem = document.getElementById('caseTitle');
    const caseCategoryElem = document.getElementById('caseCategory');
    const caseAuthorElem = document.getElementById('caseAuthor');
    const caseDateElem = document.getElementById('caseDate');
    const caseImageElem = document.getElementById('caseImage');
    const caseFullContentElem = document.getElementById('caseFullContent');
    const pdfLinkElem = document.getElementById('pdfLink');

    // --- Funciones Auxiliares ---
    function displayError(message) {
        loadingIndicator.style.display = 'none'; // Ocultar carga
        caseArticle.style.display = 'none';      // Ocultar contenedor de artículo
        errorIndicator.textContent = `Error: ${message}`;
        errorIndicator.style.display = 'block';  // Mostrar error
        document.title = "Error al cargar Caso - CNEURO"; // Actualizar título de pestaña
    }

    function formatDate(dateString) {
        if (!dateString) return 'Fecha no disponible';
        try {
            // Formato legible para el usuario
            const options = { year: 'numeric', month: 'long', day: 'numeric' };
            return new Date(dateString).toLocaleDateString('es-ES', options);
        } catch (e) {
            console.error("Error formateando fecha:", dateString, e);
            return 'Fecha inválida';
        }
    }

    // --- Lógica Principal ---

    // 1. Obtener el ID del caso desde la URL
    const params = new URLSearchParams(window.location.search);
    const caseId = params.get('id');

    if (!caseId) {
        displayError('No se especificó un ID de caso clínico en la URL.');
        return; // Detener ejecución si no hay ID
    }

    // 2. Solicitar datos del caso clínico a la API
    fetch(`/api/cases/${caseId}`) // Usar la ruta específica para casos
        .then(response => {
            if (!response.ok) {
                // Intentar obtener mensaje de error del JSON de respuesta
                 return response.json().then(errData => {
                      throw new Error(errData.message || `Estado ${response.status}: ${response.statusText}`);
                 }).catch(() => {
                     // Si no hay JSON o falla el parseo, usar solo statusText
                     throw new Error(`Estado ${response.status}: ${response.statusText}`);
                 });
            }
            return response.json(); // Parsear JSON si la respuesta es OK
        })
        .then(caseData => {
            // 3. Rellenar la página con los datos del caso clínico

            // Actualizar título de la pestaña
            document.title = `${caseData.title || 'Caso Clínico'} - CNEURO`;

            // Rellenar elementos del DOM
            caseTitleElem.textContent = caseData.title || 'Título no disponible';
            // Usamos innerHTML para poder mantener el icono y añadir el texto
            caseCategoryElem.innerHTML = `<i class="fas fa-tag"></i> ${caseData.category || 'Sin categoría'}`;
            caseAuthorElem.innerHTML = `<i class="fas fa-user-md"></i> ${caseData.author || 'Autor desconocido'}`;
            caseDateElem.innerHTML = `<i class="fas fa-calendar-alt"></i> Publicado el ${formatDate(caseData.publish_date)}`;

            // Manejar imagen destacada
            if (caseData.image_url) {
                caseImageElem.src = caseData.image_url;
                caseImageElem.alt = `Imagen principal para ${caseData.title || 'Caso Clínico'}`;
                caseImageElem.style.display = 'block'; // Mostrar el elemento img
                 // Manejo de error si la imagen no carga
                 caseImageElem.onerror = () => {
                    console.warn(`No se pudo cargar la imagen del caso: ${caseData.image_url}`);
                    caseImageElem.style.display = 'none'; // Ocultarla si falla
                 }
            } else {
                 caseImageElem.style.display = 'none'; // Ocultar si no hay URL de imagen
            }

            // Insertar contenido completo (permite HTML)
            // ¡Asegúrate de que confías en el HTML guardado o lo has sanitizado en el backend!
            caseFullContentElem.innerHTML = caseData.full_content || '<p>Contenido no disponible.</p>';

            // Manejar enlace PDF
            if (caseData.pdf_url) {
                pdfLinkElem.href = caseData.pdf_url;
                pdfLinkElem.style.display = 'inline-block'; // Mostrar enlace PDF
            } else {
                 pdfLinkElem.style.display = 'none'; // Ocultar si no hay PDF
            }

            // 4. Ocultar indicador de carga y mostrar contenido del caso
            loadingIndicator.style.display = 'none';
            caseArticle.style.display = 'block'; // Mostrar el <article> completo
        })
        .catch(error => {
            // 5. Manejar errores de fetch o procesamiento
            console.error('Error detallado al cargar el caso clínico:', error);
            displayError(error.message || 'No se pudo cargar el caso clínico. Inténtalo de nuevo más tarde.');
        });
});
// --- END OF FILE case.js ---