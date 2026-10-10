/* ==========================================================================
   DataSniff - Interactive UI Scripts
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    // 1. File Upload Dropzone Interactions (scan.html)
    const fileInput = document.getElementById("logfile") || document.querySelector('input[type="file"][name="logfile"]');
    const dropzone = document.getElementById("uploadDropzone");
    const fileBadge = document.getElementById("fileSelectedBadge");
    const fileNameSpan = document.getElementById("fileNameDisplay");

    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (file && fileBadge && fileNameSpan) {
                fileNameSpan.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
                fileBadge.style.display = "inline-flex";
            }
        });
    }

    if (dropzone && fileInput) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
            }, false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                const file = files[0];
                if (fileBadge && fileNameSpan) {
                    fileNameSpan.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
                    fileBadge.style.display = "inline-flex";
                }
            }
        });
    }

    // 2. Safe Back to Top Button
    const topBtn = document.getElementById("topBtn");
    if (topBtn) {
        window.addEventListener("scroll", () => {
            if (window.scrollY > 300) {
                topBtn.style.display = "flex";
            } else {
                topBtn.style.display = "none";
            }
        });

        topBtn.addEventListener("click", () => {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }
});