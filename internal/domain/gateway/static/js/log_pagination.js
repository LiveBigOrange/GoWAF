(function() {
    function renderPageBtns(containerId, currentPage, totalPages, goPageFn) {
        var c = document.getElementById(containerId);
        if (!c) return;
        if (totalPages <= 1) { c.innerHTML = ''; return; }
        var h = '';
        if (totalPages <= 5) {
            h += '<button class="pagination-btn" onclick="' + goPageFn + '(' + (currentPage - 1) + ')"' + (currentPage <= 1 ? ' disabled' : '') + '>‹</button>';
            for (var i = 1; i <= totalPages; i++) {
                h += '<button class="pagination-btn' + (i === currentPage ? ' active' : '') + '" onclick="' + goPageFn + '(' + i + ')">' + i + '</button>';
            }
            h += '<button class="pagination-btn" onclick="' + goPageFn + '(' + (currentPage + 1) + ')"' + (currentPage >= totalPages ? ' disabled' : '') + '>›</button>';
        } else {
            h += '<button class="pagination-btn" onclick="' + goPageFn + '(1)"' + (currentPage <= 1 ? ' disabled' : '') + '>«</button>';
            h += '<button class="pagination-btn" onclick="' + goPageFn + '(' + (currentPage - 1) + ')"' + (currentPage <= 1 ? ' disabled' : '') + '>‹</button>';
            var start = Math.max(1, currentPage - 2);
            var end = Math.min(totalPages, currentPage + 2);
            if (start > 1) {
                h += '<button class="pagination-btn" onclick="' + goPageFn + '(1)">1</button>';
                if (start > 2) h += '<span style="padding:0 6px;color:#999;">...</span>';
            }
            for (var i = start; i <= end; i++) {
                h += '<button class="pagination-btn' + (i === currentPage ? ' active' : '') + '" onclick="' + goPageFn + '(' + i + ')">' + i + '</button>';
            }
            if (end < totalPages) {
                if (end < totalPages - 1) h += '<span style="padding:0 6px;color:#999;">...</span>';
                h += '<button class="pagination-btn" onclick="' + goPageFn + '(' + totalPages + ')">' + totalPages + '</button>';
            }
            h += '<button class="pagination-btn" onclick="' + goPageFn + '(' + (currentPage + 1) + ')"' + (currentPage >= totalPages ? ' disabled' : '') + '>›</button>';
            h += '<button class="pagination-btn" onclick="' + goPageFn + '(' + totalPages + ')"' + (currentPage >= totalPages ? ' disabled' : '') + '>»</button>';
        }
        c.innerHTML = h;
    }

    window.RenderPageBtns = renderPageBtns;
})();
