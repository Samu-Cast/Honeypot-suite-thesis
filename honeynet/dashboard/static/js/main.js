document.addEventListener('DOMContentLoaded', function() {
    // pattern → color map (must match style.css badge colours)
    const PATTERN_COLORS = {
        'FULL_SPECTRUM':      '#dc3545',
        'BRUTE_FORCE_SSH':    '#e67e22',
        'SSH_THEN_PAYLOAD':   '#e74c3c',
        'SSH_THEN_LATERAL':   '#f39c12',
        'PAYLOAD_AND_LATERAL':'#9b59b6',
        'AUTOMATED_EXPLOIT':  '#3498db',
        'RECON_ONLY':         '#1abc9c',
        'LOW_SSH_ACTIVITY':   '#95a5a6',
        'UNKNOWN':            '#bdc3c7'
    };

    const chartCanvas = document.getElementById('patternChart');
    if (chartCanvas) {
        const labels = JSON.parse(chartCanvas.getAttribute('data-labels'));
        const data = JSON.parse(chartCanvas.getAttribute('data-counts'));

        // assign colour per label name so chart matches the table badges
        const colors = labels.map(function(label) {
            return PATTERN_COLORS[label] || '#bdc3c7';
        });

        new Chart(chartCanvas, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'right',
                        labels: {
                            boxWidth: 12
                        }
                    }
                }
            }
        });
    }
});

window.toggleRows = function(rowClass, btnId) {
    const rows = document.querySelectorAll('.' + rowClass);
    const btn = document.getElementById(btnId);
    let isShowingMore = false;
    
    rows.forEach(row => {
        if (row.classList.contains('d-none')) {
            row.classList.remove('d-none');
            isShowingMore = true;
        } else {
            row.classList.add('d-none');
        }
    });
    
    if (isShowingMore) {
        btn.textContent = "Show Less";
    } else {
        btn.textContent = "Show More";
    }
};
