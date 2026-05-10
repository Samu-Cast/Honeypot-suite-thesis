document.addEventListener('DOMContentLoaded', function() {
    const chartCanvas = document.getElementById('patternChart');
    if (chartCanvas) {
        const labels = JSON.parse(chartCanvas.getAttribute('data-labels'));
        const data = JSON.parse(chartCanvas.getAttribute('data-counts'));
        const colors = [
            '#dc3545', '#e67e22', '#e74c3c', '#f39c12',
            '#9b59b6', '#3498db', '#1abc9c', '#95a5a6'
        ];

        new Chart(chartCanvas, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors.slice(0, labels.length)
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }
});
