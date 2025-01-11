//Cyber360-Scan
document.addEventListener('DOMContentLoaded', function () {
    const fileForm = document.getElementById('scan-form');
    const urlForm = document.getElementById("urlForm");
    const ipForm = document.getElementById("ipForm");
    console.log("test")
    // Ensure the form elements exist before adding event listeners
    if (fileForm && urlForm && ipForm) {
        // Handle File Upload Scan
        console.log(fileForm)
        fileForm.addEventListener('submit', function (e) {
            console.log("sdfasdf")
            e.preventDefault();
            const formData = new FormData(this);
            if (formData.get('file')) {
                fetch('/scan', {
                    method: 'POST',
                    body: formData
                })
                    .then(response => response.json())
                    .then(data => displayResults(data))
                    .catch(error => {
                        console.error('Error:', error);
                        displayError('File scan failed. Please try again.');
                    });
            } else {
                displayError('Please select a file to upload.');
            }
        });

        // Handle URL Scan
        urlForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const url = document.getElementById('urlInput').value.trim();
            if (url === '') {
                displayError('Please enter a URL.');
                return;
            }

            const formData = new FormData();
            formData.append('url', encodeURIComponent(url));

            fetch('/scan', {
                method: 'POST',
                body: formData
            })
                .then(response => response.json())
                .then(data => displayResults(data))
                .catch(error => {
                    console.error('Error:', error);
                    displayError('URL scan failed. Please try again.');
                });
        });

        // Handle IP Scan
        ipForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const ip = document.getElementById('ipInput').value.trim();
            if (ip === '') {
                displayError('Please enter an IP address.');
                return;
            }

            const formData = new FormData();
            formData.append('ip', ip);

            fetch('/scan', {
                method: 'POST',
                body: formData
            })
                .then(response => response.json())
                .then(data => displayResults(data))
                .catch(error => {
                    console.error('Error:', error);
                    displayError('IP scan failed. Please try again.');
                });
        });
    } else {
        console.error('Form elements not found in the DOM.');
    }

    // Function to display results in the table
    function displayResults(data) {
        const tbody = document.getElementById('resultTable').getElementsByTagName('tbody')[0];
        tbody.innerHTML = ''; // Clear previous results

        if (data.error) {
            displayError(data.error);
        } else {
            // Assuming data is structured like VirusTotal's API response
            if (data.data && data.data.attributes) {
                Object.entries(data.data.attributes).forEach(([key, value]) => {
                    const row = tbody.insertRow();
                    const cell1 = row.insertCell(0);
                    const cell2 = row.insertCell(1);
                    cell1.textContent = key;
                    cell2.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
                });
            } else {
                // If data structure is flat or different, handle it accordingly
                Object.entries(data).forEach(([key, value]) => {
                    const row = tbody.insertRow();
                    const cell1 = row.insertCell(0);
                    const cell2 = row.insertCell(1);
                    cell1.textContent = key;
                    cell2.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
                });
            }
        }
    }

    // Function to display error messages in the table
    function displayError(message) {
        const tbody = document.getElementById('resultTable').getElementsByTagName('tbody')[0];
        tbody.innerHTML = ''; // Clear previous results

        const row = tbody.insertRow();
        const cell1 = row.insertCell(0);
        const cell2 = row.insertCell(1);
        cell1.textContent = 'Error';
        cell2.textContent = message;
    }
});
