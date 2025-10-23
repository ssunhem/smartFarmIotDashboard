// --- SOCKET.IO CLIENT SETUP AND REAL-TIME HANDLER ---

// 1. Initialize SocketIO Connection
// IMPORTANT: Use the host and port where your Flask/SocketIO server is running.
// If running Flask on port 5000 in Docker and accessing from localhost, this is correct.
const socket = io('http://localhost:5000');

// A global map to store Chart.js instances, keyed by their unique panel ID 
// (e.g., FARM_A-TEMP_01-temperature).
// This must be populated when your farm dashboard loads/is built.
const chartPanels = {}; 

/**
 * Attaches a Chart.js instance to the global map for easy access.
 * @param {string} panelPath - A unique identifier for the chart (e.g., 'FARM_A-DEV01-temp').
 * @param {object} chartInstance - The Chart.js object.
 */
function registerChartPanel(panelPath, chartInstance) {
    chartPanels[panelPath] = chartInstance;
    console.log(`Registered chart panel: ${panelPath}`);
}


// 2. Event Listener for Real-Time Telemetry Data
socket.on('new_telemetry', (data) => {
    // Data structure expected from Flask:
    // { 
    //   'farm_id': 'FARM_A',
    //   'device_id_code': 'TEMP_01', 
    //   'panel_id_code': 'PAN001', 
    //   'value': 25.4,
    //   'timestamp': 1700000000 
    // }
    
    // Create the unique ID used to find the correct chart instance
    const panelPath = `${data.farm_id}/${data.device_id_code}/${data.panel_id_code}`;
    const chart = chartPanels[panelPath];
    
    // Format the time for display on the X-axis
    // const now = new Date(data.timestamp * 1000).toLocaleTimeString();
    const now = data.timestamp;
    console.log("Now: ", now);

    // 3. Update Live Sensor Card (using renderDevices.js logic)
    // Find the device card element and update the live value display
    updateDeviceCardLiveValue(data.device_id_code, data.value, data.type);


    // 4. Update the Chart
    if (chart) {
        // Add the new data point to the dataset
        const dataset = chart.data.datasets[0];
        
        // Push time to labels (X-axis)
        chart.data.labels.push(now);
        
        // Push value to data (Y-axis)
        dataset.data.push(data.value);

        // Limit the number of points to keep the chart performant and readable
        const maxPoints = 20;
        if (chart.data.labels.length > maxPoints) {
            chart.data.labels.shift();
            dataset.data.shift();
        }

        // Redraw the chart
        chart.update('quiet'); // 'quiet' prevents animation for smooth real-time flow
    }
});

// Listener for connection/disconnection status (optional)
socket.on('connect', () => {
    console.log('SocketIO: Connected to Flask Real-Time Server.');
});

socket.on('disconnect', () => {
    console.warn('SocketIO: Disconnected from Flask Real-Time Server.');
});


/**
 * Helper function to update the live reading displayed on the device card (using logic from renderDevices.js).
 * This function should be defined in the global scope if not inside the main HTML file.
 * @param {string} deviceIdCode - The device's ID code (e.g., 'TEMP_01').
 * @param {number} value - The new sensor reading.
 * @param {string} type - The sensor type (e.g., 'temperature').
 */
function updateDeviceCardLiveValue(deviceIdCode, value, type) {
    // NOTE: This is a placeholder function. You would need to refine your
    // renderDevices.js or main HTML to make the card dynamic.
    
    // For a real-world application, you would need to:
    // 1. Find the specific card element using its deviceIdCode and type.
    // 2. Find the span/div inside the card that holds the statusText.
    // 3. Re-run the coloring/status logic based on the new 'value' and 'type'.
    
    // Simplified placeholder log:
    console.log(`[Card Update]: Device ${deviceIdCode} (${type}) value updated to ${value.toFixed(2)}.`);
}

// Ensure the io function is available globally when this script runs
// (by including the client library in the HTML head/body)
