// Add this endpoint after your existing API routes in server.js

// ——— Sensor Data Upload Endpoint ———
app.post('/api/v1/sensor-data', async (req, res) => {
  try {
    const sensorData = req.body;
    
    // Validate required fields
    if (!sensorData.session_id || !sensorData.device_id || !sensorData.sensor_data) {
      return res.status(400).json({ 
        error: 'Missing required fields: session_id, device_id, sensor_data' 
      });
    }
    
    // Log the received data for debugging
    console.log(`📱 Received sensor data from device: ${sensorData.device_id}`);
    console.log(`📊 Session: ${sensorData.session_id}`);
    console.log(`🔢 Data points - Barometer: ${sensorData.sensor_data.barometer?.length || 0}, Accelerometer: ${sensorData.sensor_data.accelerometer?.length || 0}, GPS: ${sensorData.sensor_data.gps?.length || 0}`);
    
    // Here you can process the data:
    // 1. Store raw data in database
    // 2. Extract building_id from GPS coordinates (geofencing)
    // 3. Calculate vertical delay metrics
    // 4. Update building summaries
    
    // For now, we'll just store it and send success response
    // TODO: Add database storage and processing logic
    
    // Basic processing example:
    const processedData = {
      session_id: sensorData.session_id,
      device_id: sensorData.device_id,
      start_time: sensorData.start_time,
      end_time: sensorData.end_time,
      data_points_collected: (sensorData.sensor_data.barometer?.length || 0) + 
                           (sensorData.sensor_data.accelerometer?.length || 0) + 
                           (sensorData.sensor_data.gps?.length || 0),
      building_id: await extractBuildingId(sensorData.sensor_data.gps),
      processed_at: new Date().toISOString()
    };
    
    console.log(`🏢 Processed data for building: ${processedData.building_id}`);
    
    res.status(201).json({
      success: true,
      message: 'Sensor data received and processed',
      session_id: sensorData.session_id,
      data_points: processedData.data_points_collected,
      building_id: processedData.building_id
    });
    
  } catch (error) {
    console.error('❌ Error processing sensor data:', error);
    res.status(500).json({ 
      error: 'Failed to process sensor data',
      details: error.message 
    });
  }
});

// Helper function to extract building ID from GPS coordinates
async function extractBuildingId(gpsData) {
  if (!gpsData || gpsData.length === 0) {
    return 'unknown_location';
  }
  
  // Get the most recent GPS point
  const latestGPS = gpsData[gpsData.length - 1];
  const lat = latestGPS.lat;
  const lon = latestGPS.lon;
  
  // Simple building detection logic (replace with your actual geofencing)
  // This is just a placeholder - you'll implement proper geofencing
  if (lat >= 40.7580 && lat <= 40.7590 && lon >= -73.9860 && lon <= -73.9850) {
    return '123_Main_St_NYC';
  } else if (lat >= 40.7630 && lat <= 40.7640 && lon >= -73.9730 && lon <= -73.9720) {
    return '456_Park_Ave_NYC';
  } else {
    return `building_${lat.toFixed(4)}_${lon.toFixed(4)}`;
  }
}
