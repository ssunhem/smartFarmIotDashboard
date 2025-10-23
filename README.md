# smartFarmIotDashboard
Building Smart Farm IoT Dashboard with Chart.js, Flask-MQTT (+ SocketIO + Gunicorn) and Mosquitto

Requirement: Docker Compose for Integrating all communication destination

Step (for Ubuntu/Debian):
1. cd to the project directory
2. sudo docker-compose build
3. sudo docker-compose up -d --force-recreate (In case of any error)
4. sudo docker-compose ps (to see which containers are not yet up)
5. sudo docker-compose logs custom_app (to see loggin from server)
6. let's open custom_farm_manager.html

   (Continue)
