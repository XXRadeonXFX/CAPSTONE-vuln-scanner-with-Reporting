# At the END of your backend/app.py file, REPLACE the existing monitoring import section with this:

# Remove or comment out this line if it exists:
# from automated_registry_monitor import create_monitoring_app, registry_monitor

@app.route("/report/<report_id>", methods=["GET"])
def get_report(report_id):
    try:
        report = reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        report["_id"] = str(report["_id"])
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": "Invalid report ID"}), 400

# ADD THIS SECTION - Initialize monitoring AFTER Flask app is fully configured
def initialize_monitoring():
    """Initialize the monitoring system with proper component injection."""
    try:
        # Import monitoring components
        from automated_registry_monitor import create_monitoring_app, registry_monitor
        
        # Pass required components to the monitoring system
        import automated_registry_monitor as monitor_module
        
        # Inject components into the monitoring module
        monitor_module.registry_client = registry_client
        monitor_module.run_scan = run_scan
        monitor_module.send_slack_notification = send_slack_notification
        monitor_module.reports_collection = reports_collection
        monitor_module.db = db
        monitor_module.logger = logger
        
        # Initialize the monitoring app with our Flask instance
        create_monitoring_app(app)
        
        # Initialize the registry monitor
        registry_monitor.initialize()
        
        logger.info("✅ Monitoring system initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize monitoring system: {e}")
        print(f"Warning: Monitoring system initialization failed: {e}")

if __name__ == "__main__":
    logger.info("Starting Enhanced Container Registry Vulnerability Scanner v2.1")
    logger.info(f"MongoDB URI configured: {bool(MONGO_URI)}")
    logger.info(f"Slack webhook configured: {bool(SLACK_WEBHOOK_URL)}")
    logger.info(f"Registry URL: {registry_client.registry_url}")
    
    # Initialize monitoring system after app is configured
    initialize_monitoring()
    
    logger.info("Starting Enhanced Container Registry Scanner with Auto-Monitoring")
    
    app.run(host="0.0.0.0", port=5000, debug=True)