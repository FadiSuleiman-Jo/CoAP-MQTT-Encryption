import subprocess
import os

# Function to start Mosquitto broker on a specific IP and port
def run_mosquitto_broker(ip_address="192.168.1.14", port=1883):
    # Create a temporary configuration file
    config_file = "mosquitto_temp.conf"
    
    # Write the listener configuration to the file
    with open(config_file, "w") as f:
        f.write(f"listener {port} {ip_address}\n")
        f.write("allow_anonymous true\n")  # Allow anonymous connections (optional)

    try:
        # Start the Mosquitto broker with the custom configuration file
        print(f"Starting Mosquitto broker on {ip_address}:{port} using config {config_file}...")
        broker_process = subprocess.Popen(['mosquitto', '-c', config_file],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print(f"Broker running on {ip_address}:{port}. Press Ctrl+C to stop.")
        # Wait for the process to complete (this keeps the broker running)
        broker_process.communicate()

    except KeyboardInterrupt:
        print("\nStopping the Mosquitto broker...")
        broker_process.terminate()

    except Exception as e:
        print(f"Error: {e}")
        if broker_process:
            broker_process.terminate()
    
    finally:
        # Cleanup: Remove the temporary configuration file
        if os.path.exists(config_file):
            os.remove(config_file)

# Specify the IP address and port you want the broker to listen on
run_mosquitto_broker(ip_address="192.168.1.14", port=1883)