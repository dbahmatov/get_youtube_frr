import subprocess
import yaml
import os
from loguru import logger
import ipaddress

def load_config(config_path="config.yaml"):
    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
        logger.info("Configuration loaded successfully.")
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def setup_logging(log_file):
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
            logger.info(f"Created directory for log file: {log_dir}")
        except Exception as e:
            logger.error(f"Failed to create directory {log_dir} for log file: {e}")
            raise
    
    logger.remove()
    logger.add(log_file, level="DEBUG", rotation="10 MB", compression="zip", backtrace=True, diagnose=True)
    logger.info("Logging initialized.")

def fetch_routes(as_number):
    try:
        whois_command = f"whois -h whois.radb.net -- '-i origin AS{as_number}'"
        result = subprocess.run(
            whois_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        logger.debug(f"Raw WHOIS output for AS{as_number}:{result.stdout}")
        routes = [line.split()[1] for line in result.stdout.splitlines() if line.startswith("route:")]
        logger.info(f"Fetched {len(routes)} routes for AS{as_number}.")
        return routes
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fetch routes for AS{as_number}: {e.stderr}")
        return []

def summarize_routes(ip_ranges):
    try:
        networks = [ipaddress.ip_network(ip) for ip in ip_ranges]
        summarized = list(ipaddress.collapse_addresses(networks))
        logger.info(f"Summarized {len(ip_ranges)} routes to {len(summarized)} ranges.")
        return [str(net) for net in summarized]
    except ValueError as e:
        logger.error(f"Error during summarization: {e}")
        return ip_ranges

def announce_routes(ip_addresses, router_id):
    if not ip_addresses:
        logger.warning("No IP addresses to announce.")
        return
    for ip in ip_addresses:
        command = f"""
        configure terminal
        router bgp {router_id}
        network {ip}
        exit
        """
        try:
            subprocess.run(["vtysh", "-c", command], check=True, text=True, capture_output=True)
            logger.info(f"Successfully announced route: {ip}.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to announce route {ip}. Error: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error while announcing {ip}: {e}")

if __name__ == "__main__":
    config = load_config()
    setup_logging(config["router"].get("log_file", "routes.log"))
    router_id = config["router"]["as_number"]
    youtube_as = config["router"]["youtube_as"]
    ggc_as_list = config["router"].get("ggc_as_list", [])
    
    logger.info("Fetching YouTube and GGC routes.")
    all_routes = fetch_routes(youtube_as)
    for asn in ggc_as_list:
        all_routes.extend(fetch_routes(asn))
    
    if not all_routes:
        logger.warning("No routes were fetched. Exiting script.")
    else:
        summarized_routes = summarize_routes(all_routes)
        announce_routes(summarized_routes, router_id)
    
    logger.info("Script execution completed.")

