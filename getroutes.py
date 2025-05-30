import subprocess
import yaml
import os
from loguru import logger
import ipaddress
from typing import List, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

@dataclass
class Service:
    name: str
    as_numbers: List[int]

@dataclass
class RouterConfig:
    as_number: int
    services: List[Service]
    log_file: str

def load_config(config_path: str = "config.yaml") -> RouterConfig:
    """Load and validate configuration from YAML file."""
    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
        
        services = []
        for service_name, service_data in config["router"]["services"].items():
            service = Service(
                name=service_name,
                as_numbers=service_data["as_numbers"]
            )
            services.append(service)
        
        router_config = RouterConfig(
            as_number=config["router"]["as_number"],
            services=services,
            log_file=config["router"].get("log_file", "routes.log")
        )
        logger.info("Configuration loaded successfully.")
        return router_config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def setup_logging(log_file: str) -> None:
    """Configure logging with rotation and compression."""
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
        logger.info(f"Created directory for log file: {log_dir}")

    logger.remove()
    logger.add(
        log_file,
        level="DEBUG",
        rotation="10 MB",
        compression="zip",
        backtrace=True,
        diagnose=True,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
    )
    logger.info("Logging initialized.")

def fetch_routes(as_number: int) -> List[str]:
    """Fetch routes for a given AS number using WHOIS."""
    try:
        whois_command = f"whois -h whois.radb.net -- '-i origin AS{as_number}'"
        result = subprocess.run(
            whois_command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            check=True,
            timeout=30
        )
        routes = [line.split()[1] for line in result.stdout.splitlines() if line.startswith("route:")]
        logger.info(f"Fetched {len(routes)} routes for AS{as_number}")
        return routes
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout while fetching routes for AS{as_number}")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fetch routes for AS{as_number}: {e.stderr}")
        return []

def summarize_routes(ip_ranges: List[str]) -> List[str]:
    """Summarize IP ranges to minimize routing table size."""
    try:
        networks = [ipaddress.ip_network(ip) for ip in ip_ranges]
        summarized = list(ipaddress.collapse_addresses(networks))
        logger.info(f"Summarized {len(ip_ranges)} routes to {len(summarized)} ranges")
        return [str(net) for net in summarized]
    except ValueError as e:
        logger.error(f"Error during summarization: {e}")
        return ip_ranges

def announce_routes(ip_addresses: List[str], router_id: int) -> None:
    """Announce routes using vtysh."""
    if not ip_addresses:
        logger.warning("No IP addresses to announce")
        return

    command = "\n".join([
        "configure terminal",
        f"router bgp {router_id}",
        *[f"network {ip}" for ip in ip_addresses],
        "exit"
    ])

    try:
        subprocess.run(
            ["vtysh", "-c", command],
            check=True,
            text=True,
            capture_output=True,
            timeout=60
        )
        logger.info(f"Successfully announced {len(ip_addresses)} routes")
    except subprocess.TimeoutExpired:
        logger.error("Timeout while announcing routes")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to announce routes: {e.stderr}")
    except Exception as e:
        logger.error(f"Unexpected error while announcing routes: {e}")

def main() -> None:
    """Main execution function."""
    config = load_config()
    setup_logging(config.log_file)
    
    logger.info("Fetching routes for all services")
    all_routes = set()
    
    # Fetch routes for all services in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for service in config.services:
            logger.info(f"Processing service: {service.name}")
            for asn in service.as_numbers:
                futures.append(executor.submit(fetch_routes, asn))
        
        for future in futures:
            all_routes.update(future.result())
    
    if not all_routes:
        logger.warning("No routes were fetched. Exiting script")
        return
        
    summarized_routes = summarize_routes(list(all_routes))
    announce_routes(summarized_routes, config.as_number)
    logger.info("Script execution completed")

if __name__ == "__main__":
    main()
