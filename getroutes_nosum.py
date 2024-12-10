import subprocess
import yaml
import os
from loguru import logger

# Чтение конфигурации из YAML-файла
def load_config(config_path="config.yaml"):
    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
        logger.info("Configuration loaded successfully.")
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

# Настройка логирования
def setup_logging(log_file):
    # Убедимся, что директория для файла лога существует
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
            logger.info(f"Created directory for log file: {log_dir}")
        except Exception as e:
            logger.error(f"Failed to create directory {log_dir} for log file: {e}")
            raise

    # Настройка логирования в файл
    logger.remove()  # Удаляем все существующие обработчики
    logger.add(log_file, level="DEBUG", rotation="10 MB", compression="zip", backtrace=True, diagnose=True)
    logger.info("Logging initialized.")

# Функция для получения маршрутов YouTube через команду WHOIS
def fetch_youtube_routes(youtube_as):
    try:
        whois_command = f"whois -h whois.radb.net -- '-i origin AS{youtube_as}'"
        result = subprocess.run(
            whois_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        logger.debug(f"Raw WHOIS output:\n{result.stdout}")
        routes = result.stdout.splitlines()
        logger.info(f"Successfully fetched routes for AS{youtube_as} from RADB.")
        return routes
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fetch YouTube routes: {e.stderr}")
        return []

# Извлекаем только маршруты с полем route:
def extract_route_addresses(routes):
    ip_ranges = []
    for line in routes:
        if line.startswith("route:"):
            ip_range = line.split()[1]
            ip_ranges.append(ip_range)
    logger.info(f"Extracted {len(ip_ranges)} IP ranges.")
    return ip_ranges

# Удалить все текущие маршруты
def remove_existing_routes(router_id):
    try:
        command = f"""
        configure terminal
        router bgp {router_id}
        no network 0.0.0.0/0
        """
        process = subprocess.run(
            ["vtysh", "-c", command],
            check=True,
            text=True,
            capture_output=True
        )
        logger.info("Successfully removed all existing routes.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to remove existing routes: {e.stderr}")
    except Exception as e:
        logger.error(f"Unexpected error while removing routes: {e}")

# Анонсировать маршруты через BGP
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
            process = subprocess.run(["vtysh", "-c", command], check=True, text=True, capture_output=True)
            logger.info(f"Successfully announced route: {ip}. Output: {process.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to announce route: {ip}. Error: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error while announcing {ip}: {e}")

if __name__ == "__main__":
    # Загрузка конфигурации
    config = load_config()

    # Настройка логирования
    log_file = config["router"].get("log_file", "youtube_routes.log")
    setup_logging(log_file)

    # Получение параметров из конфигурации
    router_id = config["router"]["as_number"]
    youtube_as = config["router"]["youtube_as"]

    # Удаление текущих маршрутов
    logger.info("Removing existing routes.")
    remove_existing_routes(router_id)

    # Получение новых маршрутов
    logger.info("Fetching YouTube routes.")
    routes = fetch_youtube_routes(youtube_as)

    if not routes:
        logger.warning("No routes were fetched. Exiting script.")
    else:
        ip_addresses = extract_route_addresses(routes)

        # Анонсирование маршрутов
        logger.info("Announcing YouTube IP ranges.")
        announce_routes(ip_addresses, router_id)

    logger.info("Script execution completed.")

