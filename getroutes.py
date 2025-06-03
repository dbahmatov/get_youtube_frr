import subprocess
import yaml
import os
from loguru import logger
import ipaddress
from typing import List, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import signal
import sys

@dataclass
class Service:
    name: str
    as_numbers: List[int]

@dataclass
class RouterConfig:
    as_number: int
    services: List[Service]
    log_file: str

class TimeoutHandler:
    """Обработчик таймаутов для предотвращения зависания"""
    def __init__(self, timeout_seconds=300):  # 5 минут по умолчанию
        self.timeout_seconds = timeout_seconds
        self.start_time = time.time()
    
    def __enter__(self):
        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(self.timeout_seconds)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
    
    def _timeout_handler(self, signum, frame):
        logger.error(f"Script timeout after {self.timeout_seconds} seconds")
        sys.exit(1)
    
    def check_timeout(self, operation_name=""):
        elapsed = time.time() - self.start_time
        if elapsed > self.timeout_seconds:
            logger.error(f"Manual timeout check failed for {operation_name} after {elapsed:.2f}s")
            sys.exit(1)

def load_config(config_path: str = "config.yaml") -> RouterConfig:
    """Load and validate configuration from YAML file."""
    logger.info(f"Loading configuration from {config_path}")
    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
        
        logger.debug(f"Raw config loaded: {config}")
        
        services = []
        for service_name, service_data in config["router"]["services"].items():
            service = Service(
                name=service_name,
                as_numbers=service_data["as_numbers"]
            )
            services.append(service)
            logger.debug(f"Loaded service {service_name} with AS numbers: {service_data['as_numbers']}")
        
        router_config = RouterConfig(
            as_number=config["router"]["as_number"],
            services=services,
            log_file=config["router"].get("log_file", "routes.log")
        )
        
        logger.info(f"Configuration loaded successfully. Router AS: {router_config.as_number}, Services: {len(services)}")
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
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {function}:{line} | {message}"
    )
    
    # Также выводим в консоль для отладки
    logger.add(
        sys.stderr,
        level="INFO",
        format="{time:HH:mm:ss} | {level:<8} | {message}"
    )
    
    logger.info("Logging initialized with enhanced format")

def fetch_routes(as_number: int) -> List[str]:
    """Fetch routes for a given AS number using WHOIS."""
    start_time = time.time()
    logger.debug(f"Starting route fetch for AS{as_number}")
    
    try:
        whois_command = f"whois -h whois.radb.net -- '-i origin AS{as_number}'"
        logger.debug(f"Executing command: {whois_command}")
        
        result = subprocess.run(
            whois_command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            check=True,
            timeout=30
        )
        
        routes = []
        line_count = 0
        for line in result.stdout.splitlines():
            line_count += 1
            if line.startswith("route:"):
                try:
                    route = line.split()[1]
                    # Валидируем сразу при парсинге
                    ipaddress.ip_network(route, strict=False)
                    routes.append(route)
                except (IndexError, ValueError) as e:
                    logger.warning(f"Invalid route format in line: '{line}', error: {e}")
        
        elapsed = time.time() - start_time
        logger.info(f"AS{as_number}: fetched {len(routes)} routes from {line_count} lines in {elapsed:.2f}s")
        logger.debug(f"AS{as_number} routes sample: {routes[:5]}")
        
        return routes
        
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        logger.error(f"Timeout while fetching routes for AS{as_number} after {elapsed:.2f}s")
        return []
    except subprocess.CalledProcessError as e:
        elapsed = time.time() - start_time
        logger.error(f"Failed to fetch routes for AS{as_number} after {elapsed:.2f}s: {e.stderr}")
        return []
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Unexpected error fetching routes for AS{as_number} after {elapsed:.2f}s: {e}")
        return []

def summarize_routes(ip_ranges: List[str]) -> List[str]:
    """
    Безопасная суммаризация IP диапазонов с проверкой на включение лишних адресов.
    Гарантирует, что в результат не попадут сети, которых не было в исходном списке.
    """
    start_time = time.time()
    logger.info(f"Starting route summarization for {len(ip_ranges)} routes")
    
    if not ip_ranges:
        logger.warning("No routes to summarize")
        return []
    
    try:
        # Шаг 1: Парсим и валидируем сети
        logger.debug("Step 1: Parsing and validating networks")
        valid_networks = []
        invalid_count = 0
        
        for i, ip_range in enumerate(ip_ranges):
            if i % 1000 == 0 and i > 0:
                logger.debug(f"Processed {i}/{len(ip_ranges)} routes")
            
            try:
                network = ipaddress.ip_network(ip_range.strip(), strict=False)
                valid_networks.append(network)
            except ValueError as e:
                invalid_count += 1
                if invalid_count <= 10:  # Показываем только первые 10 ошибок
                    logger.warning(f"Skipping invalid network '{ip_range}': {e}")
                elif invalid_count == 11:
                    logger.warning("Too many invalid networks, suppressing further warnings...")
        
        if not valid_networks:
            logger.error("No valid networks found after parsing")
            return []
        
        logger.info(f"Parsed {len(valid_networks)} valid networks ({invalid_count} invalid)")
        
        # Шаг 2: Удаляем дубликаты
        logger.debug("Step 2: Removing duplicates")
        unique_networks = list(set(valid_networks))
        duplicates_removed = len(valid_networks) - len(unique_networks)
        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate networks")
        
        # Шаг 3: Создаем множество всех исходных IP-адресов для валидации
        logger.debug("Step 3: Building original address set for validation")
        original_addresses = set()
        
        # Ограничиваем проверку для очень больших сетей
        total_addresses = 0
        networks_to_check = []
        
        for net in unique_networks:
            # Пропускаем очень большие сети (больше /8) для экономии памяти
            if net.prefixlen >= 8:
                networks_to_check.append(net)
                total_addresses += net.num_addresses
                # Ограничиваем общее количество адресов для проверки
                if total_addresses > 1000000:  # Максимум 1M адресов для проверки
                    logger.warning(f"Too many addresses to validate ({total_addresses}), using conservative approach")
                    break
            else:
                # Для больших сетей (/0-/7) не делаем полную проверку
                logger.warning(f"Large network {net} - skipping full validation")
                networks_to_check.append(net)
        
        if total_addresses <= 1000000:
            logger.debug(f"Building address set for {len(networks_to_check)} networks ({total_addresses} addresses)")
            for net in networks_to_check:
                if net.prefixlen >= 8:  # Только для сетей /8 и меньше
                    original_addresses.update(net)
                else:
                    # For large networks, we'll skip the detailed check
                    pass
        
        # Шаг 4: Применяем стандартную суммаризацию
        logger.debug("Step 4: Applying standard collapse")
        try:
            if len(unique_networks) > 50000:
                logger.warning(f"Large number of networks ({len(unique_networks)}), this may take time")
            
            collapsed = list(ipaddress.collapse_addresses(unique_networks))
            
            # Шаг 5: Валидация результата
            logger.debug("Step 5: Validating collapsed networks")
            
            if original_addresses and total_addresses <= 1000000:
                # Создаем множество адресов после суммаризации
                collapsed_addresses = set()
                validation_failed = False
                
                for net in collapsed:
                    if net.prefixlen >= 8:  # Проверяем только небольшие сети
                        collapsed_addresses.update(net)
                    elif net not in unique_networks:
                        # Если большая сеть появилась после collapse и её не было в исходных
                        logger.warning(f"Large network {net} appeared after collapse - checking if it's safe")
                        # Проверяем, что эта сеть полностью покрывается исходными сетями
                        covered = any(net.subnet_of(orig_net) or net == orig_net for orig_net in unique_networks)
                        if not covered:
                            logger.error(f"Network {net} was created by collapse but is not covered by original networks")
                            validation_failed = True
                            break
                
                # Проверяем, что не добавились лишние адреса
                if not validation_failed and collapsed_addresses and not collapsed_addresses.issubset(original_addresses):
                    extra_addresses = collapsed_addresses - original_addresses
                    logger.error(f"Collapse added {len(extra_addresses)} addresses not in original set")
                    logger.debug(f"Sample extra addresses: {list(extra_addresses)[:10]}")
                    validation_failed = True
                
                if validation_failed:
                    logger.warning("Validation failed - using conservative approach without collapse")
                    result = [str(net) for net in sorted(unique_networks)]
                    
                    elapsed = time.time() - start_time
                    logger.info(f"Conservative summarization completed in {elapsed:.2f}s:")
                    logger.info(f"  Original routes: {len(ip_ranges)}")
                    logger.info(f"  Valid networks: {len(valid_networks)}")
                    logger.info(f"  After dedup: {len(unique_networks)}")
                    logger.info(f"  Final routes (no collapse): {len(result)}")
                    
                    return result
            else:
                logger.info("Skipping detailed validation due to large network size - using conservative checks")
                # Для больших сетей используем только базовые проверки
                suspicious_networks = []
                for net in collapsed:
                    # Проверяем, что каждая сеть либо была в исходных, либо является суперсетью исходных
                    if net not in unique_networks:
                        # Проверяем, покрывается ли эта сеть исходными сетями
                        is_covered = False
                        covering_nets = []
                        for orig_net in unique_networks:
                            if orig_net.subnet_of(net):
                                covering_nets.append(orig_net)
                            elif net.subnet_of(orig_net) or net == orig_net:
                                is_covered = True
                                break
                        
                        if not is_covered and len(covering_nets) < 2:
                            suspicious_networks.append(net)
                
                if suspicious_networks:
                    logger.warning(f"Found {len(suspicious_networks)} suspicious networks after collapse")
                    logger.debug(f"Suspicious networks: {suspicious_networks[:5]}")
                    # В случае сомнений используем консервативный подход
                    result = [str(net) for net in sorted(unique_networks)]
                    
                    elapsed = time.time() - start_time
                    logger.info(f"Conservative summarization completed in {elapsed:.2f}s:")
                    logger.info(f"  Original routes: {len(ip_ranges)}")
                    logger.info(f"  Final routes (no collapse): {len(result)}")
                    
                    return result
            
            # Если валидация прошла успешно
            elapsed = time.time() - start_time
            reduction = len(ip_ranges) - len(collapsed)
            percentage = (reduction / len(ip_ranges)) * 100 if ip_ranges else 0
            
            logger.info(f"Validated route summarization completed in {elapsed:.2f}s:")
            logger.info(f"  Original routes: {len(ip_ranges)}")
            logger.info(f"  Valid networks: {len(valid_networks)}")
            logger.info(f"  After dedup: {len(unique_networks)}")
            logger.info(f"  Final summarized: {len(collapsed)}")
            logger.info(f"  Reduction: {reduction} routes ({percentage:.1f}%)")
            logger.info("  ✓ Validation passed - no extra addresses added")
            
            # Логируем примеры для отладки
            if collapsed:
                logger.debug(f"Sample summarized routes: {[str(net) for net in collapsed[:10]]}")
            
            return [str(net) for net in collapsed]
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Error during collapse operation after {elapsed:.2f}s: {e}")
            # Возвращаем уникальные сети без суммаризации
            result = [str(net) for net in sorted(unique_networks)]
            logger.info(f"Fallback: returning {len(result)} unique networks without summarization")
            return result
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Critical error in route summarization after {elapsed:.2f}s: {e}")
        # Последний резерв - возвращаем исходные данные
        try:
            unique_ranges = list(set(ip_ranges))
            logger.warning(f"Final fallback: returning {len(unique_ranges)} original unique routes")
            return unique_ranges
        except:
            logger.error("Even fallback failed, returning original list")
            return ip_ranges

def announce_routes(ip_addresses: List[str], router_id: int) -> None:
    """Announce routes using vtysh."""
    logger.info(f"Starting route announcement for {len(ip_addresses)} routes to BGP AS {router_id}")
    
    if not ip_addresses:
        logger.warning("No IP addresses to announce")
        return

    # Логируем первые несколько маршрутов для проверки
    logger.debug(f"Sample routes to announce: {ip_addresses[:5]}")
    
    # Разбиваем на батчи для больших списков
    batch_size = 1000
    batches = [ip_addresses[i:i+batch_size] for i in range(0, len(ip_addresses), batch_size)]
    logger.info(f"Split routes into {len(batches)} batches of max {batch_size} routes each")

    successful_announcements = 0
    
    for batch_num, batch in enumerate(batches, 1):
        logger.debug(f"Processing batch {batch_num}/{len(batches)} with {len(batch)} routes")
        
        command = "\n".join([
            "configure terminal",
            f"router bgp {router_id}",
            *[f"network {ip}" for ip in batch],
            "exit",
            "exit"
        ])

        try:
            start_time = time.time()
            result = subprocess.run(
                ["vtysh", "-c", command],
                check=True,
                text=True,
                capture_output=True,
                timeout=120  # Увеличиваем таймаут для больших батчей
            )
            elapsed = time.time() - start_time
            
            successful_announcements += len(batch)
            logger.info(f"Batch {batch_num}: announced {len(batch)} routes in {elapsed:.2f}s")
            
            if result.stdout:
                logger.debug(f"vtysh stdout: {result.stdout}")
            if result.stderr:
                logger.warning(f"vtysh stderr: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while announcing batch {batch_num}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to announce batch {batch_num}: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error while announcing batch {batch_num}: {e}")
    
    logger.info(f"Route announcement completed: {successful_announcements}/{len(ip_addresses)} routes announced successfully")

def main() -> None:
    """Main execution function with timeout protection."""
    script_start = time.time()
    logger.info("=" * 60)
    logger.info("Starting BGP route fetcher and announcer script")
    logger.info("=" * 60)
    
    try:
        with TimeoutHandler(timeout_seconds=600):  # 10 минут общий таймаут
            config = load_config()
            setup_logging(config.log_file)
            
            logger.info(f"Configuration: AS{config.as_number}, {len(config.services)} services")
            for service in config.services:
                logger.info(f"  Service '{service.name}': {len(service.as_numbers)} AS numbers")
            
            logger.info("Starting parallel route fetching")
            all_routes = set()
            
            # Fetch routes for all services in parallel
            with ThreadPoolExecutor(max_workers=3) as executor:  # Уменьшаем нагрузку
                futures = {}
                
                for service in config.services:
                    logger.info(f"Submitting tasks for service: {service.name}")
                    for asn in service.as_numbers:
                        future = executor.submit(fetch_routes, asn)
                        futures[future] = (service.name, asn)
                
                logger.info(f"Submitted {len(futures)} fetch tasks")
                
                completed_count = 0
                for future in as_completed(futures, timeout=300):  # 5 минут на все запросы
                    service_name, asn = futures[future]
                    completed_count += 1
                    
                    try:
                        routes = future.result()
                        all_routes.update(routes)
                        logger.debug(f"Task {completed_count}/{len(futures)}: AS{asn} ({service_name}) added {len(routes)} routes")
                    except Exception as e:
                        logger.error(f"Failed to get routes for AS{asn} ({service_name}): {e}")
                    
                    if completed_count % 5 == 0:
                        logger.info(f"Progress: {completed_count}/{len(futures)} tasks completed, {len(all_routes)} total routes so far")
            
            logger.info(f"Route fetching completed: {len(all_routes)} unique routes collected")
            
            if not all_routes:
                logger.error("No routes were fetched. Exiting script")
                return
            
            # Конвертируем в список для суммаризации
            routes_list = list(all_routes)
            logger.info(f"Starting route summarization for {len(routes_list)} routes")
            
            summarized_routes = summarize_routes(routes_list)
            
            if not summarized_routes:
                logger.error("Route summarization failed. Exiting script")
                return
            
            logger.info(f"Route summarization completed: {len(summarized_routes)} final routes")
            
            # Анонсируем маршруты
            announce_routes(summarized_routes, config.as_number)
            
            total_elapsed = time.time() - script_start
            logger.info("=" * 60)
            logger.info(f"Script execution completed successfully in {total_elapsed:.2f}s")
            logger.info(f"Final stats: {len(routes_list)} -> {len(summarized_routes)} routes")
            logger.info("=" * 60)
            
    except KeyboardInterrupt:
        logger.warning("Script interrupted by user")
        sys.exit(1)
    except Exception as e:
        total_elapsed = time.time() - script_start
        logger.error(f"Script failed after {total_elapsed:.2f}s: {e}")
        raise

if __name__ == "__main__":
    main()
