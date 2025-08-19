import requests
import time
import os
from pyfiglet import figlet_format
from colorama import Fore, Style, init

init(autoreset=True)

API_KEY = "API-KEY-VIRUSTOTAL"
SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

def print_colored_banner(text, color):
    banner = figlet_format(text, font="mini")
    color_map = {
        "blue": Fore.CYAN,
        "red": Fore.RED,
        "green": Fore.GREEN
    }
    print("\n" + color_map.get(color, Fore.WHITE) + banner + "\n")

def get_report_with_polling(api_key, scan_id, max_attempts=4, interval=5):
    params = {"apikey": api_key, "resource": scan_id}
    for attempt in range(max_attempts):
        response = requests.get(REPORT_URL, params=params)
        if response.status_code == 200:
            report = response.json()
            if report.get("response_code") == 1:
                return report
            else:
                print(f"{Fore.YELLOW}Отчёт не готов (попытка {attempt+1}/{max_attempts}) — ждём {interval} секунд...{Style.RESET_ALL}")
        elif response.status_code == 204:
            print(f"{Fore.RED}Превышен лимит запросов (204), ждём {interval} секунд...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Ошибка запроса отчёта: {response.status_code}{Style.RESET_ALL}")
        time.sleep(interval)
    print(f"{Fore.RED}Отчёт не получен за отведённое время.{Style.RESET_ALL}")
    return None

def scan_file_vt(api_key, file_path):
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            params = {"apikey": api_key}
            response = requests.post(SCAN_URL, files=files, params=params)
        if response.status_code != 200:
            print(f"{Fore.RED}Ошибка отправки файла на VirusTotal: {response.status_code}{Style.RESET_ALL}")
            return None

        result = response.json()
        scan_id = result.get("scan_id")
        if not scan_id:
            print(f"{Fore.RED}Не удалось получить scan_id для файла {file_path}.{Style.RESET_ALL}")
            return None

        print(f"{Fore.CYAN}Файл отправлен на сканирование: {file_path}, scan_id: {scan_id}{Style.RESET_ALL}")

        report = get_report_with_polling(api_key, scan_id)
        return report

    except Exception as e:
        print(f"{Fore.RED}Ошибка при обработке файла {file_path}: {e}{Style.RESET_ALL}")
        return None

def scan_path(api_key, path):
    all_files = []

    if not os.path.exists(path):
        print(f"{Fore.RED}Путь не существует: {path}{Style.RESET_ALL}")
        return

    if os.path.isdir(path):
        print(f"{Fore.CYAN}Сканируем папку: {path}{Style.RESET_ALL}")
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if os.path.isfile(full_path):
                    all_files.append(full_path)
    else:
        all_files.append(path)

    print(f"{Fore.CYAN}Найдено файлов для проверки: {len(all_files)}{Style.RESET_ALL}")

    virus_found = False

    for fpath in all_files:
        report = scan_file_vt(api_key, fpath)
        if report:
            positives = report.get("positives", 0)
            total = report.get("total", 0)
            print(f"{Fore.YELLOW}{fpath}: Обнаружено {positives} угроз из {total} движков{Style.RESET_ALL}")
            if positives > 0:
                virus_found = True
                for av, data in report.get("scans", {}).items():
                    if data.get("detected"):
                        print(f" - {Fore.RED}{av}: {data.get('result')}{Style.RESET_ALL}")
        print("-" * 60)

    if virus_found:
        print_colored_banner("VIRUSTOTAL.PY", "red")
    else:
        print_colored_banner("VIRUSTOTAL.PY", "green")

if __name__ == "__main__":
    print_colored_banner("VIRUSTOTAL.PY", "blue")
    path_to_scan = input("Введите путь к файлу или папке для проверки на вирусы: ").strip()
    scan_path(API_KEY, path_to_scan)
