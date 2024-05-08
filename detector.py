import os
from telnetlib import IP, RCP
import time
import threading
import logging
import yara
import requests
import keyring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import shutil
import tempfile
import docker
from scapy.all import sniff
from concurrent.futures import ThreadPoolExecutor

class RansomwareEvent:
    """Represents a ransomware event."""

    def __init__(self, file_path: str, file_hash: str, is_ransomware: bool):
        """
        Initialize a RansomwareEvent object.

        Args:
            file_path (str): The path of the file.
            file_hash (str): The hash of the file.
            is_ransomware (bool): A flag indicating whether the file is ransomware.

        Raises:
            TypeError: If file_path or file_hash is not a string, or if is_ransomware is not a boolean.
        """
        if not isinstance(file_path, str):
            raise TypeError("file_path must be a string")
        if not isinstance(file_hash, str):
            raise TypeError("file_hash must be a string")
        if not isinstance(is_ransomware, bool):
            raise TypeError("is_ransomware must be a boolean")

        self.file_path = file_path  # Path of the file
        self.file_hash = file_hash  # Hash of the file
        self.is_ransomware = is_ransomware  # Flag for ransomware

    @property
    def message(self) -> str:
        """Generate a message indicating potential ransomware."""
        return f"File '{self.file_path}' may be ransomware (hash: {self.file_hash})"

    def __repr__(self) -> str:
        """Return a string representation of the object."""
        return f"RansomwareEvent(file_path={self.file_path}, file_hash={self.file_hash}, is_ransomware={self.is_ransomware})"

    def __str__(self) -> str:
        """Return a user-friendly string representation of the object."""
        return self.message

    def __eq__(self, other) -> bool:
        """Check if two RansomwareEvent objects are equal."""
        if not isinstance(other, RansomwareEvent):
            return False
        return (self.file_path, self.file_hash, self.is_ransomware) == (other.file_path, other.file_hash, other.is_ransomware)

    def __hash__(self) -> int:
        """Return a hash value for the object."""
        return hash((self.file_path, self.file_hash, self.is_ransomware))

    def __lt__(self, other) -> bool:
        """Compare two RansomwareEvent objects."""
        if not isinstance(other, RansomwareEvent):
            raise TypeError("Cannot compare RansomwareEvent with other types")
        return (self.file_path, self.file_hash, self.is_ransomware) < (other.file_path, other.file_hash, other.is_ransomware)

    def __iter__(self) -> iter:
        """Return an iterator over the attributes of the object."""
        yield self.file_path
        yield self.file_hash
        yield self.is_ransomware

    def to_dict(self) -> dict:
        """Convert the object to a dictionary."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "is_ransomware": self.is_ransomware
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'RansomwareEvent':
        """Create a RansomwareEvent object from a dictionary."""
        return cls(data["file_path"], data["file_hash"], data["is_ransomware"])

class RansomwareDetector:
    def __init__(self, monitor_directory: str, yara_rules: str, virustotal_api_key: str, metadefender_api_key: str):
        """
        Initialize the RansomwareDetector instance.

        :param monitor_directory: The directory to monitor for suspicious files.
        :param yara_rules: The YARA rules to use for detection.
        :param virustotal_api_key: The API key for VirusTotal.

        :param metadefender_api_key: The API key for MetaDefender.
        """
        self.monitor_directory = monitor_directory
        self.yara_rules = yara_rules
        self.yara_rules_compiled = self.load_yara_rules(yara_rules)
        self.virustotal_api_key = virustotal_api_key
        self.metadefender_api_key = metadefender_api_key
        self.observer = None
        self.logging_file = 'ransomware_detector.log'
        self.init_logging()

    def load_yara_rules(self, yara_rules: str) -> yara.Rules:
        try:
            rules = yara.compile(source=yara_rules)
        except yara.SyntaxError as e:
            logging.error(f"Error compiling YARA rules: {e}")
            raise ValueError(f"Invalid YARA rules: {e}")
        return rules

    def detect_suspicious_files(self, file_path: str) -> bool:
        # Open the file and read its contents
        with open(file_path, 'rb') as f:
            file_contents = f.read()

        # Scan the file contents with the compiled YARA rules
        matches = self.yara_rules_compiled.match(data=file_contents)

        # Check if any rules match
        if matches:
            return True  # File is suspicious
        return False  # File is not suspicious

    def init_logging(self):
        """
        Initialize the logging configuration.
        """
        logging.basicConfig(
            filename=self.logging_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def analyze_file(self, file_path: str):
        """
        Analyze a suspicious file.

        :param file_path: The path to the file to analyze.
        """
        with tempfile.TemporaryDirectory() as sandbox_dir:
            sandbox_file = os.path.join(sandbox_dir, os.path.basename(file_path))
            shutil.copyfile(file_path, sandbox_file)

            with docker.from_env() as client:
                container = client.containers.create("sandbox_image", command="sleep infinity", detach=True)
                container.start()

                try:
                    with open(sandbox_file, "rb") as file:
                        container.put_archive("/", file.read())

                    container.exec_run(f"python3 {os.path.basename(file_path)}", detach=True)

                    self.monitor_container(container, file_path)

                    self.scan_file_metadefender(file_path)

                finally:
                    container.stop()
                    container.remove()

    def monitor_container(self, container, file_path: str, threshold: int = 5):
        """
        Monitor the container and analyze the behavior of the file.

        :param container: The container to monitor.
        :param file_path: The path to the file being analyzed.
        :param threshold: The CPU threshold to consider the container idle.
        """
        self.wait_until_idle(container, threshold)

    def wait_until_idle(self, container, threshold: int = 5):
        """
        Wait until the container is idle.

        :param container: The container to wait for.
        :param threshold: The CPU threshold to consider the container idle.
        """
        while True:
            cpu_stats = container.stats(stream=False)
            cpu_percent = self.calculate_cpu_percent(cpu_stats)
            if cpu_percent < threshold:
                break

    def calculate_cpu_percent(self, stats):
        try:
            cpu_usage = stats['cpu_stats']['cpu_usage']['total_usage']
            precpu_usage = stats['precpu_stats']['cpu_usage']['total_usage']
            system_cpu_usage = stats['cpu_stats']['system_cpu_usage']
            pre_system_cpu_usage = stats['precpu_stats']['system_cpu_usage']

           # Calculate the difference in CPU usage
            cpu_delta = cpu_usage - precpu_usage
            system_delta = system_cpu_usage - pre_system_cpu_usage

            # Calculate the CPU percentage
            cpu_percent = (cpu_delta / system_delta) * 100

            return cpu_percent
        except KeyError:
            return 0

    def scan_file_virustotal(self, file_path: str):
        """
        Scan a file using VirusTotal.

        :param file_path: The path to the file to scan.
        """
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "Content-Type": "application/x-zip-compressed",
            "x-apikey": self.virustotal_api_key,
        }
        files = {"file": open(file_path, "rb")}

        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()

    def scan_file_metadefender(self, file_path: str):
        """
        Scan a file using MetaDefender.

        :param file_path: The path to the file to scan.
        """
        url = "https://metadefender.opswat.com/api/v2/file/scan"
        headers = {
            "Authorization": f"Bearer {self.metadefender_api_key}",
            "Content-Type": "application/octet-stream",
        }

        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, data=file)
        response.raise_for_status()

    def monitor_directory(self):
        """
        Monitor the directory for suspicious files.
        """
        for root, _, files in os.walk(self.monitor_directory):
            for file in files:
                file_path = os.path.join(root, file)
                if self.detect_suspicious_files(file_path):
                    # Take action if the file is suspicious (e.g., log, alert, etc.)
                    logging.warning(f"Potential ransomware detected: {file_path}")
                    self.analyze_file(file_path)

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, ransomware_detector: RansomwareDetector):
        self.ransomware_detector = ransomware_detector

    def on_created(self, event):
        """
        Handle a file creation event.

        :param event: The file creation event.
        """
        if not event.is_directory:
            self.ransomware_detector.monitor_directory()

def main():
    # Initialize the RansomwareDetector instance
    ransomware_detector = RansomwareDetector(
        monitor_directory='/path/to/monitor',
        yara_rules='/path/to/yara_rules.yar',
        virustotal_api_key='YOUR_VIRUSTOTAL_API_KEY',
        metadefender_api_key='YOUR_METADEFENDER_API_KEY'
    )

    # Initialize the RansomwareHandler instance
    ransomware_handler = RansomwareHandler(ransomware_detector)

    # Initialize the observer
    ransomware_detector.observer = Observer()

    # Schedule the RansomwareHandler to monitor the directory
    ransomware_detector.observer.schedule(ransomware_handler, ransomware_detector.monitor_directory, recursive=True)

    # Start the observer
    ransomware_detector.observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Stop the observer
        ransomware_detector.observer.stop()

    # Join the observer
    ransomware_detector.observer.join()

if __name__ == "__main__":
    main()
