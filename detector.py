import os
from telnetlib import IP, RCP
import time
import hashlib
import threading
import logging
import requests
import keyring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import shutil
import tempfile
import docker
from scapy.all import sniff
from concurrent.futures import ThreadPoolExecutor
from typing import Union


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
    """
    A class for detecting ransomware by analyzing suspicious files.

    :param monitor_directory: The directory to monitor for suspicious files.
    :param virustotal_api_key: The API key for VirusTotal.
    :param metadefender_api_key: The API key for MetaDefender.
    """
    def __init__(self, monitor_directory: str, virustotal_api_key: str, metadefender_api_key: str):
        self.monitor_directory = monitor_directory
        self.virustotal_api_key = virustotal_api_key
        self.metadefender_api_key = metadefender_api_key
        self.observer = None
        self.logging_file = 'ransomware_detector.log'
        self.init_logging()

    def detect_suspicious_files(self, file_path: str) -> bool:
        # Open the file and read its contents
        with open(file_path, 'rb') as f:
            file_contents = f.read()

# Calculate the hash of the file
        file_hash = hashlib.sha256(file_contents).hexdigest()
        self.logger.debug(f'Calculated hash: {file_hash}')

        # Check if the file hash matches any known ransomware hashes
        matches = self.is_file_suspicious(file_hash)
        if matches:
            self.logger.debug(f'Found suspicious hash: {file_hash}')

            # Analyze the file with VirusTotal
            self.logger.debug(f'Calling VirusTotal API with hash: {file_hash}')
            vt_response = self.analyze_file_virustotal(file_hash)

            # Check the VirusTotal results
            if vt_response and vt_response['response_code'] == 1:
                scan_results = vt_response['scans']
                for scan_result in scan_results:
                    if scan_result['detected']:
                        self.logger.debug(f'VirusTotal detected ransomware!')
                        return True
            else:
                self.logger.debug('No VirusTotal results found')

            # Analyze the file with MetaDefender
            self.logger.debug(f'Calling MetaDefender API with hash: {file_hash}')
            md_response = self.analyze_file_metadefender(file_hash)

            # Check the MetaDefender results
            if md_response and md_response['result'] == 'detected':
                self.logger.debug(f'MetaDefender detected ransomware!')
                return True
            else:
                self.logger.debug('No MetaDefender results found')

        return False

    def analyze_file_virustotal(self, file_hash: str) -> dict or None:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {
            'x-apikey': self.virustotal_api_key,
            'Content-Type': 'application/json',
            'Accept-Encoding': 'gzip'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            self.logger.debug('VirusTotal hash not found')
            return None
        else:
            self.logger.debug(f'VirusTotal error: {response.status_code}')
            return None

    def analyze_file_metadefender(self, file_hash: str) -> dict or None:
        url = 'https://metadefender.opswat.com/api/v2/file/hash'
        headers = {
            'Authorization': 'Bearer ' + self.metadefender_api_key,
            'Content-Type': 'application/json'
        }
        data = {
            'hash': file_hash
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            self.logger.debug(f'MetaDefender error: {response.status_code}')
            return None

    def is_file_suspicious(self, file_hash: str) -> bool:
        """Check if a file with the given hash is suspicious."""
        url = 'https://ransomwarehunter.com/api/v1/hashes/check'
        headers = {
            'x-api-key': os.environ.get('RANSOMWAREHUNTER_API_KEY'),
            'Content-Type': 'application/json'
        }
        data = {
            'file_hashes': [file_hash]
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            if response.json()['ransomware_detected'][file_hash]['status_code'] == 1:
                self.logger.debug(f'RansomwareHunter detected ransomware: {response.json()["ransomware_detected"][file_hash]["name"]}')
                return True
            else:
                return False
        else:
            self.logger.debug(f'RansomwareHunter error: {response.status_code}')
            return False

    def handle_suspicious_file(self, file_path: str):
        # Notify the user about the suspicious file
        self.logger.debug(f'Found suspicious file: {file_path}')

    def watch_directory(self):
        self.logger.debug('Starting directory watcher')
        event_handler = self.SuspiciousFileHandler(self)  # Pass self as the detector
        observer = Observer()
        observer.schedule(event_handler, self.monitor_directory, recursive=False)
        observer.start()
        observer.join()

    class SuspiciousFileHandler(FileSystemEventHandler):
        """Handle events when a file is added to the monitor directory"""

        def __init__(self, detector):
            self.detector = detector

        def on_created(self, event):
            if event.is_directory:
                self.detector.logger.debug(f'Ignoring directory event: {event.src_path}')
            else:
                self.detector.logger.debug(f'File created: {event.src_path}')

                # Check if the file is suspicious
                if self.detector.detect_suspicious_files(event.src_path):
                    self.detector.handle_suspicious_file(event.src_path)

        def on_modified(self, event):
            if event.is_directory:
                self.detector.logger.debug(f'Ignoring directory event: {event.src_path}')
            else:
                self.detector.logger.debug(f'File modified: {event.src_path}')

                # Check if the file is suspicious
                if self.detector.detect_suspicious_files(event.src_path):
                    self.detector.handle_suspicious_file(event.src_path)

        def on_deleted(self, event):
            if event.is_directory:
                self.detector.logger.debug(f'Ignoring directory event: {event.src_path}')
            else:
                self.detector.logger.debug(f'File deleted: {event.src_path}')

                # Check if the file was suspicious
                ransomware_event = RansomwareEvent(event.src_path, None, False)
                if ransomware_event in self.detector.recent_ransomware_events:
                    self.detector.recent_ransomware_events.remove(ransomware_event)
                    self.detector.logger.debug(f'File {event.src_path} was marked suspicious but is now deleted')

    def init_logging(self):
        # Initialize logging to a file
        logging.basicConfig(filename=self.logging_file, level=logging.DEBUG, format='%(message)s')

        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        layout = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        console.setFormatter(layout)
        logging.getLogger('').addHandler(console)

        # Log some initialization information
        self.logger.debug('Starting ransomware detector')