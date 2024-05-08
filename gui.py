import detector
from watchdog.observers import Observer
from PySide2.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QGroupBox, QLabel, QPushButton, QLineEdit, QFileDialog, QPlainTextEdit, QHBoxLayout, QGridLayout
from PySide2.QtCore import QThread, Qt
from PySide2.QtCharts import QtCharts
import sys
from PySide2.QtWidgets import QApplication
import configparser


class SettingsWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.load_api_keys()
        self.create_event_log_ui()
        self.create_clear_event_log_button()
        self.create_dashboard_ui()

    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.central_widget_layout = QVBoxLayout()
        self.central_widget.setLayout(self.central_widget_layout)

        self.create_directory_selection_ui()
        self.create_api_key_input_ui()
        self.create_start_monitoring_button()

        self.central_widget_layout.addStretch()

    def create_directory_selection_ui(self):
        directory_groupbox = QGroupBox("Directory Settings")
        directory_layout = QHBoxLayout()

        self.directory_label = QLabel("Select a directory to monitor:")
        self.directory_button = QPushButton("Browse")
        self.directory_button.clicked.connect(self.select_directory)

        directory_layout.addWidget(self.directory_label)
        directory_layout.addWidget(self.directory_button)

        directory_groupbox.setLayout(directory_layout)
        self.central_widget_layout.addWidget(directory_groupbox)

    def create_api_key_input_ui(self):
        api_key_groupbox = QGroupBox("API Key Settings")
        api_key_layout = QGridLayout()

        self.api_key_labels = {}
        self.api_key_input_widgets = {}

        for i, service in enumerate(["VirusTotal", "MetaDefender"]):
            label = QLabel(f"{service.capitalize()} API Key:", self.central_widget)
            input_widget = QLineEdit(self.central_widget)

            api_key_layout.addWidget(label, i, 0)
            api_key_layout.addWidget(input_widget, i, 1)

            self.api_key_labels[service] = label
            self.api_key_input_widgets[service] = input_widget

        api_key_groupbox.setLayout(api_key_layout)
        self.central_widget_layout.addWidget(api_key_groupbox)

    def create_start_monitoring_button(self):
        start_button = QPushButton("Start Monitoring")
        start_button.clicked.connect(self.start_monitoring)
        self.central_widget_layout.addWidget(start_button)

        stop_button = QPushButton("Stop Monitoring")
        stop_button.clicked.connect(self.stop_monitoring)
        self.central_widget_layout.addWidget(stop_button)

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer = None
        self.detector = None

    def create_event_log_ui(self):
        event_log_groupbox = QGroupBox("Event Log")
        event_log_layout = QVBoxLayout()

        self.event_log = QPlainTextEdit()
        event_log_layout.addWidget(self.event_log)

        event_log_groupbox.setLayout(event_log_layout)
        self.central_widget_layout.addWidget(event_log_groupbox)

    def create_clear_event_log_button(self):
        clear_button = QPushButton("Clear Event Log")
        clear_button.clicked.connect(self.clear_event_log)
        self.central_widget_layout.addWidget(clear_button)

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.directory_label.setText(directory)

    def start_monitoring(self):
        if not self.directory_label.text():
            print("Error: No directory selected")
            return

        monitor_directory = self.directory_label.text()
        api_keys = {service: input_widget.text() for service, input_widget in self.api_key_input_widgets.items()}

        self.detector = detector.RansomwareDetector(monitor_directory, **api_keys)
        self.save_api_keys(api_keys)

        self.monitoring_thread = QThread(self)
        self.monitoring_thread.start()

        self.observer = Observer()
        self.event_handler = detector.RansomwareDetector.SuspiciousFileHandler(self.detector)
        self.observer.schedule(self.event_handler, path=self.detector.monitor_directory, recursive=True)
        self.observer.start()

        self.threat_types = {}
        self.event_handler.threat_detected.connect(self.update_threat_types)

    # ...

    def save_api_keys(self, api_keys):
        config = configparser.ConfigParser()
        config["API Keys"] = api_keys

        try:
            with open("config.ini", "w") as configfile:
                config.write(configfile)
        except Exception as e:
            print(f"Error saving API keys: {e}")

    def load_api_keys(self):
        config = configparser.ConfigParser()
        try:
            config.read("config.ini")
            if "API Keys" in config:
                for service, api_key in config["API Keys"].items():
                    self.api_key_input_widgets[service].setText(api_key)
        except Exception as e:
            print(f"Error loading API keys: {e}")

    def clear_event_log(self):
        self.event_log.clear()

    def update_threat_types(self, threat_type):
        if threat_type not in self.threat_types:
            self.threat_types[threat_type] = 1
        else:
            self.threat_types[threat_type] += 1

        self.event_log.appendPlainText(f"Threat detected: {threat_type}")

        if self.threat_types[threat_type] > 5:
            self.event_log.appendPlainText(f"Threat {threat_type} has been detected more than 5 times. Alerting authorities.")

    def create_dashboard_ui(self):
        dashboard_groupbox = QGroupBox("Dashboard")
        dashboard_layout = QVBoxLayout()

        self.dashboard_label = QLabel("Dashboard")
        dashboard_layout.addWidget(self.dashboard_label)

        self.dashboard_chart = QtCharts.QChartView()
        dashboard_layout.addWidget(self.dashboard_chart)

        dashboard_groupbox.setLayout(dashboard_layout)
        self.central_widget_layout.addWidget(dashboard_groupbox)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SettingsWindow()
    window.show()
    sys.exit(app.exec_())