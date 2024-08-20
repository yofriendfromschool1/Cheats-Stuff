import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, 
    QVBoxLayout, QHBoxLayout, QMessageBox, QComboBox, QTableWidget, 
    QTableWidgetItem, QSizePolicy
)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt
import psutil
import pymem

class DotEngine(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Dot Engine')
        self.setWindowIcon(QIcon('assets/logo.png'))
        self.resize(1000, 700)

        layout = QVBoxLayout()

        # Top Layout: Process selection and Search Icon
        top_layout = QHBoxLayout()
        self.process_label = QLabel('Process:')
        self.process_combo = QComboBox()
        self.process_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.process_combo.addItems(self.get_process_list())
        self.refresh_button = QPushButton()
        self.refresh_button.setIcon(QIcon('assets/search.png'))
        self.refresh_button.setIconSize(QPixmap('assets/search.png').rect().size())
        self.refresh_button.clicked.connect(self.refresh_process_list)
        top_layout.addWidget(self.process_label)
        top_layout.addWidget(self.process_combo)
        top_layout.addWidget(self.refresh_button)
        layout.addLayout(top_layout)

        # Middle Layout: Memory address, value, scan options
        middle_layout = QHBoxLayout()

        address_layout = QVBoxLayout()
        self.address_label = QLabel('Memory Address (hex):')
        self.address_input = QLineEdit()
        address_layout.addWidget(self.address_label)
        address_layout.addWidget(self.address_input)

        value_layout = QVBoxLayout()
        self.value_label = QLabel('Value:')
        self.value_input = QLineEdit()
        value_layout.addWidget(self.value_label)
        value_layout.addWidget(self.value_input)

        scan_layout = QVBoxLayout()
        self.scan_button = QPushButton('First Scan')
        self.next_scan_button = QPushButton('Next Scan')
        self.scan_button.clicked.connect(self.scan_memory)
        self.next_scan_button.clicked.connect(self.next_scan_memory)
        scan_layout.addWidget(self.scan_button)
        scan_layout.addWidget(self.next_scan_button)

        middle_layout.addLayout(address_layout)
        middle_layout.addLayout(value_layout)
        middle_layout.addLayout(scan_layout)

        layout.addLayout(middle_layout)

        # Bottom Layout: Table for addresses and values
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(['Address', 'Value', 'Previous', 'Next'])
        layout.addWidget(self.result_table)

        # Logo
        self.logo_label = QLabel()
        self.logo_label.setPixmap(QPixmap('assets/logo.png'))
        self.logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.logo_label)

        # Recent and Next Scan Features
        feature_layout = QHBoxLayout()
        self.recent_label = QLabel('Recent Scan:')
        self.recent_value_label = QLabel('No recent scan')
        self.next_label = QLabel('Next Scan:')
        self.next_value_label = QLabel('No next scan')
        feature_layout.addWidget(self.recent_label)
        feature_layout.addWidget(self.recent_value_label)
        feature_layout.addWidget(self.next_label)
        feature_layout.addWidget(self.next_value_label)
        layout.addLayout(feature_layout)

        self.setLayout(layout)

    def get_process_list(self):
        process_list = []
        for proc in psutil.process_iter(['pid', 'name']):
            process_list.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
        return process_list

    def refresh_process_list(self):
        self.process_combo.clear()
        self.process_combo.addItems(self.get_process_list())

    def read_memory(self, pm, address, size):
        try:
            data = pm.read_bytes(address, size)
            return data
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            return None

    def scan_memory(self):
        process_text = self.process_combo.currentText()
        try:
            pid = int(process_text.split('(PID: ')[1].split(')')[0])
        except (IndexError, ValueError):
            QMessageBox.critical(self, "Error", "Failed to parse process ID.")
            return

        address_text = self.address_input.text()
        value_text = self.value_input.text()
        if not address_text or not value_text:
            QMessageBox.critical(self, "Error", "Please enter a valid memory address and value.")
            return

        try:
            address = int(address_text, 16)
            value = int(value_text)
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid memory address or value.")
            return

        try:
            pm = pymem.Pymem()
            pm.open_process_from_id(pid)
            data = self.read_memory(pm, address, 4)  # Assuming 4 bytes for simplicity
            if data:
                self.display_results(address, data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def next_scan_memory(self):
        QMessageBox.information(self, "Info", "Next Scan functionality not yet implemented.")
        # Placeholder for next scan logic

    def display_results(self, address, data):
        self.result_table.setRowCount(1)
        self.result_table.setItem(0, 0, QTableWidgetItem(hex(address)))
        self.result_table.setItem(0, 1, QTableWidgetItem(hex(int.from_bytes(data, byteorder='little'))))
        self.result_table.setItem(0, 2, QTableWidgetItem("Previous Value"))
        self.result_table.setItem(0, 3, QTableWidgetItem("Next Value"))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = DotEngine()
    ex.show()
    sys.exit(app.exec_())
