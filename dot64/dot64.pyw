import sys
import os
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLineEdit,
                             QLabel, QWidget, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
                             QComboBox, QFileDialog, QProgressBar, QTabWidget, QCheckBox, QStyle, QMenu)
from PyQt5.QtCore import Qt, pyqtSignal, QRegExp
from PyQt5.QtGui import QTextCursor, QColor, QSyntaxHighlighter, QTextCharFormat, QFont, QIcon
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import subprocess
import qdarkstyle
class BasicDisassembler:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        try:
            self.pe = pefile.PE(binary_path)
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
            self.code_sections = self._get_code_sections()
            self.functions = self._extract_functions()
        except Exception as e:
            self.pe = None
            self.disassembler = None
            self.code_sections = []
            self.functions = []
            print(f"Error loading PE file: {e}")

    def _get_code_sections(self):
        code_sections = []
        if self.pe:
            for section in self.pe.sections:
                if section.Name.startswith(b'.text'):
                    code_sections.append(section)
        return code_sections

    def _extract_functions(self):
        functions = []
        if self.pe and hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.address:
                        functions.append((imp.address, imp.name.decode() if imp.name else ''))
        return functions

    def disasm(self, code_data, address):
        try:
            return self.disassembler.disasm(code_data, address)
        except Exception as e:
            print(f"Disassembly error: {e}")
            return []

    def disassemble(self):
        disassembly_output = ""
        if not self.code_sections:
            disassembly_output = "No code sections found or failed to load."
        else:
            for section in self.code_sections:
                try:
                    code_data = section.get_data()
                    disassembly_output += f"Disassembling section {section.Name.decode().strip()}:\n"
                    for instruction in self.disassembler.disasm(code_data, section.VirtualAddress):
                        disassembly_output += f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\n"
                except Exception as e:
                    disassembly_output += f"Error disassembling section {section.Name.decode().strip()}: {e}\n"
        return disassembly_output

    def disassemble_at(self, address):
        disassembly_output = ""
        try:
            for section in self.code_sections:
                if section.VirtualAddress <= address < (section.VirtualAddress + section.SizeOfRawData):
                    offset = address - section.VirtualAddress
                    code_data = section.get_data()[offset:]
                    for instruction in self.disassembler.disasm(code_data, address):
                        disassembly_output += f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\n"
                        break
                    break
            else:
                disassembly_output = "Address not within any code section."
        except Exception as e:
            disassembly_output = f"Error disassembling at address {address}: {e}"
        return disassembly_output

    def to_pseudocode(self):
        pseudocode_output = ""
        if not self.code_sections:
            pseudocode_output = "No code sections found or failed to load."
        else:
            for section in self.code_sections:
                try:
                    code_data = section.get_data()
                    pseudocode_output += f"Pseudocode for section {section.Name.decode().strip()}:\n"
                    for instruction in self.disassembler.disasm(code_data, section.VirtualAddress):
                        pseudocode_output += self.translate_to_pseudocode(instruction) + "\n"
                except Exception as e:
                    pseudocode_output += f"Error generating pseudocode for section {section.Name.decode().strip()}: {e}\n"
        return pseudocode_output

    def translate_to_pseudocode(self, instruction):
        # TRANSLATE
        translation_rules = {
            "mov": "assign",
            "add": "add",
            "sub": "subtract",
            "jmp": "goto",
            "call": "call function",
            "ret": "return",
            "push": "push to stack",
            "pop": "pop from stack"
        }
        mnemonic = instruction.mnemonic
        op_str = instruction.op_str
        if mnemonic in translation_rules:
            return f"{translation_rules[mnemonic]} {op_str}"
        return f"{mnemonic} {op_str}"

class StartupDialog(QDialog):
    file_selected = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Select File Type")
        self.setGeometry(300, 300, 300, 150)
        self.file_path = None
        self.file_type = None

        self.initUI()
        self.load_recent_files()

    def initUI(self):
        layout = QVBoxLayout()

        self.label = QLabel("Select file type:")
        layout.addWidget(self.label)

        self.file_type_combo = QComboBox()
        self.file_type_combo.addItems(["Executable (EXE)", "Dynamic Link Library (DLL)", "Binary (BIN)"])
        layout.addWidget(self.file_type_combo)

        self.browse_button = QPushButton("Browse", self)
        self.browse_button.clicked.connect(self.browse_file)
        layout.addWidget(self.browse_button)

        self.recent_files_menu = QMenu("Recent Files", self)
        self.recent_files_button = QPushButton("Recent Files", self)
        self.recent_files_button.setMenu(self.recent_files_menu)
        layout.addWidget(self.recent_files_button)

        self.ok_button = QPushButton("OK", self)
        self.ok_button.clicked.connect(self.emit_file_selected)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)

    def browse_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Binary File", "", "Executable Files (*.exe *.dll *.bin);;All Files (*)", options=options)
        if file_path:
            self.file_path = file_path

    def load_recent_files(self):
        if os.path.exists('recent_files.json'):
            with open('recent_files.json', 'r') as f:
                recent_files = json.load(f)
                for file_path, file_type in recent_files:
                    action = self.recent_files_menu.addAction(file_path)
                    action.triggered.connect(lambda checked, path=file_path, type=file_type: self.select_recent_file(path, type))

    def select_recent_file(self, file_path, file_type):
        self.file_path = file_path
        self.file_type = file_type
        self.emit_file_selected()

    def emit_file_selected(self):
        self.file_type = self.file_type_combo.currentText()
        self.file_selected.emit(self.file_path, self.file_type)
        self.accept()

class AssemblyHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.highlighting_rules = []

        self.address_format = QTextCharFormat()
        self.address_format.setForeground(QColor("#FF5733"))

        self.mnemonic_format = QTextCharFormat()
        self.mnemonic_format.setForeground(QColor("#C70039"))
        self.operand_format = QTextCharFormat()
        self.operand_format.setForeground(QColor("#900C3F"))

        keywords = ["mov", "add", "sub", "jmp", "call", "ret", "push", "pop"]
        for keyword in keywords:
            self.highlighting_rules.append((QRegExp(f"\\b{keyword}\\b"), self.mnemonic_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        address_expression = QRegExp(r"\b0x[0-9a-fA-F]+\b")
        address_index = address_expression.indexIn(text)
        while address_index >= 0:
            length = address_expression.matchedLength()
            self.setFormat(address_index, length, self.address_format)
            address_index = address_expression.indexIn(text, address_index + length)

        operand_expression = QRegExp(r", [a-zA-Z0-9]+")
        operand_index = operand_expression.indexIn(text)
        while operand_index >= 0:
            length = operand_expression.matchedLength()
            self.setFormat(operand_index + 2, length - 2, self.operand_format)
            operand_index = operand_expression.indexIn(text, operand_index + length)

class PseudocodeHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.highlighting_rules = []

        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor("#007ACC"))
        self.keyword_format.setFontWeight(QFont.Bold)

        self.identifier_format = QTextCharFormat()
        self.identifier_format.setForeground(QColor("#D4AC0D"))

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#7DCEA0"))
        self.comment_format.setFontItalic(True)

        keywords = ["assign", "add", "subtract", "goto", "call function", "return", "push to stack", "pop from stack"]
        for keyword in keywords:
            self.highlighting_rules.append((QRegExp(f"\\b{keyword}\\b"), self.keyword_format))

        self.highlighting_rules.append((QRegExp(r"#.*"), self.comment_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
class HexHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.highlighting_rules = []

        self.byte_format = QTextCharFormat()
        self.byte_format.setForeground(QColor("#FF5733"))

        self.ascii_format = QTextCharFormat()
        self.ascii_format.setForeground(QColor("#900C3F"))

        self.address_format = QTextCharFormat()
        self.address_format.setForeground(QColor("#007ACC"))

    def highlightBlock(self, text):
        byte_pattern = QRegExp(r"\b[0-9a-fA-F]{2}\b")
        index = byte_pattern.indexIn(text)
        while index >= 0:
            length = byte_pattern.matchedLength()
            self.setFormat(index, length, self.byte_format)
            index = byte_pattern.indexIn(text, index + length)

        ascii_pattern = QRegExp(r"\s\|[^\|]*\|")
        index = ascii_pattern.indexIn(text)
        while index >= 0:
            length = ascii_pattern.matchedLength()
            self.setFormat(index, length, self.ascii_format)
            index = ascii_pattern.indexIn(text, index + length)

        address_pattern = QRegExp(r"\b0x[0-9a-fA-F]+\b")
        index = address_pattern.indexIn(text)
        while index >= 0:
            length = address_pattern.matchedLength()
            self.setFormat(index, length, self.address_format)
            index = address_pattern.indexIn(text, index + length)


class DisassemblerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("dot64")
        self.setWindowIcon(QIcon("assets/asm.png"))
        self.setGeometry(100, 100, 1200, 800)
        self.dark_mode_enabled = False
        self.load_dark_mode_state()

        main_layout = QVBoxLayout()
        central_widget = QWidget(self)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        toolbar_layout = QHBoxLayout()
        self.address_input = QLineEdit(self)
        self.address_input.setPlaceholderText("Enter address (e.g., 0x401000)")
        toolbar_layout.addWidget(self.address_input)

        self.disassemble_button = QPushButton("Disassemble", self)
        self.disassemble_button.clicked.connect(self.disassemble_at_address)
        toolbar_layout.addWidget(self.disassemble_button)

        self.dump_button = QPushButton("Dump Binary", self)
        self.dump_button.clicked.connect(self.dump_binary)
        toolbar_layout.addWidget(self.dump_button)

        self.run_button = QPushButton("Debug", self)
        self.run_button.clicked.connect(self.run_file)
        toolbar_layout.addWidget(self.run_button)

        self.dark_mode_checkbox = QCheckBox("Dark Mode", self)
        self.dark_mode_checkbox.stateChanged.connect(self.toggle_mode)
        toolbar_layout.addWidget(self.dark_mode_checkbox)
        self.status_label = QLabel("", self)
        toolbar_layout.addWidget(self.status_label)
        main_layout.addLayout(toolbar_layout)

        main_splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(main_splitter)

        self.tabs = QTabWidget(self)
        main_splitter.addWidget(self.tabs)

        self.disassembly_view = QTextEdit(self)
        self.disassembly_view.setReadOnly(True)
        self.highlighter = AssemblyHighlighter(self.disassembly_view.document())
        self.tabs.addTab(self.disassembly_view, "Disassembly")

        self.hex_view = QTextEdit(self)
        self.hex_view.setReadOnly(True)
        self.hex_highlighter = HexHighlighter(self.hex_view.document())
        self.tabs.addTab(self.hex_view, "Hex View")

        self.pseudocode_view = QTextEdit(self)
        self.pseudocode_view.setReadOnly(True)
        self.pseudocode_highlighter = PseudocodeHighlighter(self.pseudocode_view.document())
        self.tabs.addTab(self.pseudocode_view, "Pseudocode")

        self.functions_view = QTableWidget(self)
        self.functions_view.setColumnCount(2)
        self.functions_view.setHorizontalHeaderLabels(["Address", "Function Name"])
        self.functions_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tabs.addTab(self.functions_view, "Functions")

        self.output_view = QTextEdit(self)
        self.output_view.setReadOnly(True)
        main_splitter.addWidget(self.output_view)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 1)

        if self.dark_mode_enabled:
            self.dark_mode_checkbox.setChecked(True)
            self.toggle_mode(Qt.Checked)

    def load_dark_mode_state(self):
        if os.path.exists('settings.json'):
            with open('settings.json', 'r') as f:
                settings = json.load(f)
                self.dark_mode_enabled = settings.get("dark_mode", False)

    def save_dark_mode_state(self):
        settings = {"dark_mode": self.dark_mode_enabled}
        with open('settings.json', 'w') as f:
            json.dump(settings, f)

    def initialize_with_file(self, file_path, file_type):
        self.file_path = file_path
        self.file_type = file_type
        self.disassembler = BasicDisassembler(self.file_path)
        self.populate_code_view()
        self.populate_hex_view()
        self.populate_pseudocode_view()
        self.populate_functions_view()
        self.populate_info_display()
        self.status_label.setText(f"Loaded: {self.file_path}")

        file_name = os.path.basename(self.file_path)
        self.setWindowTitle(f"dot64 - {file_name}")

        self.save_recent_file(self.file_path, self.file_type)

    def save_recent_file(self, file_path, file_type):
        recent_files = []
        if os.path.exists('recent_files.json'):
            with open('recent_files.json', 'r') as f:
                recent_files = json.load(f)
        if (file_path, file_type) not in recent_files:
            recent_files.append((file_path, file_type))
        with open('recent_files.json', 'w') as f:
            json.dump(recent_files[-10:], f)

    def populate_info_display(self):
        if self.disassembler:
            info_text = f"Binary Path: {self.file_path}\n"
            info_text += f"Binary Type: {self.file_type}\n"
            info_text += f"Number of Code Sections: {len(self.disassembler.code_sections)}"
            self.output_view.append(info_text)

    def populate_code_view(self):
        self.disassembly_view.clear()
        if self.disassembler:
            self.disassembly_view.append(self.disassembler.disassemble())

    def populate_hex_view(self):
        self.hex_view.clear()
        if self.disassembler:
            try:
                hex_data = self.disassembler.pe.get_memory_mapped_image()
                hex_str = ''
                for i in range(0, len(hex_data), 16):
                    hex_str += f"{i:08x}  "
                    hex_str += ' '.join(f'{b:02x}' for b in hex_data[i:i+16])
                    hex_str += '   '
                    hex_str += ''.join(chr(b) if 32 <= b < 127 else '.' for b in hex_data[i:i+16])
                    hex_str += '\n'
                self.hex_view.setText(hex_str)
            except Exception as e:
                self.hex_view.setText(f"Error loading hex view: {e}")

    def populate_pseudocode_view(self):
        self.pseudocode_view.clear()
        if self.disassembler:
            try:
                self.pseudocode_view.append(self.disassembler.to_pseudocode())
            except Exception as e:
                self.pseudocode_view.setText(f"Error generating pseudocode view: {e}")

    def populate_functions_view(self):
        self.functions_view.setRowCount(0)
        if self.disassembler:
            for address, name in self.disassembler.functions:
                row_position = self.functions_view.rowCount()
                self.functions_view.insertRow(row_position)
                self.functions_view.setItem(row_position, 0, QTableWidgetItem(f"0x{address:x}"))
                self.functions_view.setItem(row_position, 1, QTableWidgetItem(name))

    def disassemble_at_address(self):
        address_text = self.address_input.text()
        try:
            address = int(address_text, 16)
            if self.disassembler:
                disassembly_output = self.disassembler.disassemble_at(address)
                self.disassembly_view.clear()
                self.disassembly_view.append(disassembly_output)
            else:
                self.status_label.setText("No file loaded.")
        except ValueError:
            self.status_label.setText("Invalid address format.")

    def dump_binary(self):
        if self.file_path:
            file_name, file_extension = os.path.splitext(self.file_path)
            output_path, _ = QFileDialog.getSaveFileName(self, "Save Dump File", file_name + "_dump" + file_extension)
            if output_path:
                try:
                    with open(self.file_path, 'rb') as f:
                        with open(output_path, 'wb') as f_out:
                            f_out.write(f.read())
                    self.output_view.append(f"Binary dumped to: {output_path}")
                except Exception as e:
                    self.output_view.append(f"Error dumping binary: {e}")

    def run_file(self):
        if self.file_path:
            try:
                result = subprocess.run(self.file_path, check=True, capture_output=True, text=True)
                self.output_view.append(f"Output:\n{result.stdout}")
            except subprocess.CalledProcessError as e:
                self.output_view.append(f"Error:\n{e.stderr}")
            except Exception as e:
                self.output_view.append(f"Failed to run the file: {e}")

    def toggle_mode(self, state):
        if state == Qt.Checked:
            self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
            self.dark_mode_enabled = True
        else:
            self.setStyleSheet("")
            self.dark_mode_enabled = False
        self.save_dark_mode_state()


    def run_file(self):
        if self.file_path:
            try:
                os.startfile(self.file_path)
            except Exception as e:
                self.output_view.append(f"Error running file: {e}")
        else:
            self.status_label.setText("No file loaded.")

    def closeEvent(self, event):
        self.save_dark_mode_state()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)

    startup_dialog = StartupDialog()
    disassembler_gui = DisassemblerGUI()

    startup_dialog.file_selected.connect(disassembler_gui.initialize_with_file)

    if startup_dialog.exec_() == QDialog.Accepted:
        disassembler_gui.showMaximized()
        disassembler_gui.show()

    sys.exit(app.exec_())
