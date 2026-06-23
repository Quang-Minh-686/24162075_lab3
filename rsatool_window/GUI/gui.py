import sys
import subprocess
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QPushButton,
    QFileDialog,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QTabWidget,
    QComboBox,
)

from PyQt6.QtCore import Qt


BASE_DIR = Path(__file__).resolve().parent
RSATOOL = BASE_DIR / "rsatool.exe"


class RsaToolGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("RSA-OAEP & Hybrid Encryption Tool")
        self.resize(900, 650)

        self.initUI()

    def initUI(self):

        layout = QVBoxLayout()

        title = QLabel("RSA-OAEP & Hybrid Encryption")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            padding: 10px;
        """)

        layout.addWidget(title)

        tabs = QTabWidget()

        tabs.addTab(self.createKeygenTab(), "Key Generation")
        tabs.addTab(self.createEncryptTab(), "Encrypt")
        tabs.addTab(self.createDecryptTab(), "Decrypt")
        tabs.addTab(self.createBenchTab(), "Benchmark")

        layout.addWidget(tabs)

        self.logBox = QTextEdit()
        self.logBox.setReadOnly(True)

        layout.addWidget(QLabel("Output Log"))
        layout.addWidget(self.logBox)

        self.setLayout(layout)

    def createKeygenTab(self):

        widget = QWidget()
        layout = QVBoxLayout()

        self.bitsCombo = QComboBox()
        self.bitsCombo.addItems(["3072", "4096"])

        self.pubEdit = QLineEdit("pub.pem")
        self.privEdit = QLineEdit("priv.pem")

        btn = QPushButton("Generate Keys")
        btn.clicked.connect(self.runKeygen)

        layout.addWidget(QLabel("RSA Bits"))
        layout.addWidget(self.bitsCombo)

        layout.addWidget(QLabel("Public Key"))
        layout.addWidget(self.pubEdit)

        layout.addWidget(QLabel("Private Key"))
        layout.addWidget(self.privEdit)

        layout.addWidget(btn)

        widget.setLayout(layout)

        return widget

    def createEncryptTab(self):

        widget = QWidget()
        layout = QVBoxLayout()

        self.encInput = QLineEdit()
        self.encPub = QLineEdit("pub.pem")
        self.encOutput = QLineEdit("cipher.bin")

        browseIn = QPushButton("Browse Input")
        browseIn.clicked.connect(self.selectEncryptInput)

        browseOut = QPushButton("Browse Output")
        browseOut.clicked.connect(self.selectEncryptOutput)

        self.modeCombo = QComboBox()
        self.modeCombo.addItems([
            "RSA-OAEP",
            "Hybrid AES-256-GCM"
        ])

        btn = QPushButton("Encrypt")
        btn.clicked.connect(self.runEncrypt)

        layout.addWidget(QLabel("Encryption Mode"))
        layout.addWidget(self.modeCombo)

        layout.addWidget(QLabel("Input File"))
        layout.addWidget(self.encInput)
        layout.addWidget(browseIn)

        layout.addWidget(QLabel("Public Key"))
        layout.addWidget(self.encPub)

        layout.addWidget(QLabel("Output File"))
        layout.addWidget(self.encOutput)
        layout.addWidget(browseOut)

        layout.addWidget(btn)

        widget.setLayout(layout)

        return widget

    def createDecryptTab(self):

        widget = QWidget()
        layout = QVBoxLayout()

        self.decInput = QLineEdit()
        self.decPriv = QLineEdit("priv.pem")
        self.decOutput = QLineEdit("recovered.txt")

        browseIn = QPushButton("Browse Cipher")
        browseIn.clicked.connect(self.selectDecryptInput)

        browseOut = QPushButton("Browse Output")
        browseOut.clicked.connect(self.selectDecryptOutput)

        self.decModeCombo = QComboBox()
        self.decModeCombo.addItems([
            "RSA-OAEP",
            "Hybrid AES-256-GCM"
        ])

        btn = QPushButton("Decrypt")
        btn.clicked.connect(self.runDecrypt)

        layout.addWidget(QLabel("Decryption Mode"))
        layout.addWidget(self.decModeCombo)

        layout.addWidget(QLabel("Cipher File"))
        layout.addWidget(self.decInput)
        layout.addWidget(browseIn)

        layout.addWidget(QLabel("Private Key"))
        layout.addWidget(self.decPriv)

        layout.addWidget(QLabel("Output File"))
        layout.addWidget(self.decOutput)
        layout.addWidget(browseOut)

        layout.addWidget(btn)

        widget.setLayout(layout)

        return widget

    def createBenchTab(self):

        widget = QWidget()
        layout = QVBoxLayout()

        btn = QPushButton("Run Benchmark")
        btn.clicked.connect(self.runBenchmark)

        layout.addWidget(btn)

        widget.setLayout(layout)

        return widget

    def appendLog(self, text):
        self.logBox.append(text)

    def runCommand(self, cmd):

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=BASE_DIR
            )

            if result.stdout:
                self.appendLog(result.stdout)

            if result.stderr:
                self.appendLog(result.stderr)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                str(e)
            )

    def runKeygen(self):

        cmd = [
            str(RSATOOL),
            "keygen",
            "--bits",
            self.bitsCombo.currentText(),
            "--pub",
            self.pubEdit.text(),
            "--priv",
            self.privEdit.text(),
        ]

        self.runCommand(cmd)

    def runEncrypt(self):

        mode = self.modeCombo.currentText()

        if mode == "RSA-OAEP":

            cmd = [
                str(RSATOOL),
                "encrypt",
                "--in",
                self.encInput.text(),
                "--pub",
                self.encPub.text(),
                "--out",
                self.encOutput.text(),
            ]

        else:

            cmd = [
                str(RSATOOL),
                "encrypt",
                "--hybrid",
                "--in",
                self.encInput.text(),
                "--pub",
                self.encPub.text(),
                "--out",
                self.encOutput.text(),
            ]

        self.runCommand(cmd)

    def runDecrypt(self):

        mode = self.decModeCombo.currentText()

        if mode == "RSA-OAEP":

            cmd = [
                str(RSATOOL),
                "decrypt",
                "--in",
                self.decInput.text(),
                "--priv",
                self.decPriv.text(),
                "--out",
                self.decOutput.text(),
            ]

        else:

            cmd = [
                str(RSATOOL),
                "decrypt",
                "--hybrid",
                "--in",
                self.decInput.text(),
                "--priv",
                self.decPriv.text(),
                "--out",
                self.decOutput.text(),
            ]

        self.runCommand(cmd)

    def runBenchmark(self):

        cmd = [
            str(RSATOOL),
            "bench"
        ]

        self.runCommand(cmd)

    def selectEncryptInput(self):

        file, _ = QFileDialog.getOpenFileName(self)

        if file:
            self.encInput.setText(file)

    def selectEncryptOutput(self):

        file, _ = QFileDialog.getSaveFileName(self)

        if file:
            self.encOutput.setText(file)

    def selectDecryptInput(self):

        file, _ = QFileDialog.getOpenFileName(self)

        if file:
            self.decInput.setText(file)

    def selectDecryptOutput(self):

        file, _ = QFileDialog.getSaveFileName(self)

        if file:
            self.decOutput.setText(file)


app = QApplication(sys.argv)

window = RsaToolGUI()
window.show()

sys.exit(app.exec())