# NoahsARK
SMB GUI Pentesting Tool

# Noah's ARK - Advanced SMB Reconnaissance Kit


![title_image](https://github.com/user-attachments/assets/444a5641-f682-480c-9fd7-a42e1a04ac92)


Noah's ARK is a graphical, multi-threaded SMB (Server Message Block) exploration tool designed for network reconnaissance and file discovery. It provides an intuitive interface for scanning networks, browsing file shares, searching for files by name or content, and "looting" interesting files for later review, all while maintaining a responsive user experience.

---

## Features

- **Asynchronous Network Scanning:** Scans IP ranges for open SMB ports without freezing the UI.
- **Multi-threaded Share Browsing:** Authenticates to hosts and explores shares and directories in the background.
- **Robust Connection Handling:** Automatically re-establishes dropped connections for a seamless browsing experience.
- **Powerful File Search:**
    - Search for files by name or content using regular expressions.
    - Built-in scanner for sensitive data patterns (API keys, private keys, passwords).
    - Filter content searches to only include text-based files for speed.
- **Integrated & Detached File Preview:**
    - Preview text files, images, and PDFs directly within the application.
    - On-the-fly conversion of Microsoft Office documents to PDF for previewing (requires LibreOffice).
    - Open files in new, detached windows to compare multiple files at once.
- **Loot Management System:** Add interesting files to a dedicated "Loot" tab to review, preview, and export later.
- **Proxy Support:** Route all SMB traffic through a SOCKS5 proxy for operational security.
- **Modern, Themed UI:** A clean, dark-themed interface built with PyQt5.

---

## Screenshots

**Main Browser View:** Scan a network and browse shares in a familiar tree structure.
![image](https://github.com/user-attachments/assets/0ac04477-63f5-40b1-af58-56e7e02aa518)


**Search & Loot:** Find files across multiple hosts and collect them in the Loot tab.
![image](https://github.com/user-attachments/assets/09e2ed23-8710-4b12-b534-3647a1683c08)

![image](https://github.com/user-attachments/assets/70771d8d-c8bd-4c39-8aeb-4081fbabcbf3)

---

## Requirements

### Python Libraries

The application requires the following Python libraries. You can install them all with `pip`:

- `PyQt5`: For the graphical user interface.
- `impacket`: For all SMB protocol interactions.
- `PyMuPDF`: For rendering PDF previews.
- `pysocks`: For proxy support.

### External Dependencies

- **LibreOffice:** (Optional) Required for the feature that previews Microsoft Office documents (`.docx`, `.xlsx`, `.pptx`, etc.). The tool will function without it, but the Office preview feature will be disabled. It must be available in your system's PATH (e.g., you can type `libreoffice` in your terminal and have it run).

---

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/noahs-ark.git](https://github.com/your-username/noahs-ark.git)
    cd noahs-ark
    ```

2.  **Install the required Python packages:**
    ```bash
    pip install PyQt5 impacket PyMuPDF pysocks
    ```

3.  **(Optional) Install LibreOffice:**
    * **On Debian/Ubuntu:** `sudo apt-get install libreoffice`
    * **On Arch Linux:** `sudo pacman -S libreoffice-still`
    * **On Fedora:** `sudo dnf install libreoffice`

4.  **(Optional) Customize the Title Screen:**
    * To add your own image to the title screen, create a PNG file named `title_image.png` and place it in the same directory as the `NoahsARK.py` script.

---

## Usage

1.  **Launch the application:**
    ```bash
    python3 NoahsARK.py
    ```

2.  **Title Screen:** Click the "Board the ARK" button to proceed to the main application.

3.  **Enter Target Information:**
    * **Target:** Enter a single IP address (`192.168.1.10`), a CIDR range (`192.168.1.0/24`), or a hostname.
    * **Username/Password:** Provide credentials for authenticating to the SMB shares. These can be left blank for anonymous access.
    * **Proxy:** Select a SOCKS5 proxy if needed (the tool assumes proxies are running on `127.0.0.1` at the specified ports).

4.  **Scan & Browse:**
    * Click the **"Scan && Browse"** button to start the network scan. The progress bar will show the status.
    * Hosts that respond and allow authentication will appear in the "Browser" tab.
    * Expand hosts to see shares, and expand shares/folders to browse their contents.

5.  **Previewing Files:**
    * **Browser Tab:** Double-click a file to preview it in the integrated panel. Right-click a file for the option to "View in Detached Window".
    * **Search & Loot Tabs:** Double-click a file to automatically open it in a new detached window.

6.  **Searching for Files:**
    * Navigate to the "Search" tab.
    * Enter keywords (regex supported) and/or select sensitive data patterns to search for.
    * Click "Search". The tool will search across all authenticated hosts.
    * Results will appear in the table.

7.  **Looting Files:**
    * In the "Browser" or "Search" tabs, right-click any file and select "Add to Loot".
    * The file will be added to the "Loot" tab for easy access.
    * From the Loot tab, you can preview, remove, or export the list of looted files as a CSV.

---

## Note

The socks proxys are configured to my setup, if you want to change and configure your own, you must change the code.

---

## Credits

This tool stands on the shoulders of giants. It wouldn't be possible without these amazing open-source projects:
- [Impacket](https://github.com/fortra/impacket) by Fortra
- [PyQt](https://www.riverbankcomputing.com/software/pyqt/) by Riverbank Computing
- [PyMuPDF](https://github.com/pymupdf/PyMuPDF) by Artifex Software

