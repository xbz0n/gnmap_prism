# gnmap_prism

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/Language-Python%203-blue" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-orange" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License">
</p>

<p align="center">
  <b>gnmap_prism</b> is a Python script designed to parse, analyze, and process Nmap's grepable output format (`-oG`), transforming raw scan data into structured reports and target lists.
</p>

<p align="center">
  <a href="https://xbz0n.sh"><img src="https://img.shields.io/badge/Blog-xbz0n.sh-red" alt="Blog"></a>
</p>

---

## Overview

`gnmap_prism.py` streamlines the post-scan workflow when using Nmap's grepable output (`-oG`). It takes a `.gnmap` file as input and generates various organized text files, facilitating report generation, vulnerability analysis, and targeted follow-up actions based on scan results. The script helps make sense of large Nmap outputs by categorizing hosts and ports effectively.

## Features

- **Comprehensive Parsing:** Accurately extracts host status (Up/Down) and open ports/services from `.gnmap` files.
- **Multi-Format Output:** Generates various file types for different use cases:
    - Detailed `summary.txt` report.
    - `up-hosts.txt` list of live hosts.
    - Service-specific host lists (e.g., `ssh-hosts.txt`, `http-hosts.txt`).
    - Generic URL lists (`web-urls.txt`, `smb-urls.txt`).
    - Formatted target lists for tools like `testssl`, `smbclient` (`*-targets.txt`).
    - `segmentation-report.txt` analyzing network visibility.
- **Scope Awareness:** Automatically attempts to extract scan scope from the `.gnmap` header or allows manual scope definition via arguments/file.
- **Customizable:** Output directory and specific file generation can be controlled via command-line arguments.
- **Cross-Platform:** Runs on any system with Python 3.

## System Compatibility

| OS             | Compatibility | Notes                            |
|----------------|---------------|----------------------------------|
| Linux          | ✅            | Fully compatible                 |
| macOS          | ✅            | Fully compatible                 |
| Windows        | ✅            | Fully compatible                 |
| Other (Python 3)| ✅            | Should work if Python 3 is available |

## Requirements

- Python 3.3 or higher (due to the use of the `ipaddress` standard library module).
- An Nmap scan output file in grepable format (`.gnmap`).

## Installation

No complex installation is required. Simply download or clone the script:

```bash
# Clone the repository (optional)
# git clone https://github.com/xbz0n/gnmap_prism
# cd gnmap_prism

# Ensure the script is executable (optional)
# chmod +x gnmap_prism.py
```

## Usage

Run the script from your terminal, providing the path to your `.gnmap` file.

### Basic Usage

```bash
./gnmap_prism.py <your_nmap_scan.gnmap>
```
This will create a directory named `gnmap_prism_results-YYYY-MM-DD-HH-MM-SS/` with default output files (summary, up-hosts, split files, generic URLs).

### Advanced Usage

```bash
# Specify output directory and generate tool targets and segmentation report
./gnmap_prism.py scan.gnmap -o ./my_scan_results --gen-tools --segmentation --source-ip 10.0.0.5

# Specify scope manually and disable split files
./gnmap_prism.py scan.gnmap --scope "192.168.1.0/24,10.10.0.0/16" --no-split

# Use a scope file
./gnmap_prism.py scan.gnmap --scope-file targets.txt
```

### Command-Line Arguments

| Argument           | Description                                                                |
|--------------------|----------------------------------------------------------------------------|
| `input_file`       | **Required.** Path to the Nmap `.gnmap` file.                              |
| `--out-dir`, `-o`  | Specify a custom output directory name.                                    |
| `--source-ip`      | Specify the source IP used for the scan (for segmentation report).         |
| `--scope`          | Comma-separated list of target IPs/CIDRs (overrides auto-detection).       |
| `--scope-file`     | File containing target IPs/CIDRs, one per line (overrides auto-detection). |
| `--no-summary`     | Disable generation of `summary.txt`.                                       |
| `--no-split`       | Disable generation of `[service/port]-hosts.txt` files.                    |
| `--no-rename`      | Use port numbers instead of service names for split file names.            |
| `--no-generic-urls`| Disable generation of `web-urls.txt` and `smb-urls.txt`.                 |
| `--no-up`          | Disable generation of `up-hosts.txt`.                                      |
| `--gen-tools`      | Enable generation of tool-specific target files (`*-targets.txt`).           |
| `--segmentation`   | Enable generation of `segmentation-report.txt`.                            |
| `--force`          | Allow overwriting files if the output directory already exists.            |

## Script Workflow

1.  **Parse Arguments:** Reads command-line options.
2.  **Determine Scope:** Extracts scope from `.gnmap` header or uses user-provided scope.
3.  **Parse `.gnmap` File:** Reads the input file line by line, extracting host status and open port information.
4.  **Generate Outputs:** Creates the enabled output files in the specified directory based on the parsed data.
5.  **Print Summary:** Displays a summary of actions taken and files created to the console.

## Output Files Generated

Depending on the options used, the following files may be created in the output directory:

-   `summary.txt`: Human-readable report showing hosts with open ports, hosts up without open ports, and down hosts.
-   `up-hosts.txt`: Simple list of IPs found to be 'Up'.
-   `[service/port]-hosts.txt`: Lists of IPs per open port/service (e.g., `ssh-hosts.txt`).
-   `web-urls.txt`: List of potential HTTP/HTTPS URLs.
-   `smb-urls.txt`: List of potential SMB shares/hosts.
-   `[tool]-targets.txt`: Target lists formatted for specific tools (e.g., `testssl-targets.txt`).
-   `segmentation-report.txt`: Analysis of network reachability vs. open ports for the defined scope.

## Troubleshooting

-   **File Not Found:** Ensure the path to the `.gnmap` input file is correct.
-   **Permission Denied:** Check if you have write permissions for the output directory location.
-   **Parsing Errors:** Malformed or non-standard `.gnmap` lines might cause warnings or incomplete results. Ensure the input file was generated correctly with `nmap -oG`.
-   **Scope Issues:** If automatic scope detection fails, provide the scope manually using `--scope` or `--scope-file`.
-   **No Output Files:** Check the console output. If no hosts were found up or no open ports were detected according to your scan parameters, some files might be empty or not generated.

## Contributing

Contributions, issues, and feature requests are welcome! Please feel free to submit a Pull Request or open an issue.

## Author

- **Ivan Spiridonov (xbz0n)** - [Blog](https://xbz0n.sh) | [GitHub](https://github.com/xbz0n)

## License

This project is licensed under the MIT License - see the `LICENSE` file for details (assuming one exists, otherwise state "MIT License").

## Acknowledgments

- The [Nmap Project](https://nmap.org/) for the essential network scanning tool.
