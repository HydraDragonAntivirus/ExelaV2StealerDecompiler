import os
import struct
import marshal
import zlib
import sys
from uuid import uuid4 as uniquename
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii
import re
import pefile
import pyzipper
import subprocess
import tempfile

# Set script directory
script_dir = os.getcwd()

detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
# 7-Zip executable path
seven_zip_executable = "C:\\Program Files\\7-Zip\\7z.exe"

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name

class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b'\0' * 4
        self.barePycList = [] # List of pyc's whose headers have to be fixed


    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[!] Error: Could not open {0}'.format(self.filePath))
            return False
        return True


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    def checkFile(self):
        print('[+] Processing {0}'.format(self.filePath))

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            print('[!] Error : File is too short or truncated')
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            print('[!] Error : Missing cookie, unsupported pyinstaller version or not a pyinstaller archive')
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self.fPtr.read(64).lower():
            print('[+] Pyinstaller version: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
        else:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[+] Pyinstaller version: 2.0')

        return True


    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = \
                struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = \
                struct.unpack('!8sIIii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            print('[!] Error : The file is not a pyinstaller archive')
            return False

        self.pymaj, self.pymin = (pyver//100, pyver%100) if pyver >= 100 else (pyver//10, pyver%10)
        print('[+] Python version: {0}.{1}'.format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - (self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE)

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[+] Length of package: {0} bytes'.format(lengthofPackage))
        return True


    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iIIIBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!IIIBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                print('[!] Warning: File name {0} contains invalid bytes. Using random name {1}'.format(name, newName))
                name = newName
            
            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList.append( \
                                CTOCEntry(                      \
                                    self.overlayPos + entryPos, \
                                    cmprsdDataSize,             \
                                    uncmprsdDataSize,           \
                                    cmprsFlag,                  \
                                    typeCmprsData,              \
                                    name                        \
                                ))

            parsedLen += entrySize
        print('[+] Found {0} files in CArchive'.format(len(self.tocList)))


    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace('/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        if nmDir != '' and not os.path.exists(nmDir): # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, 'wb') as f:
            f.write(data)


    def extractFiles(self):
        print('[+] Beginning extraction...please standby')
        extractionDir = os.path.join(os.getcwd(), 'exela_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    print('[!] Error : Failed to decompress {0}'.format(entry.name))
                    continue
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check

            if entry.typeCmprsData == b'd' or entry.typeCmprsData == b'o':
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                print('[+] Possible entry point: {0}.pyc'.format(entry.name))

                if self.pycMagic == b'\0' * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + '.pyc')
                self._writePyc(entry.name + '.pyc', data)

            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b'\r\n':
                    # < pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4: 
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + '.pyc', data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + '.pyc')

                    self._writePyc(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)

        # Fix bare pyc's if any
        self._fixBarePycs()


    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, 'r+b') as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)


    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(self.pycMagic)            # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:                # PEP 552 -- Deterministic pycs
                pycFile.write(b'\0' * 4)        # Bitfield
                pycFile.write(b'\0' * 8)        # (Timestamp + size) || hash 

            else:
                pycFile.write(b'\0' * 4)      # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)


    def _extractPyz(self, name):
        dirName = 'exela_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' # Sanity Check

            pyzPycMagic = f.read(4) # Python magic value

            if self.pycMagic == b'\0' * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                print('[!] Warning: pyc magic of files inside PYZ archive are different from those in CArchive')

            # Skip PYZ extraction if not running under the same python version
            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                print('[!] Warning: This script is running in a different Python version than the one used to build the executable.')
                print('[!] Please run this script in Python {0}.{1} to prevent extraction errors during unmarshalling'.format(self.pymaj, self.pymin))
                print('[!] Skipping pyz extraction')
                return

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return

            print('[+] Found {0} files in PYZ archive'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode('utf-8')
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace('..', '__').replace('.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(filePath))
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)  

def DecryptString(key, tag, nonce, _input):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(_input) + decryptor.finalize()
    return decrypted_data.decode(errors="ignore")

def add_base64_padding(b64_string):
    padding = len(b64_string) % 4
    if padding != 0:
        b64_string += '=' * (4 - padding)
    return b64_string

def extract_base64_string(line):
    """ Extract base64 string from the line, removing the surrounding code. """
    match = re.search(r"'([^']+)'|\"([^\"]+)\"", line)
    if match:
        return match.group(1) or match.group(2)
    return None

def extract_webhooks(content):
    """ Extract webhook URLs from the content. """
    webhook_pattern = r'https://discord\.com/api/webhooks/\d+/\S+'
    return re.findall(webhook_pattern, content)

def is_winrar_sfx(file_path):
    """
    Checks if the file is a WinRAR SFX archive using detectiteasy.
    """
    try:
        # Path to the detectiteasy console executable
        detectiteasy_dir = os.path.join(os.path.dirname(__file__), "detectiteasy")
        detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")
        
        if not os.path.exists(detectiteasy_console_path):
            print(f"[-] detectiteasy console (diec.exe) not found at {detectiteasy_console_path}")
            return False

        print(f"[*] Checking file: {file_path}")

        # Create a temporary file with a simple name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as temp_file:
            temp_file_path = temp_file.name
            
            # Copy original file content to the temporary file
            with open(file_path, "rb") as original_file:
                temp_file.write(original_file.read())
            
            # Close to ensure the file is ready for external use
            temp_file.close()

            # Verify that the file path exists before executing
            if not os.path.exists(temp_file_path):
                print(f"[-] Verified failure: temporary file does not exist at {temp_file_path}")
                return False
            
            print(f"[*] Running detectiteasy on {temp_file_path}")

            # Run the command
            result = subprocess.run([detectiteasy_console_path, temp_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode != 0:
                print(f"[-] Error running detectiteasy:\n{result.stderr}")
                print(f"[*] Subprocess output:\n{result.stdout}")
                return False

            print(f"[*] Subprocess output:\n{result.stdout}")

            # Determine if it's a WinRAR SFX
            if "Sfx: WinRAR" in result.stdout:
                print("[+] This is a WinRAR SFX archive.")
                return True
            else:
                print("[-] This is not a WinRAR SFX archive.")
                return False

    except Exception as e:
        print(f"[-] Error processing the file: {e}")
        return False
        
def is_zip_file(zip_path):
    """Checks if the file is a ZIP archive."""
    try:
        # Attempt to open the file as an AES Zip file
        with pyzipper.AESZipFile(zip_path) as zip_file:
            # If it opens without error, return True indicating it's a ZIP file
            return True
    except (pyzipper.zipfile.BadZipFile, RuntimeError):
        # If the file is not a valid ZIP archive, return False
        return False
    except PermissionError:
        print(f"[-] Permission denied: {zip_path}. Unable to access the file.")
        return False
    except FileNotFoundError:
        print(f"[-] File not found: {zip_path}. Ensure the file path is correct.")
        return False
    except Exception as e:
        print(f"[-] Unexpected error while checking ZIP file: {e}")
        return False

def is_pe_file(file_path):
    """Checks if the file is a valid PE file using pefile."""
    try:
        pe = pefile.PE(file_path)
        # If no exception was raised, the file is a valid PE file
        return True
    except pefile.PEFormatError:
        # If the file is not a valid PE file, it raises a PEFormatError
        return False
    except Exception as e:
        print(f"[-] Error processing {file_path}: {e}")
        return False

def extract_with_7z(archive_path, output_dir='extracted_output', seven_zip_folder='C:\\Program Files\\7-Zip'):
    """Extracts a file using 7-Zip and checks for PE files in the extracted content."""
    
    # Define the path to the 7z executable
    seven_zip_path = os.path.join(seven_zip_folder, '7z.exe')
    
    # Check if the 7z executable exists
    if not os.path.exists(seven_zip_path):
        print(f"[-] 7z.exe not found at {seven_zip_path}")
        return None
    
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Running the extraction command
    extraction_command = [seven_zip_path, 'x', archive_path, f'-o{output_dir}', '-y']
    result = subprocess.run(extraction_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Check if extraction was successful
    if result.returncode != 0:
        print(f"[-] Error during extraction:\n{result.stderr}")
        return None

    # Log extraction success
    print(f"[*] Extraction successful:\n{result.stdout}")

    # Verify extracted files
    extracted_files = os.listdir(output_dir)
    if not extracted_files:
        print("[!] No files were extracted.")
        return None

    print(f"[+] Files extracted to {output_dir}")
    
    # Track the latest PE file found
    latest_executable = None
    
    # Process each extracted file individually
    for file in extracted_files:
        file_path = os.path.join(output_dir, file)
        
        # Check if the extracted file is a PE file
        if is_pe_file(file_path):
            print(f"[+] Found PE file: {file_path}")
            latest_executable = file_path  # Update the latest executable path
        
        # Check if the extracted file is a ZIP archive
        elif is_zip_file(file_path):
            print(f"[+] Found ZIP archive: {file_path}")
        
        else:
            print(f"[-] {file_path} is neither a PE file nor a ZIP archive.")
    
    # After processing, return the latest executable found, if any
    if latest_executable:
        print(f"[+] Latest executable found: {latest_executable}")
        return latest_executable
    else:
        print("[!] No executable found in extracted files.")
        return None
        
def find_pe_files(directory):
    """Scans a directory for PE files using the pefile library."""
    pe_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_pe_file(file_path):
                pe_files.append(file_path)
    return pe_files

def extract_zip_file(zip_path, output_dir='extracted_zip', password='infected'):
    """Extracts files from a ZIP archive, handles nested ZIPs."""
    if not is_zip_file(zip_path):
        print("[!] The file is not a valid ZIP archive.")
        return None
    os.makedirs(output_dir, exist_ok=True)
    try:
        with pyzipper.AESZipFile(zip_path) as zip_file:
            zip_file.extractall(output_dir, pwd=password.encode())
            print(f"[+] ZIP file extracted to '{output_dir}'.")
            return output_dir
    except RuntimeError:
        print("[!] Incorrect password or encryption issue.")
        return None

def process_file_until_non_archive(file_path, output_dir='processed_output', password='infected'):
    """Recursively processes archives until it finds a non-SFX, non-ZIP file or reaches an executable."""
    current_path = file_path
    final_executable_path = None  # Track the latest executable found
    
    while True:
        # Check if the current file is an executable
        if is_pe_file(current_path):
            print(f"[+] Executable file found: {current_path}")
            final_executable_path = current_path  # Update the latest executable path
            
            # If it's an executable, check if it's also a WinRAR SFX archive
            if is_winrar_sfx(current_path):
                print(f"[*] WinRAR SFX archive detected: {current_path}")
                extracted_path = extract_with_7z(current_path, output_dir)
                
                if extracted_path is None:
                    print("[!] No executable found in SFX.")
                    return final_executable_path  # Return the last executable found before SFX
                
                print(f"[+] Executable extracted from SFX: {extracted_path}")
                current_path = extracted_path  # Update the path to the newly extracted executable
                continue  # Continue processing the extracted executable file

            else:
                # It's a regular executable, break out of the loop and return this file path
                return final_executable_path

        # If the file is a ZIP archive, extract it and process the nested files
        elif is_zip_file(current_path):
            print(f"[*] ZIP file detected: {current_path}")
            extracted_path = extract_zip_file(current_path, output_dir, password)
            if extracted_path is None:
                print("[!] Could not extract ZIP file.")
                return final_executable_path  # Return the last executable path if ZIP extraction fails

            # Handle nested files if any are extracted from the ZIP
            nested_files = [os.path.join(extracted_path, f) for f in os.listdir(extracted_path)]
            if nested_files:
                current_path = nested_files[0]  # Continue with the first nested file
            else:
                print("[!] No files found in extracted ZIP.")
                return final_executable_path  # Return the last executable path if ZIP has no files
        else:
            # If it's neither an archive nor an executable, break and return the last executable found
            print(f"[+] Non-archive, non-executable file found: {current_path}")
            return final_executable_path  # Return the last executable path processed

    return final_executable_path  # Return the final executable path after all processing
      
def main():
    exela_path = input("Enter the path of the infected Exela Stealer file: ")
    output_dir = "exela_extracted"

    # Step 1: Unpack nested archives until we reach the actual file
    final_file_path = process_file_until_non_archive(exela_path, output_dir)
    if final_file_path is None:
        print("[!] Could not reach the final file for processing.")
        return
    
    print(f"[+] Final file path for processing: {final_file_path}")

    arch = PyInstArchive(final_file_path)
    if arch.open():
        if arch.checkFile():
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles()
                arch.close()

                os.chdir("..")

                # Decompiling the Stub.pyc file using pycdc.exe
                stub_path = os.path.join(os.getcwd(), 'exela_extracted', 'Stub.pyc')
                output_file = 'exela_stealer.py'
                
                if os.path.exists(stub_path):
                    os.system(f'pycdc.exe "{stub_path}" > "{output_file}"')
                    print(f'[+] Code extracted to {output_file} successfully.')
                else:
                    print('[!] Error: Stub.pyc not found in the extracted files.')
                    return

                # Now to decrypt the content of exela_stealer.py
                with open(output_file, 'r', encoding='utf-8') as file:
                    content = file.read()

                # Extract key, tag, and nonce from the content
                key_line = [line for line in content.splitlines() if line.startswith("key = ")][0]
                tag_line = [line for line in content.splitlines() if line.startswith("tag = ")][0]
                nonce_line = [line for line in content.splitlines() if line.startswith("nonce = ")][0]

                # Extract base64 strings using the new function
                key_base64 = extract_base64_string(key_line)
                tag_base64 = extract_base64_string(tag_line)
                nonce_base64 = extract_base64_string(nonce_line)

                # Print extracted base64 strings for debugging
                print(f"Extracted Base64 Key: {key_base64}")
                print(f"Extracted Base64 Tag: {tag_base64}")
                print(f"Extracted Base64 Nonce: {nonce_base64}")

                # Clean and decode the values
                try:
                    key = base64.b64decode(add_base64_padding(key_base64))
                    tag = base64.b64decode(add_base64_padding(tag_base64))
                    nonce = base64.b64decode(add_base64_padding(nonce_base64))
                except (binascii.Error, ValueError) as e:
                    print(f"[!] Error decoding base64: {e}")
                    return

                encrypted_data_line = [line for line in content.splitlines() if "encrypted_data" in line][0]
                encrypted_data_base64 = extract_base64_string(encrypted_data_line)
                encrypted_data = base64.b64decode(add_base64_padding(encrypted_data_base64))

                # First decryption to get intermediate data
                intermediate_data = DecryptString(key, tag, nonce, encrypted_data)

                # Save intermediate data to a temporary file for the second decryption
                temp_file = 'intermediate_data.py'
                with open(temp_file, 'w', encoding='utf-8') as temp:
                    temp.write(intermediate_data.strip())  # Remove leading/trailing whitespace

                # Extract key, tag, and nonce from the intermediate data
                with open(temp_file, 'r', encoding='utf-8') as temp:
                    intermediate_content = temp.read()

                key_line_2 = [line for line in intermediate_content.splitlines() if line.startswith("key = ")][0]
                tag_line_2 = [line for line in intermediate_content.splitlines() if line.startswith("tag = ")][0]
                nonce_line_2 = [line for line in intermediate_content.splitlines() if line.startswith("nonce = ")][0]

                # Extract base64 strings from the intermediate data
                key_base64_2 = extract_base64_string(key_line_2)
                tag_base64_2 = extract_base64_string(tag_line_2)
                nonce_base64_2 = extract_base64_string(nonce_line_2)

                # Print extracted base64 strings for debugging
                print(f"Extracted Base64 Key 2: {key_base64_2}")
                print(f"Extracted Base64 Tag 2: {tag_base64_2}")
                print(f"Extracted Base64 Nonce 2: {nonce_base64_2}")

                # Clean and decode the second set of values
                try:
                    key_2 = base64.b64decode(add_base64_padding(key_base64_2))
                    tag_2 = base64.b64decode(add_base64_padding(tag_base64_2))
                    nonce_2 = base64.b64decode(add_base64_padding(nonce_base64_2))
                except (binascii.Error, ValueError) as e:
                    print(f"[!] Error decoding base64 in second decryption: {e}")
                    return

                encrypted_data_2_line = [line for line in intermediate_content.splitlines() if "encrypted_data" in line][0]
                encrypted_data_2_base64 = extract_base64_string(encrypted_data_2_line)
                encrypted_data_2 = base64.b64decode(add_base64_padding(encrypted_data_2_base64))

                # Decrypt the final data
                final_decrypted_data = DecryptString(key_2, tag_2, nonce_2, encrypted_data_2)

                # Save the final source code
                source_code_file = 'exela_stealer_last_stage.py'
                with open(source_code_file, 'w', encoding='utf-8') as source_file:
                    lines = final_decrypted_data.strip().splitlines()
                    # Remove leading whitespace if the next line has leading whitespace
                    cleaned_lines = [lines[i].rstrip() if i + 1 < len(lines) and lines[i + 1].startswith(" ") else lines[i]
                                     for i in range(len(lines))]
                    source_file.write('\n'.join(cleaned_lines))  # Write cleaned lines

                print(f'[+] Source code decrypted and saved to {source_code_file} successfully.')

                # Now decrypt the exela_source_code.py one more time
                exela_source_code_path = source_code_file
                with open(exela_source_code_path, 'r', encoding='utf-8') as file:
                    source_code_content = file.read()

                # Extract key, tag, and nonce from the source code
                key_line_final = [line for line in source_code_content.splitlines() if line.startswith("key = ")][0]
                tag_line_final = [line for line in source_code_content.splitlines() if line.startswith("tag = ")][0]
                nonce_line_final = [line for line in source_code_content.splitlines() if line.startswith("nonce = ")][0]

                # Extract base64 strings from the final source code
                key_base64_final = extract_base64_string(key_line_final)
                tag_base64_final = extract_base64_string(tag_line_final)
                nonce_base64_final = extract_base64_string(nonce_line_final)

                # Print extracted base64 strings for debugging
                print(f"Extracted Base64 Key Final: {key_base64_final}")
                print(f"Extracted Base64 Tag Final: {tag_base64_final}")
                print(f"Extracted Base64 Nonce Final: {nonce_base64_final}")

                # Clean and decode the final set of values
                try:
                    key_final = base64.b64decode(add_base64_padding(key_base64_final))
                    tag_final = base64.b64decode(add_base64_padding(tag_base64_final))
                    nonce_final = base64.b64decode(add_base64_padding(nonce_base64_final))
                except (binascii.Error, ValueError) as e:
                    print(f"[!] Error decoding base64 in final decryption: {e}")
                    return

                encrypted_data_final_line = [line for line in source_code_content.splitlines() if "encrypted_data" in line][0]
                encrypted_data_final_base64 = extract_base64_string(encrypted_data_final_line)
                encrypted_data_final = base64.b64decode(add_base64_padding(encrypted_data_final_base64))

                # Decrypt the final data again
                final_decrypted_data_2 = DecryptString(key_final, tag_final, nonce_final, encrypted_data_final)

                # Save the final result as exela_last_stage.py
                final_file = 'exela_stealer_source_code.py'
                with open(final_file, 'w', encoding='utf-8') as final_source_file:
                    lines = final_decrypted_data_2.strip().splitlines()
                    # Remove leading whitespace if the next line has leading whitespace
                    cleaned_lines_final = [lines[i].rstrip() if i + 1 < len(lines) and lines[i + 1].startswith(" ") else lines[i]
                                           for i in range(len(lines))]
                    final_source_file.write('\n'.join(cleaned_lines_final))  # Write cleaned lines

                print(f'[+] Final code decrypted and saved to {final_file} successfully.')

                # Extract webhook URLs from the final content
                webhooks = extract_webhooks(final_decrypted_data_2)
                if webhooks:
                    print("[+] Webhook URLs found:")
                    for webhook in webhooks:
                        print(webhook)
                else:
                    print("[!] No webhook URLs found.")

if __name__ == '__main__':
    main()
