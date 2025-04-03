import os
import platform
import subprocess
import psutil
from datetime import datetime

from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma

def collect_system_info():
    """Collect detailed system configuration information"""
    system_info = {
        "os": {
            "name": platform.system(),
            "version": platform.version(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "distribution": platform.platform(),
        },
        "hardware": {
            "processor": platform.processor(),
            "physical_cores": psutil.cpu_count(logical=False),
            "total_cores": psutil.cpu_count(logical=True),
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available,
        },
        "software": {
            "python_version": platform.python_version(),
        },
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add installed packages depending on OS
    if platform.system() == "Windows":
        try:
            # Get installed software on Windows
            installed_software = subprocess.check_output('wmic product get name,version', shell=True).decode('utf-8')
            system_info["software"]["installed_packages"] = [
                line.strip() for line in installed_software.split('\n') 
                if line.strip() and "Name" not in line
            ]
        except:
            system_info["software"]["installed_packages"] = ["Failed to retrieve installed packages"]
    
    elif platform.system() == "Linux":
        try:
            # For Debian/Ubuntu
            dpkg_output = subprocess.check_output('dpkg-query -W -f="${Package} ${Version}\n"', shell=True).decode('utf-8', errors='ignore')
            system_info["software"]["installed_packages"] = [
                line.strip() for line in dpkg_output.split('\n') if line.strip()
            ]
        except:
            try:
                # For Red Hat/CentOS
                rpm_output = subprocess.check_output('rpm -qa --qf "%{NAME} %{VERSION}\n"', shell=True).decode('utf-8', errors='ignore')
                system_info["software"]["installed_packages"] = [
                    line.strip() for line in rpm_output.split('\n') if line.strip()
                ]
            except:
                system_info["software"]["installed_packages"] = ["Failed to retrieve installed packages"]
    
    elif platform.system() == "Darwin":  # macOS
        try:
            brew_output = subprocess.check_output('brew list --versions', shell=True).decode('utf-8', errors='ignore')
            system_info["software"]["installed_packages"] = [
                line.strip() for line in brew_output.split('\n') if line.strip()
            ]
        except:
            system_info["software"]["installed_packages"] = ["Failed to retrieve installed packages"]
    
    return system_info

def store_system_info(persistent_directory, embeddings):
    """Store system information in the vector database"""
    system_info = collect_system_info()
    
    # Convert system info to documents
    documents = []
    
    # Create document for OS info
    os_text = f"Operating System: {system_info['os']['name']} {system_info['os']['version']} {system_info['os']['release']} ({system_info['os']['architecture']})"
    documents.append(Document(
        page_content=os_text,
        metadata={"source": "system_info", "category": "os", "timestamp": system_info['timestamp']}
    ))
    
    # Create document for hardware info
    hardware_text = f"Hardware: Processor: {system_info['hardware']['processor']}, Physical cores: {system_info['hardware']['physical_cores']}, Total cores: {system_info['hardware']['total_cores']}, Memory: {system_info['hardware']['memory_total'] // (1024*1024*1024)} GB"
    documents.append(Document(
        page_content=hardware_text,
        metadata={"source": "system_info", "category": "hardware", "timestamp": system_info['timestamp']}
    ))
    
    # Create documents for installed packages (chunked in groups of 10)
    if "installed_packages" in system_info["software"]:
        packages = system_info["software"]["installed_packages"]
        for i in range(0, len(packages), 10):
            chunk = packages[i:i+10]
            package_text = "Installed packages: " + ", ".join(chunk)
            documents.append(Document(
                page_content=package_text,
                metadata={"source": "system_info", "category": "software", "chunk_id": i//10, "timestamp": system_info['timestamp']}
            ))
    
    # Create the vector store directory if it doesn't exist
    os.makedirs(os.path.dirname(persistent_directory), exist_ok=True)
    
    # Check if the database already exists
    if os.path.exists(persistent_directory):
        # Load the existing vector store
        db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
        # Add the new system info documents
        db.add_documents(documents)
    else:
        # Create a new vector store
        db = Chroma.from_documents(
            documents=documents,
            embedding=embeddings,
            persist_directory=persistent_directory
        )
    
    # Persist the vector store
    db.persist()
    return len(documents)
