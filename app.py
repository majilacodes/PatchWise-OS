import os
import json
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import platform
import subprocess
import psutil
from langchain.chains import create_history_aware_retriever, create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_huggingface import HuggingFaceEmbeddings

# Load environment variables from .env
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Define the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
persistent_directory = os.path.join(current_dir, "db", "chroma_db_with_metadata")
nvd_api_key = os.getenv("NVD_API_KEY", "")  # Get NVD API key from .env

# Define the embedding model
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-mpnet-base-v2")

# Create LLM instance
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")

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

def store_system_info():
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

def fetch_vulnerabilities():
    """Fetch latest OS vulnerabilities from NVD database"""
    # Get current system info to use for fetching relevant vulnerabilities
    system_info = collect_system_info()
    os_name = system_info['os']['name'].lower()
    
    # Map internal OS names to CVE searchable terms
    os_search_terms = {
        "windows": "windows",
        "linux": "linux",
        "darwin": "macos"
    }
    
    search_term = os_search_terms.get(os_name, os_name)
    
    # Calculate the date 30 days ago (to get recent vulnerabilities)
    thirty_days_ago = (datetime.now() - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000")
    current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
    
    # Set up the NVD API request
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": search_term,
        "pubStartDate": thirty_days_ago,
        "pubEndDate": current_time
    }
    
    # Only add API key header if it exists in environment variables
    headers = {}
    if nvd_api_key and nvd_api_key.strip():
        headers["apiKey"] = nvd_api_key
    
    try:
        response = requests.get(url, params=params, headers=headers)
        # Add a delay to respect rate limits when not using API key
        if not nvd_api_key or not nvd_api_key.strip():
            import time
            time.sleep(6)  # NVD has a rate limit of 10 requests per minute without API key
            
        if response.status_code == 200:
            vulnerabilities = response.json().get('vulnerabilities', [])
            
            # Convert to documents and store in vector database
            documents = []
            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                description = cve.get('descriptions', [{}])[0].get('value', 'No description')
                
                # Get metrics if available
                metrics = cve.get('metrics', {})
                cvss_data = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else metrics.get('cvssMetricV2', [{}])[0] if 'cvssMetricV2' in metrics else {}
                
                base_score = cvss_data.get('cvssData', {}).get('baseScore', 'N/A') if cvss_data else 'N/A'
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'N/A') if cvss_data else 'N/A'
                
                # Create the document
                doc_content = f"CVE ID: {cve_id}\nSeverity: {severity}\nBase Score: {base_score}\nDescription: {description}"
                documents.append(Document(
                    page_content=doc_content,
                    metadata={
                        "source": "nvd",
                        "cve_id": cve_id,
                        "severity": severity,
                        "base_score": base_score,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                ))
            
            # Add to vector database
            if documents:
                db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
                db.add_documents(documents)
                db.persist()
            
            return vulnerabilities
        else:
            return {"error": f"API returned status code {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def setup_rag_chain():
    """Set up the RAG chain for vulnerability analysis"""
    # Load the vector store
    db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
    
    # Create a retriever
    retriever = db.as_retriever(
        search_type="similarity",
        search_kwargs={"k": 5},
    )
    
    # Contextualize question prompt
    contextualize_q_system_prompt = (
        "Given a chat history and the latest user question "
        "which might reference context in the chat history, "
        "formulate a standalone question which can be understood "
        "without the chat history. Do NOT answer the question, just "
        "reformulate it if needed and otherwise return it as is."
    )
    
    contextualize_q_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", contextualize_q_system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}"),
        ]
    )
    
    # Create a history-aware retriever
    history_aware_retriever = create_history_aware_retriever(
        llm, retriever, contextualize_q_prompt
    )
    
    # Answer question prompt
    qa_system_prompt = (
        "You are a cybersecurity expert specializing in vulnerability assessment and mitigation. "
        "Use the following pieces of retrieved context to analyze vulnerabilities and their applicability "
        "to the user's system. When asked about vulnerabilities:"
        "\n\n"
        "1. Identify if the vulnerability applies to the user's system configuration"
        "2. Provide detailed but concise mitigation steps specific to the user's OS"
        "3. Explain the severity and potential impact of the vulnerability"
        "4. Include specific commands or actions the user should take"
        "\n\n"
        "If you don't have enough information, ask for specific details about the system. "
        "If a vulnerability doesn't apply to the user's system, clearly state this fact."
        "\n\n"
        "{context}"
    )
    
    qa_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", qa_system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}"),
        ]
    )
    
    # Create a chain to combine documents for question answering
    question_answer_chain = create_stuff_documents_chain(llm, qa_prompt)
    
    # Create the full retrieval chain
    rag_chain = create_retrieval_chain(history_aware_retriever, question_answer_chain)
    
    return rag_chain

def generate_vulnerability_report(vulnerability, system_info, mitigation_steps):
    """Generate an HTML report for a vulnerability"""
    report_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Assessment Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
            .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            h2 { color: #2980b9; margin-top: 20px; }
            .severity-high { background-color: #e74c3c; color: white; padding: 5px 10px; border-radius: 3px; }
            .severity-medium { background-color: #f39c12; color: white; padding: 5px 10px; border-radius: 3px; }
            .severity-low { background-color: #3498db; color: white; padding: 5px 10px; border-radius: 3px; }
            .severity-na { background-color: #95a5a6; color: white; padding: 5px 10px; border-radius: 3px; }
            .section { margin-bottom: 20px; padding: 15px; background: #f9f9f9; border-radius: 5px; }
            code { background: #f4f6f8; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
            .mitigation { background: #eafaf1; padding: 15px; border-left: 5px solid #2ecc71; }
            .footer { margin-top: 30px; text-align: center; font-size: 12px; color: #7f8c8d; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Vulnerability Assessment Report</h1>
            
            <div class="section">
                <h2>Vulnerability Details</h2>
                <p><strong>CVE ID:</strong> {{cve_id}}</p>
                <p><strong>Severity:</strong> <span class="severity-{{severity_class}}">{{severity}}</span></p>
                <p><strong>Base Score:</strong> {{base_score}}</p>
                <p><strong>Published:</strong> {{published_date}}</p>
                <p><strong>Description:</strong> {{description}}</p>
            </div>
            
            <div class="section">
                <h2>System Information</h2>
                <p><strong>Operating System:</strong> {{os_name}} {{os_version}} ({{os_arch}})</p>
                <p><strong>Distribution:</strong> {{os_dist}}</p>
                <p><strong>Processor:</strong> {{processor}}</p>
                <p><strong>Assessment Date:</strong> {{assessment_date}}</p>
            </div>
            
            <div class="section mitigation">
                <h2>Mitigation Steps</h2>
                {{mitigation_steps}}
            </div>
            
            <div class="footer">
                <p>Generated by OS Vulnerability Assessment Tool on {{generated_date}}</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Extract vulnerability details
    cve = vulnerability.get('cve', {})
    cve_id = cve.get('id', 'Unknown')
    description = cve.get('descriptions', [{}])[0].get('value', 'No description available')
    
    # Extract metrics
    metrics = cve.get('metrics', {})
    cvss_data = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else metrics.get('cvssMetricV2', [{}])[0] if 'cvssMetricV2' in metrics else {}
    
    base_score = cvss_data.get('cvssData', {}).get('baseScore', 'N/A') if cvss_data else 'N/A'
    severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'N/A') if cvss_data else 'N/A'
    
    # Determine severity class for styling
    severity_class = "na"
    if severity == "HIGH" or severity == "CRITICAL":
        severity_class = "high"
    elif severity == "MEDIUM":
        severity_class = "medium"
    elif severity == "LOW":
        severity_class = "low"
    
    # Get published date
    published_date = cve.get('published', 'Unknown')
    
    # Format the mitigation steps from LLM
    formatted_mitigation = mitigation_steps.replace('\n', '<br>')
    
    # Replace template variables
    report = report_template.replace('{{cve_id}}', cve_id)
    report = report.replace('{{severity}}', severity)
    report = report.replace('{{severity_class}}', severity_class)
    report = report.replace('{{base_score}}', str(base_score))
    report = report.replace('{{published_date}}', published_date)
    report = report.replace('{{description}}', description)
    report = report.replace('{{os_name}}', system_info['os']['name'])
    report = report.replace('{{os_version}}', system_info['os']['version'])
    report = report.replace('{{os_arch}}', system_info['os']['architecture'])
    report = report.replace('{{os_dist}}', system_info['os']['distribution'])
    report = report.replace('{{processor}}', system_info['hardware']['processor'])
    report = report.replace('{{assessment_date}}', datetime.now().strftime("%Y-%m-%d"))
    report = report.replace('{{mitigation_steps}}', formatted_mitigation)
    report = report.replace('{{generated_date}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    return report

# Set up routes
@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_system():
    """Scan the system for vulnerabilities"""
    try:
        # Store system info in the database
        num_docs = store_system_info()
        
        # Fetch vulnerabilities
        vulnerabilities = fetch_vulnerabilities()
        
        return jsonify({
            "status": "success",
            "message": f"System scan complete. {num_docs} configuration documents stored.",
            "vulnerability_count": len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/vulnerabilities')
def list_vulnerabilities():
    """List all vulnerabilities in the database"""
    try:
        db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
        results = db.get(where={"source": "nvd"})
        
        vulnerabilities = []
        for i, doc in enumerate(results['documents']):
            metadata = results['metadatas'][i]
            vulnerabilities.append({
                "cve_id": metadata.get("cve_id", "Unknown"),
                "severity": metadata.get("severity", "Unknown"),
                "base_score": metadata.get("base_score", "N/A"),
                "description": doc.split("Description: ")[1] if "Description: " in doc else "No description available",
                "timestamp": metadata.get("timestamp", "Unknown")
            })
        
        return jsonify({"status": "success", "vulnerabilities": vulnerabilities})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/analyze', methods=['POST'])
def analyze_vulnerability():
    """Analyze a specific vulnerability and generate mitigation steps"""
    try:
        data = request.json
        cve_id = data.get('cve_id')
        
        if not cve_id:
            return jsonify({"status": "error", "message": "CVE ID is required"})
        
        # Set up the RAG chain
        rag_chain = setup_rag_chain()
        
        # Prepare the query
        query = f"Analyze the vulnerability {cve_id} for my system and provide specific mitigation steps."
        
        # Execute the query
        result = rag_chain.invoke({"input": query, "chat_history": []})
        
        # Get system info for the report
        system_info = collect_system_info()
        
        # Get vulnerability details
        db = Chroma(persist_directory=persistent_directory, embedding_function=embeddings)
        vuln_results = db.get(where={"cve_id": cve_id})
        
        if not vuln_results['documents']:
            return jsonify({"status": "error", "message": f"Vulnerability {cve_id} not found in database"})
        
        # Convert the document metadata to a vulnerability object
        vuln_metadata = vuln_results['metadatas'][0]
        vulnerability = {
            "cve": {
                "id": cve_id,
                "descriptions": [{"value": vuln_results['documents'][0].split("Description: ")[1] if "Description: " in vuln_results['documents'][0] else "No description"}],
                "published": vuln_metadata.get("timestamp", datetime.now().strftime("%Y-%m-%d"))
            },
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": vuln_metadata.get("base_score", "N/A"),
                        "baseSeverity": vuln_metadata.get("severity", "N/A")
                    }
                }]
            }
        }
        
        # Generate the HTML report
        report_html = generate_vulnerability_report(vulnerability, system_info, result['answer'])
        
        return jsonify({
            "status": "success",
            "analysis": result['answer'],
            "report_html": report_html
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/chat', methods=['POST'])
def chat():
    """Handle chat interactions with the vulnerability assessment system"""
    try:
        data = request.json
        query = data.get('query')
        chat_history = data.get('chat_history', [])
        
        # Convert the chat history to the format expected by LangChain
        formatted_history = []
        for msg in chat_history:
            if msg['role'] == 'user':
                formatted_history.append(HumanMessage(content=msg['content']))
            else:
                formatted_history.append(AIMessage(content=msg['content']))
        
        # Set up the RAG chain
        rag_chain = setup_rag_chain()
        
        # Execute the query
        result = rag_chain.invoke({"input": query, "chat_history": formatted_history})
        
        return jsonify({
            "status": "success",
            "response": result['answer']
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# Create templates directory and flask templates
def create_templates():
    # Create the templates directory if it doesn't exist
    templates_dir = os.path.join(current_dir, "templates")
    os.makedirs(templates_dir, exist_ok=True)
    
    # Create the index.html template
    index_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>OS Vulnerability Assessment Tool</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; background-color: #f4f6f8; color: #333; }
            header { background-color: #2c3e50; color: white; padding: 1rem; text-align: center; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .card { background: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            button { background-color: #3498db; color: white; border: none; padding: 10px 15px; border-radius: 5px; cursor: pointer; }
            button:hover { background-color: #2980b9; }
            .danger { background-color: #e74c3c; }
            .danger:hover { background-color: #c0392b; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f4f6f8; }
            .severity-high { background-color: #e74c3c; color: white; padding: 3px 8px; border-radius: 3px; }
            .severity-medium { background-color: #f39c12; color: white; padding: 3px 8px; border-radius: 3px; }
            .severity-low { background-color: #3498db; color: white; padding: 3px 8px; border-radius: 3px; }
            .severity-na { background-color: #95a5a6; color: white; padding: 3px 8px; border-radius: 3px; }
            .hidden { display: none; }
            .chat-container { border: 1px solid #ddd; border-radius: 5px; height: 300px; display: flex; flex-direction: column; }
            .chat-messages { flex-grow: 1; overflow-y: auto; padding: 10px; background-color: #f9f9f9; }
            .chat-input { display: flex; padding: 10px; background-color: #fff; border-top: 1px solid #ddd; }
            .chat-input input { flex-grow: 1; padding: 8px; border: 1px solid #ddd; border-radius: 3px; margin-right: 10px; }
            .user-message { background-color: #e1f5fe; padding: 8px 12px; border-radius: 15px; margin: 5px 0; max-width: 80%; align-self: flex-end; }
            .ai-message { background-color: #f1f1f1; padding: 8px 12px; border-radius: 15px; margin: 5px 0; max-width: 80%; align-self: flex-start; }
            #reportModal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }
            .modal-content { background-color: #fefefe; margin: 5% auto; padding: 20px; border: 1px solid #888; width: 80%; max-height: 80%; overflow: auto; }
            .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
            .tabs { display: flex; border-bottom: 1px solid #ddd; margin-bottom: 20px; }
            .tab { padding: 10px 15px; cursor: pointer; }
            .tab.active { border-bottom: 2px solid #3498db; color: #3498db; }
            .tab-content { display: none; }
            .tab-content.active { display: block; }
        </style>
    </head>
    <body>
        <header>
            <h1>OS Vulnerability Assessment Tool</h1>
        </header>
        
        <div class="container">
            <div class="tabs">
                <div class="tab active" data-tab="dashboard">Dashboard</div>
                <div class="tab" data-tab="vulnerabilities">Vulnerabilities</div>
                <div class="tab" data-tab="chat">Chat Assistant</div>
            </div>
            
            <div id="dashboard" class="tab-content active">
                <div class="card">
                    <h2>System Information</h2>
                    <div id="systemInfo">
                        <p>Click "Scan System" to retrieve your system information and check for vulnerabilities.</p>
                    </div>
                    <button id="scanButton">Scan System</button>
                </div>
                
                <div class="card">
                    <h2>Vulnerability Summary</h2>
                    <div id="vulnSummary">
                        <p>No vulnerability data available. Please scan your system first.</p>
                    </div>
                </div>
            </div>
            
            <div id="vulnerabilities" class="tab-content">
                <div class="card">
                    <h2>Detected Vulnerabilities</h2>
                    <div id="vulnList">
                        <p>No vulnerabilities detected yet. Please scan your system first.</p>
                    </div>
                </div>
            </div>
            
            <div id="chat" class="tab-content">
                <div class="card">
                    <h2>Vulnerability Assessment Assistant</h2>
                    <p>Ask questions about vulnerabilities, mitigation steps, or your system configuration.</p>
                    <div class="chat-container">
                        <div class="chat-messages" id="chatMessages">
                            <div class="ai-message">Hello! I'm your vulnerability assessment assistant. How can I help you today?</div>
                        </div>
                        <div class="chat-input">
                            <input type="text" id="chatInput" placeholder="Type your message here...">
                            <button id="sendButton">Send</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="reportModal" class="modal">
            <div class="modal-content">
                <span class="close">&times;</span>
                <div id="reportContent"></div>
            </div>
        </div>
        
        <script>
            // Store chat history
            let chatHistory = [];
            
            // DOM elements
            const scanButton = document.getElementById('scanButton');
            const systemInfo = document.getElementById('systemInfo');
            const vulnSummary = document.getElementById('vulnSummary');
            const vulnList = document.getElementById('vulnList');
            const chatMessages = document.getElementById('chatMessages');
            const chatInput = document.getElementById('chatInput');
            const sendButton = document.getElementById('sendButton');
            const reportModal = document.getElementById('reportModal');
            const reportContent = document.getElementById('reportContent');
            const closeModal = document.querySelector('.close');
            const tabs = document.querySelectorAll('.tab');
            const tabContents = document.querySelectorAll('.tab-content');
            
            // Tab switching
            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    // Remove active class from all tabs and contents
                    tabs.forEach(t => t.classList.remove('active'));
                    tabContents.forEach(c => c.classList.remove('active'));
                    
                    // Add active class to clicked tab and corresponding content
                    tab.classList.add('active');
                    document.getElementById(tab.dataset.tab).classList.add('active');
                });
            });
            
            // Scan system
            scanButton.addEventListener('click', async () => {
                scanButton.textContent = 'Scanning...';
                scanButton.disabled = true;
                
                try {
                    const response = await fetch('/scan', {
                        method: 'POST'
                    });
                    
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        // Update UI with success message
                        alert('System scan complete. Loading results...');
                        
                        // Fetch system info
                        loadSystemInfo();
                        
                        // Fetch vulnerabilities
                        loadVulnerabilities();
                    } else {
                        alert(`Error: ${data.message}`);
                    }
                } catch (error) {
                    alert(`Error scanning system: ${error.message}`);
                } finally {
                    scanButton.textContent = 'Scan System';
                    scanButton.disabled = false;
                }
            });
            
            // Load system information
            async function loadSystemInfo() {
                try {
                    // Get the first document with system info
                    const response = await fetch('/chat', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            query: 'Summarize my system configuration in a concise format.',
                            chat_history: []
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        systemInfo.innerHTML = `<p>${data.response.replace(/\n/g, '<br>')}</p>`;
                    }
                } catch (error) {
                    systemInfo.innerHTML = `<p>Error loading system info: ${error.message}</p>`;
                }
            }
            
            // Load vulnerabilities
            async function loadVulnerabilities() {
                try {
                    const response = await fetch('/vulnerabilities');
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        // Update vulnerability summary
                        const highCount = data.vulnerabilities.filter(v => v.severity === 'HIGH' || v.severity === 'CRITICAL').length;
                        const mediumCount = data.vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
                        const lowCount = data.vulnerabilities.filter(v => v.severity === 'LOW').length;
                        
                        vulnSummary.innerHTML = `
                            <p>Found ${data.vulnerabilities.length} vulnerabilities that may affect your system:</p>
                            <ul>
                                <li><span class="severity-high">High/Critical</span>: ${highCount}</li>
                                <li><span class="severity-medium">Medium</span>: ${mediumCount}</li>
                                <li><span class="severity-low">Low</span>: ${lowCount}</li>
                            </ul>
                        `;
                        
                        // Update vulnerability list
                        if (data.vulnerabilities.length > 0) {
                            let tableHtml = `
                                <table>
                                    <thead>
                                        <tr>
                                            <th>CVE ID</th>
                                            <th>Severity</th>
                                            <th>Base Score</th>
                                            <th>Description</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            `;
                            
                            data.vulnerabilities.forEach(vuln => {
                                let severityClass = 'severity-na';
                                if (vuln.severity === 'HIGH' || vuln.severity === 'CRITICAL') {
                                    severityClass = 'severity-high';
                                } else if (vuln.severity === 'MEDIUM') {
                                    severityClass = 'severity-medium';
                                } else if (vuln.severity === 'LOW') {
                                    severityClass = 'severity-low';
                                }
                                
                                let description = vuln.description;
                                if (description.length > 100) {
                                    description = description.substring(0, 100) + '...';
                                }
                                
                                tableHtml += `
                                    <tr>
                                        <td>${vuln.cve_id}</td>
                                        <td><span class="${severityClass}">${vuln.severity}</span></td>
                                        <td>${vuln.base_score}</td>
                                        <td>${description}</td>
                                        <td><button onclick="analyzeVulnerability('${vuln.cve_id}')">Analyze</button></td>
                                    </tr>
                                `;
                            });
                            
                            tableHtml += `
                                    </tbody>
                                </table>
                            `;
                            
                            vulnList.innerHTML = tableHtml;
                        } else {
                            vulnList.innerHTML = '<p>No vulnerabilities found that may affect your system.</p>';
                        }
                    } else {
                        vulnList.innerHTML = `<p>Error: ${data.message}</p>`;
                    }
                } catch (error) {
                    vulnList.innerHTML = `<p>Error loading vulnerabilities: ${error.message}</p>`;
                }
            }
            
            // Analyze a specific vulnerability
            window.analyzeVulnerability = async function(cveId) {
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            cve_id: cveId
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        // Display the HTML report in the modal
                        reportContent.innerHTML = data.report_html;
                        reportModal.style.display = 'block';
                    } else {
                        alert(`Error: ${data.message}`);
                    }
                } catch (error) {
                    alert(`Error analyzing vulnerability: ${error.message}`);
                }
            };
            
            // Close the modal
            closeModal.addEventListener('click', () => {
                reportModal.style.display = 'none';
            });
            
            // Close modal when clicking outside of it
            window.addEventListener('click', (event) => {
                if (event.target === reportModal) {
                    reportModal.style.display = 'none';
                }
            });
            
            // Chat functionality
            sendButton.addEventListener('click', sendMessage);
            chatInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    sendMessage();
                }
            });
            
            async function sendMessage() {
                const message = chatInput.value.trim();
                
                if (message === '') {
                    return;
                }
                
                // Add user message to chat
                chatMessages.innerHTML += `<div class="user-message">${message}</div>`;
                
                // Clear input
                chatInput.value = '';
                
                // Scroll to bottom
                chatMessages.scrollTop = chatMessages.scrollHeight;
                
                // Add to chat history
                chatHistory.push({ role: 'user', content: message });
                
                try {
                    const response = await fetch('/chat', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            query: message,
                            chat_history: chatHistory
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        // Add AI response to chat
                        chatMessages.innerHTML += `<div class="ai-message">${data.response.replace(/\n/g, '<br>')}</div>`;
                        
                        // Add to chat history
                        chatHistory.push({ role: 'assistant', content: data.response });
                    } else {
                        chatMessages.innerHTML += `<div class="ai-message">Error: ${data.message}</div>`;
                    }
                } catch (error) {
                    chatMessages.innerHTML += `<div class="ai-message">Error: ${error.message}</div>`;
                }
                
                // Scroll to bottom
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }
        </script>
    </body>
    </html>
    """
    
    with open(os.path.join(templates_dir, "index.html"), "w") as f:
        f.write(index_html)

# Main function to start the Flask app
if __name__ == "__main__":
    # Create templates before starting
    create_templates()
    
    # Create the database directory if it doesn't exist
    os.makedirs(os.path.dirname(persistent_directory), exist_ok=True)
    
    # Start the Flask app
    app.run(debug=True)