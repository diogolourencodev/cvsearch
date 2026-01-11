from flask import Flask, render_template, jsonify, request
from services import search_cve, search_vuln
from utils import is_valid_cve
from flasgger import Swagger

app = Flask(__name__)
swagger = Swagger(app)

@app.route('/')
def home_page():
    return render_template('index.html')

@app.route('/api')
def api_status():
    """
    API Status
    ---
    responses:
        200:
            description: Tests the API base
    """
    return jsonify({"status":"If u find this: a big kiss  >:3"})

@app.route('/api/search/<searchTerm>')
def search(searchTerm):
    """
    Search for CVE or terms/vulnerabilities
    ---
    parameters:
      - name: searchTerm
        in: path
        type: string
        required: true
        description: CVE/Search term
    responses:
      200:
        description: CVE/Term response
    """
    if is_valid_cve(term=searchTerm):
        return search_cve(searchTerm)
    else:
        return search_vuln(searchTerm)
