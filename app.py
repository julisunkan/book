#!/usr/bin/env python3
"""
Flask Tutorial App - PDF to Interactive Tutorial Platform
"""

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import sqlite3
import os
import markdown
from markdown.extensions import codehilite, tables, toc
import json
from pdf_extractor import PDFExtractor

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')

# Configuration
DATABASE = 'database.db'
MODULES_DIR = 'modules'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    
    # Create progress tracking table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 1,
            module_id INTEGER,
            status TEXT DEFAULT 'not_started',
            completed_on DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, module_id)
        )
    ''')
    
    # Create modules table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS modules (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            filename TEXT NOT NULL,
            order_num INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_modules():
    """Get all available modules"""
    modules = []
    
    # Check if modules directory exists and has files
    if os.path.exists(MODULES_DIR):
        module_files = [f for f in os.listdir(MODULES_DIR) if f.endswith('.md')]
        module_files.sort()  # Sort alphabetically
        
        for i, filename in enumerate(module_files, 1):
            filepath = os.path.join(MODULES_DIR, filename)
            
            # Extract title from markdown file
            title = filename.replace('.md', '').replace('_', ' ').title()
            
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Try to extract title from first heading
                    lines = content.split('\n')
                    for line in lines:
                        if line.startswith('# '):
                            title = line[2:].strip()
                            break
            except Exception as e:
                print(f"Error reading {filename}: {e}")
            
            modules.append({
                'id': i,
                'title': title,
                'filename': filename,
                'order_num': i
            })
    
    return modules

def get_module_progress(user_id=1):
    """Get progress for all modules"""
    conn = get_db_connection()
    
    # Get all modules
    modules = get_modules()
    
    # Get progress for each module
    progress_dict = {}
    progress_rows = conn.execute(
        'SELECT module_id, status, completed_on FROM progress WHERE user_id = ?',
        (user_id,)
    ).fetchall()
    
    for row in progress_rows:
        progress_dict[row['module_id']] = {
            'status': row['status'],
            'completed_on': row['completed_on']
        }
    
    # Combine modules with progress
    for module in modules:
        module_id = module['id']
        if module_id in progress_dict:
            module['status'] = progress_dict[module_id]['status']
            module['completed_on'] = progress_dict[module_id]['completed_on']
        else:
            module['status'] = 'not_started'
            module['completed_on'] = None
    
    conn.close()
    return modules

def update_progress(user_id, module_id, status):
    """Update progress for a module"""
    conn = get_db_connection()
    
    completed_on = None
    if status == 'completed':
        completed_on = 'CURRENT_TIMESTAMP'
        conn.execute('''
            INSERT OR REPLACE INTO progress 
            (user_id, module_id, status, completed_on, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (user_id, module_id, status))
    else:
        conn.execute('''
            INSERT OR REPLACE INTO progress 
            (user_id, module_id, status, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, module_id, status))
    
    conn.commit()
    conn.close()

@app.route('/')
def home():
    """Homepage with module list and progress"""
    modules = get_module_progress()
    
    # Calculate overall progress
    total_modules = len(modules)
    completed_modules = sum(1 for m in modules if m['status'] == 'completed')
    progress_percentage = (completed_modules / total_modules * 100) if total_modules > 0 else 0
    
    return render_template('home.html', 
                         modules=modules, 
                         total_modules=total_modules,
                         completed_modules=completed_modules,
                         progress_percentage=progress_percentage)

@app.route('/module/<int:module_id>')
def module_page(module_id):
    """Individual module page"""
    modules = get_modules()
    
    # Find the requested module
    current_module = None
    for module in modules:
        if module['id'] == module_id:
            current_module = module
            break
    
    if not current_module:
        flash('Module not found', 'error')
        return redirect(url_for('home'))
    
    # Read markdown content
    filepath = os.path.join(MODULES_DIR, current_module['filename'])
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            markdown_content = f.read()
    except Exception as e:
        flash(f'Error loading module content: {e}', 'error')
        return redirect(url_for('home'))
    
    # Convert markdown to HTML with extensions
    md = markdown.Markdown(extensions=[
        'codehilite',
        'tables', 
        'toc',
        'fenced_code'
    ])
    html_content = md.convert(markdown_content)
    
    # Get current progress
    progress = get_module_progress()
    current_progress = next((p for p in progress if p['id'] == module_id), None)
    
    # Calculate navigation
    prev_module = None
    next_module = None
    
    for i, module in enumerate(modules):
        if module['id'] == module_id:
            if i > 0:
                prev_module = modules[i-1]
            if i < len(modules) - 1:
                next_module = modules[i+1]
            break
    
    # Mark as in progress if not started
    if current_progress and current_progress['status'] == 'not_started':
        update_progress(1, module_id, 'in_progress')
        current_progress['status'] = 'in_progress'
    
    return render_template('module.html',
                         module=current_module,
                         content=html_content,
                         progress=current_progress,
                         prev_module=prev_module,
                         next_module=next_module)

@app.route('/mark_complete/<int:module_id>', methods=['POST'])
def mark_complete(module_id):
    """Mark a module as completed"""
    update_progress(1, module_id, 'completed')
    flash('Module marked as completed!', 'success')
    return redirect(url_for('module_page', module_id=module_id))

@app.route('/extract_pdf', methods=['POST'])
def extract_pdf():
    """Extract content from PDF"""
    try:
        extractor = PDFExtractor()
        result = extractor.process_pdf()
        
        if result:
            flash(f'Successfully extracted {len(result)} modules from PDF!', 'success')
        else:
            flash('Failed to extract content from PDF', 'error')
            
    except Exception as e:
        flash(f'Error extracting PDF: {str(e)}', 'error')
    
    return redirect(url_for('home'))

@app.route('/progress_api')
def progress_api():
    """API endpoint for progress data"""
    modules = get_module_progress()
    return jsonify(modules)

def initialize_app():
    """Initialize the application"""
    init_database()
    
    # Check if PDF exists and modules don't exist, offer to extract
    if os.path.exists('book.pdf') and not os.path.exists(MODULES_DIR):
        os.makedirs(MODULES_DIR, exist_ok=True)

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)