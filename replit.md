# Overview

This is a Flask-based educational platform that converts PDF books into interactive tutorial modules. The application extracts content from PDF files (specifically focused on ethical hacking/Python programming books) and presents them as organized, trackable learning modules. Students can progress through chapters sequentially, with their completion status being tracked in a SQLite database.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 templating with Flask
- **UI Framework**: Bootstrap 5 for responsive design
- **Styling**: Custom CSS with Font Awesome icons for enhanced UX
- **JavaScript**: Vanilla JavaScript for interactive features like code copying, module card animations, and progress tracking
- **Responsive Design**: Mobile-first approach using Bootstrap's grid system

## Backend Architecture
- **Web Framework**: Flask (Python) following MVC pattern
- **Application Structure**: Single-file Flask application (`app.py`) with modular PDF extraction functionality
- **Database Layer**: SQLite with custom connection management
- **Content Processing**: Markdown rendering with extensions for code highlighting, tables, and table of contents
- **PDF Processing**: PyMuPDF (fitz) for text extraction, with support for images and tables via PIL, camelot, and tabula

## Data Storage Solutions
- **Primary Database**: SQLite with two main tables:
  - `progress`: Tracks user completion status per module
  - `modules`: Stores module metadata (title, filename, description)
- **File Storage**: 
  - Markdown files stored in `modules/` directory
  - Static assets (images, CSS, JS) in `static/` directory
  - PDF source files in project root

## Content Management
- **PDF Extraction**: Automated extraction of chapters/modules from PDF books using configurable chapter detection patterns
- **Text Processing**: Cleaning algorithms to remove headers, footers, and page numbers
- **Content Organization**: Sequential module numbering with automatic title extraction
- **Markdown Conversion**: Rich text formatting with syntax highlighting for code blocks

## Progress Tracking System
- **User Sessions**: Simple session management with configurable secret keys
- **Progress States**: Three-tier system (not_started, in_progress, completed)
- **Completion Metrics**: Percentage-based progress calculation across all modules
- **Navigation**: Previous/next module navigation with progress-aware routing

# External Dependencies

## Python Libraries
- **Flask**: Web framework and templating
- **PyMuPDF (fitz)**: PDF text and image extraction
- **Pillow (PIL)**: Image processing and manipulation
- **camelot-py**: Table extraction from PDFs
- **tabula-py**: Alternative table extraction tool
- **python-markdown**: Markdown to HTML conversion with extensions (codehilite, tables, toc)

## Frontend Libraries
- **Bootstrap 5**: CSS framework delivered via CDN
- **Prism.js**: Syntax highlighting for code blocks
- **Font Awesome**: Icon library for UI elements

## Development Tools
- **SQLite3**: Built-in Python database interface
- **Jinja2**: Template engine (included with Flask)

## Infrastructure Requirements
- **File System**: Local storage for modules, static files, and database
- **Environment Variables**: SESSION_SECRET for security configuration
- **Directory Structure**: Predefined folders for modules, static assets, and templates

The application is designed to be self-contained with minimal external service dependencies, making it suitable for local development and simple deployment scenarios.