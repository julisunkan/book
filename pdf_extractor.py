#!/usr/bin/env python3
"""
PDF to Tutorial Extractor
Extracts text, images, and tables from PDF book and converts to organized modules
"""

import pymupdf as fitz  # PyMuPDF
import os
import re
import sqlite3
from PIL import Image
import io
import camelot
import tabula

class PDFExtractor:
    def __init__(self, pdf_path="book.pdf", output_dir="modules", images_dir="static/images"):
        self.pdf_path = pdf_path
        self.output_dir = output_dir
        self.images_dir = images_dir
        self.doc = None
        self.chapters = []
        
        # Configurable chapter detection keywords - more precise patterns
        self.chapter_keywords = [r"^Chapter\s+\d+", r"^Module\s+\d+", r"^Lesson\s+\d+"]
        self.exclude_patterns = [r'[.]{3,}', r'\d+\s*$', r'Contents', r'Index', r'Bibliography']
        
        # Ensure directories exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.images_dir, exist_ok=True)

    def open_pdf(self):
        """Open the PDF document"""
        try:
            self.doc = fitz.open(self.pdf_path)
            if self.doc is None:
                print(f"Failed to open PDF: {self.pdf_path}")
                return False
            print(f"Successfully opened PDF: {self.pdf_path}")
            print(f"Total pages: {self.doc.page_count}")
        except Exception as e:
            print(f"Error opening PDF: {e}")
            return False
        return True

    def clean_text(self, text):
        """Clean extracted text by removing headers, footers, and page numbers"""
        lines = text.split('\n')
        cleaned_lines = []
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Skip common header/footer patterns
            if re.match(r'^\d+$', line):  # Page numbers
                continue
            if len(line) < 3:  # Very short lines
                continue
            if re.match(r'^(Chapter|Part|Section)\s+\d+\s*$', line):  # Isolated chapter headers
                continue
                
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    def detect_chapters(self):
        """Detect chapter boundaries in the PDF"""
        chapters = []
        current_chapter = None
        
        if self.doc is None:
            return chapters
        
        for page_num in range(self.doc.page_count):
            if self.doc is None:
                return []
            page = self.doc.load_page(page_num)
            text = page.get_text()
            
            # Look for chapter markers with improved filtering
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                
                # Skip if line is too short or too long
                if len(line) < 8 or len(line) > 150:
                    continue
                    
                # Check if it matches chapter pattern
                chapter_match = False
                for keyword_pattern in self.chapter_keywords:
                    if re.search(keyword_pattern, line, re.IGNORECASE):
                        chapter_match = True
                        break
                        
                if not chapter_match:
                    continue
                    
                # Exclude TOC entries and other non-chapter lines
                exclude_line = False
                for exclude_pattern in self.exclude_patterns:
                    if re.search(exclude_pattern, line):
                        exclude_line = True
                        break
                        
                if exclude_line:
                    continue
                    
                # Skip if we've already seen this chapter title
                chapter_title = re.sub(r'^[\s■▪•\-]+', '', line)  # Clean title
                if any(ch['title'] == chapter_title for ch in chapters):
                    continue
                    
                # This looks like a real chapter
                if current_chapter:
                    current_chapter['end_page'] = page_num - 1
                    chapters.append(current_chapter)
                
                current_chapter = {
                    'title': chapter_title,
                    'start_page': page_num,
                    'end_page': None,
                    'content': [],
                    'images': []
                }
                break  # Only one chapter per page
        
        # Close the last chapter
        if current_chapter:
            current_chapter['end_page'] = self.doc.page_count - 1
            chapters.append(current_chapter)
        
        # If no chapters detected, create a single chapter
        if not chapters:
            chapters.append({
                'title': 'Complete Book',
                'start_page': 0,
                'end_page': self.doc.page_count - 1,
                'content': [],
                'images': []
            })
        
        self.chapters = chapters
        print(f"Detected {len(chapters)} chapters")
        return chapters

    def extract_images_from_page(self, page, page_num, chapter_num):
        """Extract images from a page"""
        image_list = page.get_images()
        extracted_images = []
        
        for img_index, img in enumerate(image_list):
            try:
                # Get image data
                xref = img[0]
                pix = fitz.Pixmap(self.doc, xref)
                
                # Skip if not RGB
                if pix.n - pix.alpha < 4:  # GRAY or RGB
                    # Convert to PNG
                    img_data = pix.tobytes("png")
                    
                    # Save image
                    img_filename = f"chapter_{chapter_num}_page_{page_num}_img_{img_index}.png"
                    img_path = os.path.join(self.images_dir, img_filename)
                    
                    with open(img_path, "wb") as img_file:
                        img_file.write(img_data)
                    
                    extracted_images.append(img_filename)
                    print(f"Extracted image: {img_filename}")
                
                pix = None  # Release memory
                
            except Exception as e:
                print(f"Error extracting image {img_index} from page {page_num}: {e}")
        
        return extracted_images

    def extract_tables_from_page(self, page_num):
        """Extract tables from a page using Camelot and Tabula"""
        tables = []
        
        try:
            # Try Camelot first (better for vector PDFs)
            camelot_tables = camelot.read_pdf(self.pdf_path, pages=str(page_num + 1))
            
            for table in camelot_tables:
                if table.df is not None and not table.df.empty:
                    # Convert to markdown table
                    markdown_table = self.dataframe_to_markdown(table.df)
                    if markdown_table:
                        tables.append(markdown_table)
        except Exception as e:
            print(f"Camelot extraction failed for page {page_num}: {e}")
            
        # If Camelot didn't find tables, try Tabula (better for image-based PDFs)
        if not tables:
            try:
                tabula_tables = tabula.read_pdf(self.pdf_path, pages=page_num + 1, multiple_tables=True)
                
                for df in tabula_tables:
                    if df is not None and not df.empty:
                        markdown_table = self.dataframe_to_markdown(df)
                        if markdown_table:
                            tables.append(markdown_table)
            except Exception as e:
                print(f"Tabula extraction failed for page {page_num}: {e}")
        
        return tables
    
    def dataframe_to_markdown(self, df):
        """Convert a pandas DataFrame to markdown table"""
        try:
            # Clean the dataframe
            df = df.fillna('')  # Fill NaN with empty string
            
            # Convert to markdown
            markdown_lines = []
            
            # Header row
            headers = [str(col).strip() for col in df.columns]
            if headers and any(header for header in headers):  # Check if headers are meaningful
                header_row = "| " + " | ".join(headers) + " |"
                separator = "|" + "---|" * len(headers)
                markdown_lines.append(header_row)
                markdown_lines.append(separator)
            
            # Data rows
            for _, row in df.iterrows():
                cells = [str(cell).strip() for cell in row.values]
                if any(cell for cell in cells):  # Skip empty rows
                    row_line = "| " + " | ".join(cells) + " |"
                    markdown_lines.append(row_line)
            
            if len(markdown_lines) > 2:  # At least header, separator, and one data row
                return "\n".join(markdown_lines)
                
        except Exception as e:
            print(f"Error converting dataframe to markdown: {e}")
        
        return None


    def extract_chapter_content(self, chapter, chapter_num):
        """Extract content for a single chapter"""
        content = []
        all_images = []
        
        for page_num in range(chapter['start_page'], chapter['end_page'] + 1):
            page = self.doc.load_page(page_num)
            
            # Extract text
            text = page.get_text()
            cleaned_text = self.clean_text(text)
            
            if cleaned_text.strip():
                # Extract tables
                tables = self.extract_tables_from_page(page_num)
                
                # Insert tables into text or add them separately
                if tables:
                    for table in tables:
                        cleaned_text += "\n\n" + table + "\n\n"
                
                content.append(cleaned_text)
            
            # Extract images
            page_images = self.extract_images_from_page(page, page_num, chapter_num)
            all_images.extend(page_images)
        
        chapter['content'] = content
        chapter['images'] = all_images
        return chapter

    def create_markdown_file(self, chapter, chapter_num):
        """Create markdown file for a chapter"""
        filename = f"module{chapter_num}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Write title
            f.write(f"# {chapter['title']}\n\n")
            
            # Write content
            for content_block in chapter['content']:
                f.write(content_block)
                f.write("\n\n")
            
            # Add images
            if chapter['images']:
                f.write("## Images and Figures\n\n")
                for img in chapter['images']:
                    f.write(f"![Figure](../static/images/{img})\n\n")
        
        print(f"Created markdown file: {filepath}")
        return filename

    def process_pdf(self):
        """Main processing function"""
        if not self.open_pdf():
            return False
        
        print("Detecting chapters...")
        chapters = self.detect_chapters()
        
        print("Extracting content...")
        markdown_files = []
        
        for i, chapter in enumerate(chapters, 1):
            print(f"Processing Chapter {i}: {chapter['title']}")
            
            # Extract content
            self.extract_chapter_content(chapter, i)
            
            # Create markdown file
            md_file = self.create_markdown_file(chapter, i)
            markdown_files.append({
                'file': md_file,
                'title': chapter['title'],
                'module_id': i
            })
        
        print(f"Processing complete! Created {len(markdown_files)} modules.")
        return markdown_files

def main():
    extractor = PDFExtractor()
    result = extractor.process_pdf()
    
    if result:
        print("PDF extraction successful!")
        for module in result:
            print(f"- {module['file']}: {module['title']}")
    else:
        print("PDF extraction failed!")

if __name__ == "__main__":
    main()