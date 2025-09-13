#!/usr/bin/env python3
"""
PDF to Tutorial Extractor
Extracts text, images, and tables from PDF book and converts to organized modules
"""

import fitz  # PyMuPDF
import os
import re
import sqlite3
from PIL import Image
import io

class PDFExtractor:
    def __init__(self, pdf_path="book.pdf", output_dir="modules", images_dir="static/images"):
        self.pdf_path = pdf_path
        self.output_dir = output_dir
        self.images_dir = images_dir
        self.doc = None
        self.chapters = []
        
        # Configurable chapter detection keywords
        self.chapter_keywords = [r"Chapter\s+\d+", r"Module\s+\d+", r"Lesson\s+\d+", r"Part\s+[IVX]+"]
        
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
                return all_images
            page = self.doc.load_page(page_num)
            text = page.get_text()
            
            # Look for chapter markers
            for keyword_pattern in self.chapter_keywords:
                matches = re.finditer(keyword_pattern, text, re.IGNORECASE)
                
                for match in matches:
                    # Get the full line containing the chapter
                    lines = text.split('\n')
                    for line in lines:
                        if match.group() in line:
                            chapter_title = line.strip()
                            
                            # Close previous chapter
                            if current_chapter:
                                current_chapter['end_page'] = page_num - 1
                                chapters.append(current_chapter)
                            
                            # Start new chapter
                            current_chapter = {
                                'title': chapter_title,
                                'start_page': page_num,
                                'end_page': None,
                                'content': [],
                                'images': []
                            }
                            break
        
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

    def extract_tables_as_text(self, page_text):
        """Simple table detection and conversion to markdown"""
        lines = page_text.split('\n')
        tables = []
        
        # Look for patterns that might be tables
        potential_table_lines = []
        for line in lines:
            # Check if line has multiple columns separated by spaces
            if len(line.split()) > 3 and '\t' not in line:
                words = line.split()
                # Check if words are reasonably spaced
                if len(' '.join(words)) < len(line) * 0.8:  # Has significant spacing
                    potential_table_lines.append(line)
            elif potential_table_lines:
                # End of potential table
                if len(potential_table_lines) > 2:  # At least 3 rows
                    table_text = self.convert_to_markdown_table(potential_table_lines)
                    if table_text:
                        tables.append(table_text)
                potential_table_lines = []
        
        # Check last set of lines
        if len(potential_table_lines) > 2:
            table_text = self.convert_to_markdown_table(potential_table_lines)
            if table_text:
                tables.append(table_text)
        
        return tables

    def convert_to_markdown_table(self, lines):
        """Convert detected table lines to markdown table format"""
        if len(lines) < 2:
            return None
        
        # Try to align columns
        max_cols = 0
        for line in lines:
            cols = len(line.split())
            if cols > max_cols:
                max_cols = cols
        
        if max_cols < 2:
            return None
        
        markdown_table = []
        header_added = False
        
        for line in lines:
            words = line.split()
            if len(words) >= 2:
                # Pad with empty cells if needed
                while len(words) < max_cols:
                    words.append("")
                
                row = "| " + " | ".join(words) + " |"
                markdown_table.append(row)
                
                # Add header separator after first row
                if not header_added:
                    separator = "|" + "---|" * max_cols
                    markdown_table.append(separator)
                    header_added = True
        
        return "\n".join(markdown_table)

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
                tables = self.extract_tables_as_text(text)
                
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