# Overview

This is a Flask-based inventory management system designed for barcode scanning and tracking of physical inventory items (bobines/coils). The application allows users to scan 28-character barcodes, extract article codes and lot numbers, track physical weights, add remarks, and export data to Excel. It includes authentication, manual entry capabilities, and data verification against reference stock files.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Web Framework
- **Flask** with Flask-Login for session management and user authentication
- **Jinja2 templating** for server-side rendering with Bootstrap 5 for responsive UI
- Session-based authentication with username/password and PIN-based operations

## Database Layer
- **SQLiteCloud** as primary database solution for cloud-based data storage
- **Local SQLite fallback** when cloud connection is unavailable
- Single `inventory` table schema with fields: lot (primary key), code_article, poids_physique, remarque, date_scan
- Environment variable-based database URL configuration for security

## Authentication & Security
- **Flask-Login** for user session management
- **Environment variable-based credentials** (USERNAME, PASSWORD, PIN_CODE)
- Demo credentials hardcoded as fallback for development (security warning implemented)
- PIN-protected sensitive operations (export, reset)

## Data Processing
- **Pandas** for Excel file handling and data manipulation
- **28-character barcode parsing** logic (positions 8-18 for article code, 18-28 for lot)
- **Reference stock validation** against MB52.xlsx file
- Real-time verification of scanned lots against reference data

## File Operations
- **Excel export functionality** using BytesIO for in-memory file generation
- **Reference file loading** (MB52.xlsx) for stock validation
- Automatic lot formatting with zero-padding

## Frontend Architecture
- **Bootstrap 5** component library for responsive design
- **Font Awesome** icons for enhanced UI
- **Modal-based interactions** for exports and confirmations
- **Custom CSS** for scanner input styling and verification status indicators

## Core Features
- **Barcode scanning interface** with real-time parsing
- **Manual entry form** for non-scannable items
- **Dashboard with statistics** (scanned items, targets, progress)
- **Search and filtering** capabilities
- **Data export to Excel** with PIN protection
- **Inventory reset functionality** with confirmation safeguards

# External Dependencies

## Database Services
- **SQLiteCloud** - Cloud-hosted SQLite database service for primary data storage
- **SQLite3** - Local fallback database for offline operation

## Python Libraries
- **Flask** - Web framework and routing
- **Flask-Login** - User authentication and session management
- **Pandas** - Data manipulation and Excel file processing
- **SQLiteCloud** - Cloud database connector

## Frontend Libraries
- **Bootstrap 5** - CSS framework via CDN
- **Font Awesome 6** - Icon library via CDN

## File Dependencies
- **MB52.xlsx** - Reference stock file for lot validation (expected in root directory)

## Environment Variables
- **DATABASE_URL** - SQLiteCloud connection string
- **SESSION_SECRET** - Flask session encryption key
- **INVENTORY_USERNAME** - Application login username
- **INVENTORY_PASSWORD** - Application login password  
- **INVENTORY_PIN** - PIN code for sensitive operations