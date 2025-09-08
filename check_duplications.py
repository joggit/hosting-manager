#!/usr/bin/env python3
"""
Code Duplication Checker for Hosting Manager
Analyzes the codebase for potential duplications and conflicts
"""

import os
import re
import difflib
from collections import defaultdict

def find_python_files():
    """Find all Python files in the project"""
    python_files = []
    for root, dirs, files in os.walk('.'):
        # Skip common non-code directories
        dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'venv', '.venv']]
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files

def extract_functions(file_path):
    """Extract function definitions from a Python file"""
    functions = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Find function definitions
            pattern = r'def\s+(\w+)\s*\([^)]*\):'
            matches = re.findall(pattern, content)
            functions = matches
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return functions

def extract_classes(file_path):
    """Extract class definitions from a Python file"""
    classes = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Find class definitions
            pattern = r'class\s+(\w+)(?:\([^)]*\))?:'
            matches = re.findall(pattern, content)
            classes = matches
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return classes

def extract_imports(file_path):
    """Extract import statements from a Python file"""
    imports = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Find import statements
            import_pattern = r'(?:from\s+[\w.]+\s+)?import\s+([\w,\s\*]+)'
            matches = re.findall(import_pattern, content)
            for match in matches:
                imports.extend([imp.strip() for imp in match.split(',') if imp.strip()])
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return imports

def check_database_operations(file_path):
    """Check for database operations"""
    db_operations = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Find SQL operations
            sql_patterns = [
                r'CREATE\s+TABLE\s+(\w+)',
                r'INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)',
                r'SELECT\s+.*?\s+FROM\s+(\w+)',
                r'UPDATE\s+(\w+)',
                r'DELETE\s+FROM\s+(\w+)'
            ]
            for pattern in sql_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                db_operations.extend(matches)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return db_operations

def analyze_codebase():
    """Analyze the entire codebase for duplications"""
    print("🔍 Analyzing codebase for duplications...")
    print("=" * 50)
    
    python_files = find_python_files()
    print(f"📁 Found {len(python_files)} Python files:")
    for file in python_files:
        print(f"   {file}")
    
    print("\n" + "=" * 50)
    
    # Check for duplicate function names
    all_functions = defaultdict(list)
    all_classes = defaultdict(list)
    all_imports = defaultdict(list)
    all_db_operations = defaultdict(list)
    
    for file_path in python_files:
        functions = extract_functions(file_path)
        classes = extract_classes(file_path)
        imports = extract_imports(file_path)
        db_ops = check_database_operations(file_path)
        
        for func in functions:
            all_functions[func].append(file_path)
        for cls in classes:
            all_classes[cls].append(file_path)
        for imp in imports:
            all_imports[imp].append(file_path)
        for op in db_ops:
            all_db_operations[op].append(file_path)
    
    # Report duplications
    print("🔄 DUPLICATE FUNCTION NAMES:")
    print("-" * 30)
    duplicate_functions = {name: files for name, files in all_functions.items() if len(files) > 1}
    if duplicate_functions:
        for func_name, files in duplicate_functions.items():
            print(f"⚠️  Function '{func_name}' found in:")
            for file in files:
                print(f"     {file}")
            print()
    else:
        print("✅ No duplicate function names found")
    
    print("\n🏗️  DUPLICATE CLASS NAMES:")
    print("-" * 30)
    duplicate_classes = {name: files for name, files in all_classes.items() if len(files) > 1}
    if duplicate_classes:
        for class_name, files in duplicate_classes.items():
            print(f"⚠️  Class '{class_name}' found in:")
            for file in files:
                print(f"     {file}")
            print()
    else:
        print("✅ No duplicate class names found")
    
    print("\n🗄️  DATABASE TABLE OPERATIONS:")
    print("-" * 30)
    table_operations = {table: files for table, files in all_db_operations.items() if len(files) > 1}
    if table_operations:
        for table_name, files in table_operations.items():
            print(f"📋 Table '{table_name}' operated on in:")
            for file in files:
                print(f"     {file}")
            print()
    else:
        print("✅ No overlapping database operations found")
    
    # Check for similar imports
    print("\n📦 COMMON IMPORTS:")
    print("-" * 30)
    common_imports = {imp: files for imp, files in all_imports.items() if len(files) > 1}
    frequently_imported = {imp: files for imp, files in common_imports.items() if len(files) >= 3}
    
    if frequently_imported:
        for import_name, files in list(frequently_imported.items())[:10]:  # Show top 10
            print(f"📦 '{import_name}' imported in {len(files)} files")
    
    # Check for potential conflicts
    print("\n⚠️  POTENTIAL ISSUES:")
    print("-" * 30)
    
    issues_found = False
    
    # Check for SSL-related duplications
    ssl_files = [f for f in python_files if 'ssl' in f.lower()]
    if len(ssl_files) > 1:
        print(f"⚠️  Multiple SSL-related files found:")
        for file in ssl_files:
            print(f"     {file}")
        issues_found = True
    
    # Check for monitoring duplications
    monitoring_files = [f for f in python_files if 'monitor' in f.lower()]
    if len(monitoring_files) > 1:
        print(f"⚠️  Multiple monitoring files found:")
        for file in monitoring_files:
            print(f"     {file}")
        issues_found = True
    
    # Check for API duplications
    api_files = [f for f in python_files if 'api' in f.lower() or 'server' in f.lower()]
    if len(api_files) > 1:
        print(f"⚠️  Multiple API/server files found:")
        for file in api_files:
            print(f"     {file}")
        issues_found = True
    
    if not issues_found:
        print("✅ No obvious structural conflicts detected")
    
    print("\n" + "=" * 50)
    print("📊 SUMMARY:")
    print(f"   �� Files analyzed: {len(python_files)}")
    print(f"   🔄 Duplicate functions: {len(duplicate_functions)}")
    print(f"   🏗️  Duplicate classes: {len(duplicate_classes)}")
    print(f"   🗄️  Shared tables: {len(table_operations)}")
    
    return {
        'files': python_files,
        'duplicate_functions': duplicate_functions,
        'duplicate_classes': duplicate_classes,
        'shared_tables': table_operations,
        'issues': issues_found
    }

def check_file_similarities():
    """Check for similar file contents"""
    print("\n🔍 Checking for similar file contents...")
    python_files = find_python_files()
    
    similar_pairs = []
    
    for i, file1 in enumerate(python_files):
        for file2 in python_files[i+1:]:
            try:
                with open(file1, 'r', encoding='utf-8') as f1:
                    content1 = f1.readlines()
                with open(file2, 'r', encoding='utf-8') as f2:
                    content2 = f2.readlines()
                
                # Calculate similarity
                similarity = difflib.SequenceMatcher(None, content1, content2).ratio()
                
                if similarity > 0.3:  # More than 30% similar
                    similar_pairs.append((file1, file2, similarity))
                    
            except Exception as e:
                continue
    
    if similar_pairs:
        print("⚠️  Files with high similarity:")
        for file1, file2, similarity in sorted(similar_pairs, key=lambda x: x[2], reverse=True):
            print(f"   {similarity:.1%} similar: {file1} ↔ {file2}")
    else:
        print("✅ No highly similar files found")

if __name__ == "__main__":
    results = analyze_codebase()
    check_file_similarities()
    
    print("\n🎯 RECOMMENDATIONS:")
    if results['duplicate_functions'] or results['duplicate_classes']:
        print("   • Review duplicate functions/classes for consolidation")
    if results['shared_tables']:
        print("   • Consider centralizing database operations")
    if results['issues']:
        print("   • Resolve structural conflicts before deployment")
    else:
        print("   ✅ Codebase looks clean for deployment!")
