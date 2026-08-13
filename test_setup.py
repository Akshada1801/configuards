"""
Test script to verify Configuards project setup
"""
import os
import sys

def check_project():
    print("=" * 50)
    print("CONFIGUARDS PROJECT VERIFICATION")
    print("=" * 50)
    
    # Check main files
    files_to_check = [
        'app.py',
        'requirements.txt',
        'README.md',
        'static/css/style.css',
        'templates/login.html',
        'templates/signup.html',
        'templates/dashboard.html',
        'templates/profile.html',
        'templates/findings.html',
        'templates/reports.html',
        'templates/settings.html',
        'templates/change_password.html',
        'templates/two_factor.html',
        'templates/feedback.html',
        'templates/about.html'
    ]
    
    print("\nChecking files...")
    missing_files = []
    for file in files_to_check:
        if os.path.exists(file):
            print(f"  [OK] {file}")
        else:
            print(f"  [MISSING] {file}")
            missing_files.append(file)
    
    if missing_files:
        print(f"\n⚠ Missing {len(missing_files)} file(s)")
        return False
    
    print("\nAll files present!")
    
    # Check Flask import
    print("\nChecking Flask...")
    try:
        import flask
        print(f"  [OK] Flask {flask.__version__} installed")
    except ImportError:
        print("  [ERROR] Flask not installed")
        print("  Run: pip install -r requirements.txt")
        return False
    
    print("\n" + "=" * 50)
    print("PROJECT IS READY!")
    print("=" * 50)
    print("\nTo run the application:")
    print("  python app.py")
    print("\nThen open: http://127.0.0.1:5000")
    print("=" * 50)
    
    return True

if __name__ == "__main__":
    check_project()
