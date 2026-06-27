#!/usr/bin/env python
"""
Validate the phishing pipeline setup.
Checks dependencies, configuration, and API connectivity.
"""
import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed."""
    print("\n[*] Checking dependencies...")
    required = [
        "google.auth",
        "google.oauth2",
        "google_auth_oauthlib",
        "googleapiclient",
        "aiohttp",
        "dotenv",
        "rich",
        "openai",
    ]

    missing = []
    for dep in required:
        try:
            __import__(dep)
            print(f"  ✓ {dep}")
        except ImportError:
            print(f"  ✗ {dep}")
            missing.append(dep)

    if missing:
        print(f"\n[!] Missing dependencies: {', '.join(missing)}")
        print("    Run: pip install -r requirements.txt")
        return False

    return True


def check_structure():
    """Check if directory structure is correct."""
    print("\n[*] Checking directory structure...")

    required_dirs = [
        "pipeline/ingest",
        "pipeline/extract",
        "pipeline/enrich",
        "pipeline/decide",
        "pipeline/respond",
        "pipeline/close",
        "models",
        "utils",
    ]

    for dir_path in required_dirs:
        if Path(dir_path).exists():
            print(f"  ✓ {dir_path}/")
        else:
            print(f"  ✗ {dir_path}/")
            return False

    return True


def check_files():
    """Check if all required files exist."""
    print("\n[*] Checking required files...")

    required_files = [
        "main.py",
        "config.py",
        "test_pipeline.py",
        ".env.example",
        "requirements.txt",
        "README.md",
        "QUICKSTART.md",
        "pipeline/ingest/gmail_poller.py",
        "pipeline/extract/ioc_extractor.py",
        "pipeline/enrich/virustotal.py",
        "pipeline/decide/score_aggregator.py",
        "pipeline/respond/auto_block.py",
        "pipeline/close/thehive_client.py",
        "models/phishing_case.py",
        "utils/logger.py",
    ]

    missing = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ {file_path}")
            missing.append(file_path)

    if missing:
        print(f"\n[!] Missing files: {', '.join(missing)}")
        return False

    return True


def check_config():
    """Check .env configuration."""
    print("\n[*] Checking configuration...")

    if Path(".env").exists():
        print("  ✓ .env exists")

        # Check for OpenAI key (required)
        env_content = Path(".env").read_text()
        if "OPENAI_API_KEY=" in env_content:
            print("  ✓ OPENAI_API_KEY defined")
            if env_content.split("OPENAI_API_KEY=")[1].split("\n")[0].strip():
                print("  ✓ OPENAI_API_KEY has value")
            else:
                print("  ⚠ OPENAI_API_KEY is empty (required)")
                return False
        else:
            print("  ✗ OPENAI_API_KEY not found")
            return False

        # Check for Gmail (recommended)
        if "GMAIL_CREDENTIALS_PATH=" in env_content:
            print("  ✓ GMAIL_CREDENTIALS_PATH defined")

        return True
    else:
        print("  ✗ .env not found")
        print("    Run: cp .env.example .env")
        print("    Then edit .env with your API keys")
        return False


def check_gmail_oauth():
    """Check if Gmail OAuth is configured."""
    print("\n[*] Checking Gmail OAuth...")

    if Path("credentials.json").exists():
        print("  ✓ credentials.json exists")
    else:
        print("  ⚠ credentials.json not found (Gmail polling will fail)")
        print("    Download from Google Cloud Console")

    if Path("token.pickle").exists():
        print("  ✓ token.pickle exists (OAuth completed)")
    else:
        print("  ⚠ token.pickle not found")
        print("    Run: python -c \"from pipeline.ingest.gmail_poller import setup_gmail_oauth; setup_gmail_oauth()\"")


def check_imports():
    """Check if main modules can be imported."""
    print("\n[*] Checking Python imports...")

    try:
        import config
        print("  ✓ config imports successfully")
    except Exception as e:
        print(f"  ✗ config import failed: {e}")
        return False

    try:
        from models import Email, IOCs, Verdict, PhishingCase
        print("  ✓ models import successfully")
    except Exception as e:
        print(f"  ✗ models import failed: {e}")
        return False

    try:
        from pipeline.extract.ioc_extractor import IOCExtractor
        print("  ✓ IOCExtractor imports successfully")
    except Exception as e:
        print(f"  ✗ IOCExtractor import failed: {e}")
        return False

    try:
        from pipeline.decide.score_aggregator import ScoreAggregator
        print("  ✓ ScoreAggregator imports successfully")
    except Exception as e:
        print(f"  ✗ ScoreAggregator import failed: {e}")
        return False

    return True


def test_ioc_extraction():
    """Test IOC extraction on sample text."""
    print("\n[*] Testing IOC extraction...")

    try:
        from pipeline.extract.ioc_extractor import IOCExtractor

        sample = """
        Check these URLs:
        https://malicious.com/phish
        http://192.168.1.100

        MD5: 5d41402abc4b2a76b9719d911017c592
        """

        iocs = IOCExtractor.extract_all(sample)

        if len(iocs.urls) > 0:
            print(f"  ✓ URL extraction works ({len(iocs.urls)} URLs found)")
        else:
            print("  ⚠ No URLs found (might be expected)")

        if len(iocs.hashes) > 0:
            print(f"  ✓ Hash extraction works ({len(iocs.hashes)} hashes found)")
        else:
            print("  ⚠ No hashes found (might be expected)")

        return True
    except Exception as e:
        print(f"  ✗ IOC extraction failed: {e}")
        return False


def main():
    """Run all validation checks."""
    print("=" * 60)
    print("PHISHING PIPELINE SETUP VALIDATION")
    print("=" * 60)

    checks = [
        ("Dependencies", check_dependencies),
        ("Directory Structure", check_structure),
        ("Files", check_files),
        ("Configuration", check_config),
        ("Imports", check_imports),
        ("IOC Extraction", test_ioc_extraction),
    ]

    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"[!] {check_name} check failed with error: {e}")
            results.append((check_name, False))

    # Gmail OAuth is optional
    try:
        check_gmail_oauth()
    except Exception as e:
        print(f"[!] Gmail OAuth check failed: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for check_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {check_name}: {status}")

    print("\n" + "=" * 60)
    print(f"Overall: {passed}/{total} checks passed")
    print("=" * 60)

    if passed == total:
        print("\n✓ Setup validation PASSED!")
        print("\nYou can now:")
        print("  1. Test: python test_pipeline.py")
        print("  2. Run:  python main.py")
        return 0
    else:
        print("\n✗ Setup validation FAILED!")
        print("\nPlease fix the issues above and try again.")
        print("See README.md or QUICKSTART.md for help.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
