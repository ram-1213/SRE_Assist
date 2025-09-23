"""
main.py - Entry point for SRE Codeshield
Calls pages.py for all UI functionality
"""
import streamlit as st
import logging
from pathlib import Path
import sys

# Add project root to Path
sys.path.append(str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Page config
st.set_page_config(
    page_title="SRE Codeshield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def main():
    """Main entry point - imports and runs pages.py"""
    try:
        # Import pages module
        import pages
        pages.main()

    except ImportError as e:
        st.error(f"Failed to import pages.py: {e}")
        st.error("Please ensure pages.py exists in the same directory")

    except Exception as e:
        st.error(f"Application error: {e}")
        logging.error(f"Application startup error: {e}")


if __name__ == "__main__":
    main()