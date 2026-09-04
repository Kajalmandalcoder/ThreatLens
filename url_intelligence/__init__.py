"""
ThreadLens - URL Intelligence Module
Provides safe, modular, explainable URL threat detection.
"""

from url_intelligence.analyzer import analyze_single_url, analyze_urls

__all__ = ["analyze_urls", "analyze_single_url"]